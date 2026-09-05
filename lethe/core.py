import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .audit import AuditLog
from .certificate import build_certificate
from .connectors.base import Connector
from .hashing import hash_subject
from .ledger import Ledger
from .models import Certificate, LayerResult, TagRecord
from .signing import Signer
from .version import __version__


class Lethe:
    def __init__(
        self,
        *,
        ledger: Ledger,
        audit: AuditLog,
        signer: Signer,
        connectors: dict[str, Connector],
        salt: str,
        cert_validity: timedelta = timedelta(days=30),
    ):
        self.ledger = ledger
        self.audit = audit
        self.signer = signer
        self.connectors = connectors
        self.salt = salt
        # Default window after issue during which a certificate's absence claim
        # is asserted; past valid_until a reader should re-verify. Operator
        # policy — override per-call with forget(valid_for=...).
        self.cert_validity = cert_validity

    def _subject_hash(self, subject_id: str) -> str:
        return hash_subject(subject_id, self.salt)

    def tag(self, subject_id: str, store: str, namespace: str, record_id: str) -> None:
        self.ledger.record(
            TagRecord(
                subject_hash=self._subject_hash(subject_id),
                store=store,
                namespace=namespace,
                record_id=record_id,
            )
        )

    def preview(self, subject_id: str) -> dict:
        """Read-only blast radius: what forget() WOULD touch, per layer.
        Feeds the MCP two-step guard; deletes nothing, purges nothing."""
        subject_hash = self._subject_hash(subject_id)
        counts: dict[tuple[str, str], int] = defaultdict(int)
        for row in self.ledger.lookup(subject_hash):
            counts[(row.store, row.namespace)] += 1
        return {
            "subject_hash": subject_hash,
            "layers": [
                {"store": store, "namespace": namespace, "count": n}
                for (store, namespace), n in sorted(counts.items())
            ],
        }

    def forget(
        self,
        subject_id: str,
        *,
        request_id: str | None = None,
        now: datetime | None = None,
        valid_for: timedelta | None = None,
    ) -> Certificate:
        subject_hash = self._subject_hash(subject_id)
        request_id = request_id or str(uuid.uuid4())
        now_dt = now if now is not None else datetime.now(timezone.utc)
        issued_at = now_dt.isoformat()
        # NB: `valid_for or self.cert_validity` is WRONG — timedelta(0) is falsy,
        # so an explicit zero/near-zero window would silently coalesce to the
        # default. Select with `is None` so an explicit window is honored and a
        # non-positive one reaches build_certificate's guard (which rejects it).
        window = valid_for if valid_for is not None else self.cert_validity
        valid_until = (now_dt + window).isoformat()

        groups: dict[tuple[str, str], list[str]] = defaultdict(list)
        for row in self.ledger.lookup(subject_hash):
            groups[(row.store, row.namespace)].append(row.record_id)

        # Pre-flight audit event: a mid-loop connector failure must never
        # leave real deletions with no audit trace; the started/completed pair
        # brackets every destructive attempt. Its hash is also the chain tip
        # this run starts from — binding it into the signed certificate ties
        # the cert to a position in the tamper-evident chain, and the
        # completion entry below chains forward from here carrying the cert's
        # payload_hash, so cert and chain point at each other.
        audit_head = self.audit.append(
            {
                "event": "forget_started",
                "request_id": request_id,
                "subject_hash": subject_hash,
                "issued_at": issued_at,
                "requested_layers": len(groups),
            }
        )

        layers: list[LayerResult] = []
        for (store, namespace), ids in groups.items():
            connector = self.connectors.get(store)
            if connector is None:
                # A tagged store with no configured connector must NOT crash the
                # loop mid-flight (that would leave already-deleted layers with no
                # certificate). Record it as an unhandled, unverified layer so the
                # certificate is honest and the ledger is preserved for retry once
                # the connector is configured.
                layers.append(
                    LayerResult(
                        store,
                        namespace,
                        deleted_count=0,
                        verified_absent=False,
                        requested_count=len(ids),
                        handled=False,
                    )
                )
                continue
            deleted = connector.delete(namespace, ids)
            # Prefer verify_detail (records the residual count + query descriptor
            # as certifiable evidence); fall back to the boolean verify() for
            # custom connectors that only implement the required Protocol.
            if hasattr(connector, "verify_detail"):
                vr = connector.verify_detail(namespace, ids)
                verified, residual, method, idx_ver = (
                    vr.absent, vr.residual_count, vr.method, vr.index_version
                )
            else:
                verified = connector.verify(namespace, ids)
                residual, method, idx_ver = None, "boolean-verify (no verify_detail)", None
            layers.append(
                LayerResult(
                    store,
                    namespace,
                    deleted_count=deleted,
                    verified_absent=verified,
                    requested_count=len(ids),
                    handled=True,
                    residual_count=residual,
                    verify_method=method,
                    index_version=idx_ver,
                )
            )

        cert = build_certificate(
            request_id=request_id,
            subject_hash=subject_hash,
            layers=layers,
            issued_at=issued_at,
            version=__version__,
            signer=self.signer,
            valid_until=valid_until,
            # The boundary the issuer drew: every store Lethe was configured to
            # sweep. A tagged store missing a connector is still recorded (as an
            # unhandled layer); declared_scope names the full configured set.
            declared_scope=list(self.connectors.keys()),
            audit_head=audit_head,
        )

        self.audit.append(
            {
                "event": "forget",
                "request_id": request_id,
                "subject_hash": subject_hash,
                "issued_at": issued_at,
                "payload_hash": cert.payload_hash,
                "all_verified": cert.payload["all_verified"],
            }
        )

        # Only purge the provenance map once deletion is fully verified — otherwise
        # we keep the map so the operation can be retried.
        if cert.payload["all_verified"]:
            self.ledger.purge(subject_hash)

        return cert

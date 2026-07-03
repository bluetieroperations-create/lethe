import uuid
from collections import defaultdict
from datetime import datetime, timezone

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
    ):
        self.ledger = ledger
        self.audit = audit
        self.signer = signer
        self.connectors = connectors
        self.salt = salt

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
    ) -> Certificate:
        subject_hash = self._subject_hash(subject_id)
        request_id = request_id or str(uuid.uuid4())
        issued_at = (now or datetime.now(timezone.utc)).isoformat()

        groups: dict[tuple[str, str], list[str]] = defaultdict(list)
        for row in self.ledger.lookup(subject_hash):
            groups[(row.store, row.namespace)].append(row.record_id)

        # Pre-flight audit event: a mid-loop connector failure must never
        # leave real deletions with no audit trace; the started/completed
        # pair brackets every destructive attempt.
        self.audit.append(
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
            verified = connector.verify(namespace, ids)
            layers.append(
                LayerResult(
                    store,
                    namespace,
                    deleted_count=deleted,
                    verified_absent=verified,
                    requested_count=len(ids),
                    handled=True,
                )
            )

        cert = build_certificate(
            request_id=request_id,
            subject_hash=subject_hash,
            layers=layers,
            issued_at=issued_at,
            version=__version__,
            signer=self.signer,
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

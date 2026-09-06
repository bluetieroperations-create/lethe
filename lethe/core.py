import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from .audit import AuditContention, AuditLog
from .certificate import build_certificate
from .connectors.base import Connector
from .hashing import hash_subject
from .ledger import Ledger
from .models import Certificate, LayerResult, TagRecord
from .signing import Signer
from .version import __version__


def parse_allowed_namespaces(raw: str | None) -> dict[str, set[str]] | None:
    """Parse LETHE_ALLOWED_NAMESPACES: comma-separated STORE:NAMESPACE pairs.

        pgvector:documents,pgvector:chat_turns,pinecone:memories

    Returns None when unset — unrestricted, the pre-existing behaviour. An
    empty or whitespace-only value is a misconfiguration rather than a way to
    express "allow nothing": silently running unrestricted because a variable
    expanded to nothing is exactly the failure this control exists to stop.
    """
    if raw is None:
        return None
    entries = [item.strip() for item in raw.split(",") if item.strip()]
    if not entries:
        raise ValueError(
            "LETHE_ALLOWED_NAMESPACES is set but empty; unset it to run "
            "unrestricted, or list STORE:NAMESPACE pairs"
        )
    allowed: dict[str, set[str]] = {}
    for entry in entries:
        store, sep, namespace = entry.partition(":")
        if not sep or not store.strip() or not namespace.strip():
            raise ValueError(
                f"LETHE_ALLOWED_NAMESPACES entry {entry!r} must be STORE:NAMESPACE"
            )
        allowed.setdefault(store.strip(), set()).add(namespace.strip())
    return allowed


class ForgetRecordedIncompletely(Exception):
    """The deletion happened; the completion audit entry did not.

    Carries the certificate, because at this point it is the only durable
    record of the run outside the chain — discarding it would lose the evidence
    of a deletion that really occurred.
    """

    def __init__(self, message: str, *, certificate):
        self.certificate = certificate
        super().__init__(message)


class NamespaceNotAllowed(Exception):
    """tag() was asked to record a store/namespace outside the allowlist.

    Enforced in Lethe.tag rather than at the MCP boundary on purpose: the
    ledger is what forget() deletes from, so guarding only one entry point
    would leave the CLI, the library and reconcile()'s remediation path able
    to write entries that forget() would then honour.
    """

    code = "NAMESPACE_NOT_ALLOWED"


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
        retain_verification_ids: bool = False,
        allowed_namespaces: dict[str, set[str]] | None = None,
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
        # Keep the deleted record ids so reverify() can re-query them after
        # valid_until lapses. Off by default: the certificate advises
        # re-verification, but retaining identifiers tied to a subject you just
        # erased is a real privacy cost, so it is the operator's decision. The
        # certificate records which way it was set.
        self.retain_verification_ids = retain_verification_ids
        # Which (store, namespace) pairs this deployment may ever tag, and so
        # ever delete from. None means unrestricted — the pre-existing
        # behaviour, kept as the default so upgrading cannot silently start
        # rejecting a deployment's real traffic. An operator running
        # unrestricted can see so in `lethe status`.
        self.allowed_namespaces = allowed_namespaces

    def _subject_hash(self, subject_id: str) -> str:
        return hash_subject(subject_id, self.salt)

    def _namespace_allowed(self, store: str, namespace: str) -> bool:
        if self.allowed_namespaces is None:
            return True
        return namespace in self.allowed_namespaces.get(store, set())

    def _check_namespace(self, store: str, namespace: str) -> None:
        if self._namespace_allowed(store, namespace):
            return
        # Reached only when an allowlist is configured, but bind it explicitly
        # rather than relying on that invariant holding across a refactor of
        # _namespace_allowed.
        configured = self.allowed_namespaces or {}
        allowed = sorted(f"{s}:{n}" for s, ns in configured.items() for n in ns)
        raise NamespaceNotAllowed(
            f"{store}:{namespace} is not in this deployment's allowed namespaces "
            f"({', '.join(allowed) or 'none configured'})"
        )

    def tag(self, subject_id: str, store: str, namespace: str, record_id: str) -> None:
        # Checked BEFORE the ledger write: an entry that should not exist must
        # never reach the table forget() reads from.
        self._check_namespace(store, namespace)
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
                {
                    "store": store,
                    "namespace": namespace,
                    "count": n,
                    # forget() will refuse a layer outside the allowlist, so a
                    # preview that did not say so would misstate the blast
                    # radius the caller is about to confirm.
                    "allowed": self._namespace_allowed(store, namespace),
                }
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
        now_dt = now if now is not None else datetime.now(UTC)
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
            # The allowlist bounds DELETION, not merely tagging. A ledger entry
            # can predate the allowlist, or be written by anything with SQL
            # access to lethe_provenance, and forget() would otherwise honour
            # it. Recorded as an unhandled layer — the same shape as a store
            # with no connector — so all_verified goes False and the
            # certificate says a layer was found and not swept, rather than
            # quietly omitting it.
            if not self._namespace_allowed(store, namespace):
                layers.append(
                    LayerResult(
                        store,
                        namespace,
                        deleted_count=0,
                        verified_absent=False,
                        requested_count=len(ids),
                        handled=False,
                        verify_method="not performed: namespace outside the allowlist",
                    )
                )
                continue
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
            reverifiable=self.retain_verification_ids,
        )

        try:
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
        except AuditContention as exc:
            # The rows are already gone. Letting a bare "could not append"
            # surface here would read as "the forget failed", and the operator
            # would retry a deletion that has in fact completed — finding zero
            # rows the second time and concluding, wrongly, that nothing was
            # ever deleted. Say what actually happened instead, and hand back
            # the certificate: it is signed, it is accurate, and it is the only
            # record of this run that now exists outside the chain.
            raise ForgetRecordedIncompletely(
                f"deletion COMPLETED ({cert.payload['records_deleted']} records "
                f"across {cert.payload['layers_found']} layer(s)) but the audit "
                f"chain would not accept the completion entry: {exc}. The "
                f"forget_started entry at audit_head {audit_head} records that "
                f"this run began. Do not re-run it — reconcile from the "
                f"certificate, whose payload_hash is {cert.payload_hash}.",
                certificate=cert,
            ) from None

        # Only purge the provenance map once deletion is fully verified — otherwise
        # we keep the map so the operation can be retried.
        if cert.payload["all_verified"]:
            # Retention must happen BEFORE the purge it is copying from.
            if self.retain_verification_ids:
                self.ledger.retain_for_reverification(subject_hash, request_id)
            self.ledger.purge(subject_hash)

        return cert

    def reverify(self, subject_id: str) -> dict:
        """Re-query the stores for a subject whose forget already completed.

        The certificate asserts absence only up to valid_until and advises
        re-verifying past it. That is possible only when the deployment opted
        into retain_verification_ids — otherwise forget() purged the record ids
        a re-query would need, and this reports that honestly instead of
        returning a hollow "absent" derived from having nothing to check.
        """
        subject_hash = self._subject_hash(subject_id)
        retained = self.ledger.retained(subject_hash)
        if not retained:
            return {
                "subject_hash": subject_hash,
                "reverifiable": False,
                "reason": (
                    "no retained record ids for this subject — either no forget has "
                    "completed, or the deployment did not set retain_verification_ids"
                ),
                "layers": [],
                "still_absent": None,
            }

        groups: dict[tuple[str, str], list[str]] = defaultdict(list)
        for row in retained:
            groups[(row.store, row.namespace)].append(row.record_id)

        layers = []
        for (store, namespace), ids in sorted(groups.items()):
            connector = self.connectors.get(store)
            if connector is None:
                layers.append({
                    "store": store, "namespace": namespace, "handled": False,
                    "absent": None, "residual_count": None,
                    "verify_method": None,
                })
                continue
            if hasattr(connector, "verify_detail"):
                vr = connector.verify_detail(namespace, ids)
                absent, residual, method = vr.absent, vr.residual_count, vr.method
            else:
                absent = connector.verify(namespace, ids)
                residual, method = None, "boolean-verify (no verify_detail)"
            layers.append({
                "store": store, "namespace": namespace, "handled": True,
                "absent": absent, "residual_count": residual,
                "verify_method": method,
            })

        # Unknown (an unhandled layer) must never read as absent.
        still_absent = all(lyr["absent"] is True for lyr in layers) if layers else False
        self.audit.append({
            "event": "reverify",
            "subject_hash": subject_hash,
            "checked_at": datetime.now(UTC).isoformat(),
            "still_absent": still_absent,
        })
        return {
            "subject_hash": subject_hash,
            "reverifiable": True,
            "reason": None,
            "layers": layers,
            "still_absent": still_absent,
        }

    def reconcile(
        self,
        subject_id: str,
        *,
        targets: list[tuple[str, str, str]],
        tag_untracked: bool = False,
    ) -> dict:
        """Compare what a store actually holds for a subject against what the
        ledger knows about.

        forget() deletes exactly what the provenance ledger tagged, so a write
        that bypassed the wrapper is invisible to it — and a certificate can
        still read all_verified because every layer Lethe *knew about* was
        verified. This asks the stores directly instead.

        `targets` are (store, namespace, subject_field) triples: Lethe does not
        know your schema, so the caller names the column/field holding the data
        subject. Note this searches by the RAW subject id, because that is what
        the store holds — the ledger holds only its keyed hash.

        With `tag_untracked=True`, anything found untracked is tagged into the
        ledger so a subsequent forget() will delete and certify it. Detection is
        the default; remediation mutates the ledger and is opt-in.
        """
        if tag_untracked:
            # Fail before scanning rather than part-way through tagging: a
            # partial remediation would leave the ledger in a state the caller
            # did not ask for and cannot easily see.
            for store, namespace, _ in targets:
                self._check_namespace(store, namespace)

        subject_hash = self._subject_hash(subject_id)
        tracked: dict[tuple[str, str], set[str]] = defaultdict(set)
        for row in self.ledger.lookup(subject_hash):
            tracked[(row.store, row.namespace)].add(row.record_id)

        layers = []
        total_untracked = 0
        for store, namespace, subject_field in targets:
            connector = self.connectors.get(store)
            if connector is None or not hasattr(connector, "scan"):
                # Unscannable is NOT clean: a layer we could not look at must
                # never be reported as having nothing untracked.
                layers.append({
                    "store": store, "namespace": namespace, "scanned": False,
                    "reason": (
                        "no configured connector" if connector is None
                        else f"connector '{store}' does not implement scan()"
                    ),
                    "found_in_store": None, "tracked_in_ledger": None,
                    "untracked": None,
                })
                continue
            found = connector.scan(namespace, subject_field, subject_id)
            known = tracked.get((store, namespace), set())
            untracked = sorted(set(found) - known)
            total_untracked += len(untracked)
            if tag_untracked:
                for record_id in untracked:
                    self.tag(subject_id, store, namespace, record_id)
            layers.append({
                "store": store, "namespace": namespace, "scanned": True,
                "reason": None,
                "found_in_store": len(found), "tracked_in_ledger": len(known),
                "untracked": untracked,
            })

        all_scanned = all(lyr["scanned"] for lyr in layers) if layers else False
        self.audit.append({
            "event": "reconcile",
            "subject_hash": subject_hash,
            "checked_at": datetime.now(UTC).isoformat(),
            "targets": len(targets),
            "untracked_found": total_untracked,
            "tagged": bool(tag_untracked and total_untracked),
        })
        return {
            "subject_hash": subject_hash,
            "layers": layers,
            "untracked_total": total_untracked,
            # Clean only if every target was actually scanned AND nothing was
            # found untracked. A partial scan can never certify cleanliness.
            "clean": all_scanned and total_untracked == 0,
            "tagged_untracked": bool(tag_untracked and total_untracked),
        }

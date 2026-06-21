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

        layers: list[LayerResult] = []
        for (store, namespace), ids in groups.items():
            connector = self.connectors[store]
            deleted = connector.delete(namespace, ids)
            verified = connector.verify(namespace, ids)
            layers.append(LayerResult(store, namespace, deleted, verified))

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

import hashlib
import json

from .models import Certificate, LayerResult
from .signing import Signer, verify_signature

CLAIM = (
    "Deleted across the listed retrieval layers and verified absent. "
    "Not a guarantee of erasure from backups, model weights, or systems "
    "outside Lethe's configured connectors."
)


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def build_certificate(
    *,
    request_id: str,
    subject_hash: str,
    layers: list[LayerResult],
    issued_at: str,
    version: str,
    signer: Signer,
) -> Certificate:
    ordered = sorted(layers, key=lambda l: (l.store, l.namespace))
    payload = {
        "request_id": request_id,
        "subject_hash": subject_hash,
        "issued_at": issued_at,
        "lethe_version": version,
        "claim": CLAIM,
        "all_verified": all(l.verified_absent for l in ordered),
        "layers": [
            {
                "store": l.store,
                "namespace": l.namespace,
                "deleted_count": l.deleted_count,
                "verified_absent": l.verified_absent,
            }
            for l in ordered
        ],
    }
    data = _canonical_bytes(payload)
    return Certificate(
        payload=payload,
        payload_hash=hashlib.sha256(data).hexdigest(),
        signature=signer.sign(data),
        public_key=signer.public_key_b64(),
    )


def verify_certificate(cert: Certificate) -> bool:
    data = _canonical_bytes(cert.payload)
    if hashlib.sha256(data).hexdigest() != cert.payload_hash:
        return False
    return verify_signature(cert.public_key, data, cert.signature)

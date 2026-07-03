import base64
import hashlib
import hmac
import json

from .models import Certificate, LayerResult
from .signing import Signer, verify_signature

CLAIM = (
    "Deleted across the listed retrieval layers and verified absent. "
    "Not a guarantee of erasure from backups, model weights, or systems "
    "outside Lethe's configured connectors."
)

CERT_SCHEMA_VERSION = "lethe.cert/1"


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

    def _is_erasure(l: LayerResult) -> bool:
        # A layer is a genuine, certifiable erasure only when Lethe was handled
        # by a real connector, confirmed the records absent, AND actually removed
        # records this run. deleted_count 0 with verified_absent True means the
        # data was already gone (another subject's forget, or a prior partial
        # run) — Lethe did NOT perform this erasure and must not certify it.
        return l.handled and l.verified_absent and l.deleted_count > 0

    erasures = [_is_erasure(l) for l in ordered]

    # all_verified is the load-bearing claim a regulator relies on. It is True
    # ONLY if at least one layer was found AND every layer is a genuine erasure.
    # Empty layers (unknown subject / nothing found) => all([]) would be True;
    # we require a non-empty layer set so "found nothing" can never read as a
    # successful, verified erasure.
    all_verified = bool(ordered) and all(erasures)

    payload = {
        "schema": CERT_SCHEMA_VERSION,
        "request_id": request_id,
        "subject_hash": subject_hash,
        "issued_at": issued_at,
        "lethe_version": version,
        "claim": CLAIM,
        "all_verified": all_verified,
        # Honest summary of what actually happened, so a zero-deletion or
        # unhandled-store outcome cannot be misread off the layer list.
        "layers_found": len(ordered),
        "records_deleted": sum(l.deleted_count for l in ordered),
        "all_layers_handled": all(l.handled for l in ordered) if ordered else True,
        "layers": [
            {
                "store": l.store,
                "namespace": l.namespace,
                "deleted_count": l.deleted_count,
                "verified_absent": l.verified_absent,
                "requested_count": l.requested_count,
                "handled": l.handled,
                "erased": erased,
            }
            for l, erased in zip(ordered, erasures)
        ],
    }
    data = _canonical_bytes(payload)
    return Certificate(
        payload=payload,
        payload_hash=hashlib.sha256(data).hexdigest(),
        signature=signer.sign(data),
        public_key=signer.public_key_b64(),
    )


def verify_certificate(cert: Certificate, trusted_public_key: str) -> bool:
    """Verify a deletion certificate. Key pinning is MANDATORY.

    SECURITY: a certificate carries the public key that signed it, so a
    self-verifying check ("does the embedded key validate the embedded
    signature?") only proves internal consistency, NOT authenticity — an
    attacker can mint a fully self-consistent certificate with their own
    keypair. A certificate can therefore only be verified against the
    operator's out-of-band-published key (e.g. from /.well-known), passed as
    ``trusted_public_key``; self-consistency-only checks are not proof and
    are no longer offered. The certificate's embedded key must match the
    trusted key before the signature is even checked.
    """
    try:
        embedded = base64.b64decode(cert.public_key, validate=True)
        trusted = base64.b64decode(trusted_public_key, validate=True)
    except Exception:
        return False
    if not hmac.compare_digest(embedded, trusted):
        return False

    data = _canonical_bytes(cert.payload)
    if hashlib.sha256(data).hexdigest() != cert.payload_hash:
        return False
    return verify_signature(cert.public_key, data, cert.signature)


def canonical_payload_bytes(payload: dict) -> bytes:
    """Public alias: the exact byte encoding that is hashed and signed."""
    return _canonical_bytes(payload)


def certificate_to_dict(cert: Certificate) -> dict:
    """The wire/JSON envelope — matches schemas/certificate-v1.json."""
    return {
        "payload": cert.payload,
        "payload_hash": cert.payload_hash,
        "signature": cert.signature,
        "public_key": cert.public_key,
    }

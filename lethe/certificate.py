import base64
import hashlib
import hmac
import json
from datetime import datetime

from .models import Certificate, LayerResult
from .signing import Signer, key_id_for, verify_signature

CLAIM = (
    "Deleted across the listed retrieval layers and verified absent by re-query "
    "at issue time against the configured endpoint, recording the residual match "
    "count for each layer. Scope is limited to the declared connectors "
    "(declared_scope); a store not listed there was not checked. The absence is "
    "asserted as of issued_at and is not asserted beyond valid_until (when set) — "
    "re-verify after that time, as the underlying index can change (possible only "
    "where reverifiable is true; otherwise the issuer did not retain the record "
    "identifiers a re-query needs). Not a "
    "guarantee of erasure from backups, model weights, or systems outside Lethe's "
    "configured connectors, nor a guarantee against read replicas, caches, or "
    "asynchronous propagation (e.g. eventually-consistent stores such as Pinecone). "
    "This certificate is self-issued: issued_at is the issuer's own clock, and the "
    "signature proves only that the holder of key_id produced it. Where audit_head is "
    "set, the certificate is bound to that position in the issuer's tamper-evident "
    "audit chain. Where timestamp is null, no external timestamping authority has "
    "corroborated the issue time."
)

CERT_SCHEMA_VERSION = "lethe.cert/3"


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
    valid_until: str | None = None,
    declared_scope: list[str] | None = None,
    audit_head: str | None = None,
    timestamp: dict | None = None,
    reverifiable: bool = False,
) -> Certificate:
    # The absence claim is asserted from issued_at up to valid_until. A
    # valid_until at or before issued_at is a self-nullifying window: the cert
    # would still sign and schema-validate, yet assert absence for a
    # zero/negative interval. Refuse to mint such a trust artifact. (None is
    # allowed — unbounded, discouraged, but scoped to issue time by the CLAIM.)
    if valid_until is not None:
        try:
            issued_dt = datetime.fromisoformat(issued_at)
            valid_dt = datetime.fromisoformat(valid_until)
        except ValueError as exc:
            raise ValueError(
                "issued_at and valid_until must be ISO-8601 timestamps"
            ) from exc
        # Both naive or both aware compare cleanly; a naive/aware mix is itself a
        # bug (inconsistent clocks) and TypeError surfaces it rather than hiding
        # it — normalize to an explicit, honest error.
        try:
            ordered_ok = valid_dt > issued_dt
        except TypeError as exc:
            raise ValueError(
                "issued_at and valid_until must both be timezone-aware or both "
                "naive; a mixed pair is ambiguous"
            ) from exc
        if not ordered_ok:
            raise ValueError(
                f"valid_until ({valid_until}) must be strictly after issued_at "
                f"({issued_at}); a non-positive validity window is not certifiable"
            )

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
        # Which key signed this. Derived from the public key, so a verifier
        # recomputes it and rejects a cert whose key_id disagrees with its own
        # embedded key. Names the key epoch for operators who rotate: an old
        # certificate stays verifiable against the retired key it names.
        "key_id": signer.key_id(),
        "request_id": request_id,
        "subject_hash": subject_hash,
        "issued_at": issued_at,
        # Time after which the absence is no longer asserted (re-verify past it).
        # None => unbounded (discouraged; the CLAIM still scopes to issue time).
        "valid_until": valid_until,
        "lethe_version": version,
        "claim": CLAIM,
        # The boundary the issuer drew: stores Lethe was configured to sweep, so
        # a reader can see what was in scope — and infer what was NOT checked.
        "declared_scope": sorted(declared_scope or []),
        # Tip of the issuer's tamper-evident audit chain when this run began.
        # Binds the certificate to a chain position, so a fabricated or
        # backdated cert must also be consistent with a chain the issuer has
        # published; None when no chain position was supplied.
        "audit_head": audit_head,
        # Reserved slot for external corroboration of issued_at (e.g. an
        # RFC 3161 token from a timestamping authority). Null means nobody
        # outside the issuer has attested to the time — the honest default,
        # carried in the signed payload rather than left to the reader.
        "timestamp": timestamp,
        # Whether the issuer retained what a later re-query needs. The claim
        # advises re-verifying past valid_until; by default forget() purges the
        # provenance map (data minimisation), which destroys the record ids that
        # re-query requires. Saying so in the payload keeps the advice from
        # being something the certificate cannot actually support.
        "reverifiable": reverifiable,
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
                # cert v2 verification evidence (nullable — see LayerResult).
                "residual_count": l.residual_count,
                "verify_method": l.verify_method,
                "index_version": l.index_version,
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

    # key_id is derived from the public key, so it must be recomputed and
    # compared — otherwise it is decorative, and a cert could name a key epoch
    # other than the one that actually signed it. Only v3+ carries the field;
    # older certs legitimately have none.
    declared_kid = cert.payload.get("key_id")
    if declared_kid is not None:
        if not hmac.compare_digest(
            declared_kid.encode(), key_id_for(cert.public_key).encode()
        ):
            return False

    data = _canonical_bytes(cert.payload)
    if hashlib.sha256(data).hexdigest() != cert.payload_hash:
        return False
    return verify_signature(cert.public_key, data, cert.signature)


def canonical_payload_bytes(payload: dict) -> bytes:
    """Public alias: the exact byte encoding that is hashed and signed."""
    return _canonical_bytes(payload)


def certificate_to_dict(cert: Certificate) -> dict:
    """The wire/JSON envelope (payload + hash + signature + key). The envelope
    is version-independent; the payload's `schema` field names the cert version
    (currently lethe.cert/2), which selects the JSON Schema at verify time."""
    return {
        "payload": cert.payload,
        "payload_hash": cert.payload_hash,
        "signature": cert.signature,
        "public_key": cert.public_key,
    }

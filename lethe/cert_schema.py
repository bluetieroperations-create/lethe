"""Machine verification of Lethe certificates: JSON-Schema shape check plus
key-pinned cryptographic verification with structured, agent-branchable reasons."""

import base64
import copy
import hashlib
import hmac as hmac_mod
import json
from functools import cache
from importlib import resources

import jsonschema

from .certificate import canonical_payload_bytes
from .signing import key_id_for, verify_signature

# A certificate is meant to be verifiable forever, so newer verifiers must still
# validate older certs. Each version has its own schema, selected by the cert's
# declared payload.schema; the per-schema `const` pins a declared version to its
# exact shape, so a cert can't claim v1 while carrying v2 fields (or vice versa).
_SCHEMA_FILES = {
    "lethe.cert/1": "schemas/certificate-v1.json",
    "lethe.cert/2": "schemas/certificate-v2.json",
    "lethe.cert/3": "schemas/certificate-v3.json",
}
_LATEST = "lethe.cert/3"


@cache
def _load_schema(version: str = _LATEST) -> dict:
    text = resources.files("lethe").joinpath(_SCHEMA_FILES[version]).read_text()
    return json.loads(text)


@cache
def _validator(version: str = _LATEST) -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(_load_schema(version))


def _version_of(data) -> str:
    """Which schema version to validate `data` against, from its declared
    payload.schema. Unknown/missing falls back to the latest — whose `const`
    then rejects the mismatch — so a bogus version can never skip validation."""
    if isinstance(data, dict):
        payload = data.get("payload")
        if isinstance(payload, dict):
            v = payload.get("schema")
            if isinstance(v, str) and v in _SCHEMA_FILES:
                return v
    return _LATEST


def load_schema(version: str = _LATEST) -> dict:
    """Return the certificate JSON Schema for `version` (default: latest).

    Returns a defensive deep copy: the cached schema dict is shared process-wide,
    so callers must never be handed the mutable original.
    """
    return copy.deepcopy(_load_schema(version))


def schema_errors(data) -> list[str]:
    validator = _validator(_version_of(data))
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(
            validator.iter_errors(data),
            key=lambda e: [str(x) for x in e.absolute_path],
        )
    ]


def verify_certificate_json(
    data,
    trusted_public_key: str | None = None,
    *,
    trusted_keys: dict[str, str] | None = None,
) -> dict:
    """Verify a certificate received as JSON. A trusted key is REQUIRED:
    an unpinned check only proves self-consistency, never authenticity.

    Pass exactly one of:

    * ``trusted_public_key`` — a single key, when you know which one signed.
    * ``trusted_keys`` — ``{key_id: public_key}``, and the certificate's own
      ``key_id`` selects from it. This is what makes rotation usable: a
      certificate is self-describing about which key epoch signed it, so the
      verifier can do the lookup instead of the caller hand-maintaining it.
      Certificates predating ``lethe.cert/3`` carry no ``key_id`` and cannot be
      resolved this way — pass their key explicitly.

    Reasons an agent can branch on, checked in order:
    SCHEMA_MISMATCH -> UNKNOWN_KEY_ID -> KEY_MISMATCH -> KEY_ID_MISMATCH ->
    PAYLOAD_TAMPERED -> BAD_SIGNATURE.
    """
    if (trusted_public_key is None) == (trusted_keys is None):
        raise ValueError(
            "pass exactly one of trusted_public_key or trusted_keys; an unpinned "
            "check proves only self-consistency, never authenticity"
        )

    errors = schema_errors(data)
    if errors:
        return {"valid": False, "reasons": ["SCHEMA_MISMATCH"], "detail": errors}

    if trusted_keys is not None:
        # Resolve BEFORE any comparison, so an unrecognised key epoch is
        # reported as such rather than surfacing as a confusing KEY_MISMATCH
        # against whichever key happened to be tried.
        declared = data["payload"].get("key_id")
        if declared is None:
            return {
                "valid": False, "reasons": ["UNKNOWN_KEY_ID"],
                "detail": [
                    "certificate predates lethe.cert/3 and carries no key_id; "
                    "pass trusted_public_key explicitly to verify it"
                ],
            }
        if declared not in trusted_keys:
            return {
                "valid": False, "reasons": ["UNKNOWN_KEY_ID"],
                "detail": [
                    f"certificate names key epoch {declared!r}, which is not in the "
                    f"provided registry ({', '.join(sorted(trusted_keys)) or 'empty'})"
                ],
            }
        pinned = trusted_keys[declared]
    else:
        # Bound explicitly rather than leaning on the exactly-one check above
        # holding across a refactor.
        assert trusted_public_key is not None
        pinned = trusted_public_key

    try:
        embedded = base64.b64decode(data["public_key"], validate=True)
        trusted = base64.b64decode(pinned, validate=True)
    except Exception:
        return {
            "valid": False, "reasons": ["KEY_MISMATCH"],
            "detail": ["public key is not valid base64"],
        }
    if not hmac_mod.compare_digest(embedded, trusted):
        return {
            "valid": False, "reasons": ["KEY_MISMATCH"],
            "detail": ["certificate's embedded key does not match the trusted key"],
        }
    # See verify_certificate: a derived key_id must be recomputed, or it is
    # decorative. v1/v2 carry no key_id and skip this.
    declared_kid = data["payload"].get("key_id")
    if declared_kid is not None and not hmac_mod.compare_digest(
        declared_kid.encode(), key_id_for(data["public_key"]).encode()
    ):
        return {
            "valid": False, "reasons": ["KEY_ID_MISMATCH"],
            "detail": ["payload key_id does not match the embedded public key"],
        }
    payload_bytes = canonical_payload_bytes(data["payload"])
    if hashlib.sha256(payload_bytes).hexdigest() != data["payload_hash"]:
        return {
            "valid": False, "reasons": ["PAYLOAD_TAMPERED"],
            "detail": ["payload_hash does not match the payload"],
        }
    if not verify_signature(data["public_key"], payload_bytes, data["signature"]):
        return {
            "valid": False, "reasons": ["BAD_SIGNATURE"],
            "detail": ["Ed25519 signature verification failed"],
        }
    return {"valid": True, "reasons": [], "detail": []}

"""Machine verification of Lethe certificates: JSON-Schema shape check plus
key-pinned cryptographic verification with structured, agent-branchable reasons."""

import base64
import copy
import hashlib
import hmac as hmac_mod
import json
from functools import lru_cache
from importlib import resources

import jsonschema

from .certificate import canonical_payload_bytes
from .signing import verify_signature


# A certificate is meant to be verifiable forever, so newer verifiers must still
# validate older certs. Each version has its own schema, selected by the cert's
# declared payload.schema; the per-schema `const` pins a declared version to its
# exact shape, so a cert can't claim v1 while carrying v2 fields (or vice versa).
_SCHEMA_FILES = {
    "lethe.cert/1": "schemas/certificate-v1.json",
    "lethe.cert/2": "schemas/certificate-v2.json",
}
_LATEST = "lethe.cert/2"


@lru_cache(maxsize=None)
def _load_schema(version: str = _LATEST) -> dict:
    text = resources.files("lethe").joinpath(_SCHEMA_FILES[version]).read_text()
    return json.loads(text)


@lru_cache(maxsize=None)
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


def verify_certificate_json(data, trusted_public_key: str) -> dict:
    """Verify a certificate received as JSON. The trusted key is REQUIRED:
    an unpinned check only proves self-consistency, never authenticity.
    Reasons an agent can branch on, checked in order:
    SCHEMA_MISMATCH -> KEY_MISMATCH -> PAYLOAD_TAMPERED -> BAD_SIGNATURE."""
    errors = schema_errors(data)
    if errors:
        return {"valid": False, "reasons": ["SCHEMA_MISMATCH"], "detail": errors}
    try:
        embedded = base64.b64decode(data["public_key"], validate=True)
        trusted = base64.b64decode(trusted_public_key, validate=True)
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

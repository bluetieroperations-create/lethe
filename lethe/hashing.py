import hashlib
import hmac


def hash_subject(subject_id: str, salt: str) -> str:
    """Deterministic, non-reversible subject identifier for the provenance ledger.

    HMAC-SHA256 keyed by a per-deployment salt so the ledger never stores raw PII
    but lookups remain consistent.
    """
    return hmac.new(salt.encode(), subject_id.encode(), hashlib.sha256).hexdigest()

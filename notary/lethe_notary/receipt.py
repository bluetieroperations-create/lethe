"""The countersigned receipt a notary returns for a Lethe certificate.

WHAT THIS IS FOR. A Lethe certificate is self-attestation, and says so in its
own claim text: the operator generates the key, performs the deletion, signs
the certificate, and stamps it with their own clock. docs/anchoring.md names
the consequence — nothing in the artifact brings in a party the operator does
not control. This receipt is that party.

WHAT A RECEIPT CAN AND CANNOT SAY. The notary sees a 2.3 KB JSON document. It
has no access to the issuer's database, no way to observe the deletion, and no
way to know that the key embedded in the certificate belongs to the
organisation the presenter claims to be. So the receipt attests to exactly
three things and refuses the rest:

  * that a certificate with this payload hash was PRESENTED at this time, by
    the notary's clock rather than the issuer's;
  * that the certificate is INTERNALLY VALID — payload hash matches, Ed25519
    signature verifies against the key embedded in it, declared key_id matches
    that key;
  * that it named this audit_head at that moment.

The third is the one that pays for the other two. Lethe's chain cannot detect
tip-truncation on its own, and the documented mitigation is that a copy of the
head must live somewhere the operator cannot reach. A notary is that place: an
operator who later drops entries has to produce a chain that still contains
every head the notary witnessed, and cannot.
"""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime

from lethe.cert_schema import verify_certificate_json
from lethe.certificate import canonical_payload_bytes
from lethe.signing import key_id_for, verify_signature

NOTARY_SCHEMA = "lethe.notary/1"

CLAIM = (
    "At witnessed_at, by the notary's clock, a certificate with this "
    "payload_hash was presented to the notary and found internally valid: its "
    "payload hash matches its payload, its Ed25519 signature verifies against "
    "the public key embedded in it, and its declared key_id is the derived id "
    "of that key. The notary recorded audit_head as the chain position the "
    "certificate named at that moment, and retains that record. "
    "This receipt does NOT attest that the presenter is who they say they are, "
    "that certificate_public_key belongs to any particular organisation, that "
    "the deletion the certificate describes actually happened, or that "
    "anything else in the certificate is true. The notary has no access to the "
    "issuer's systems or data and cannot check any of that. What it adds to a "
    "self-issued certificate is an independent clock, an independent signature, "
    "and a copy of the audit head held outside the issuer's reach."
)


class NotarizationRefused(Exception):
    """The certificate did not verify, so it was not countersigned."""

    def __init__(self, reasons: list[str], detail: list[str]):
        self.reasons = reasons
        self.detail = detail
        super().__init__(f"certificate did not verify: {', '.join(reasons)}")


def _check_certificate(cert: dict) -> None:
    """Verify the certificate against the key embedded in it.

    Pinning to the certificate's own key is exactly the self-consistency check
    that lethe.cert_schema refuses to call proof — and here that is the correct
    check, because the notary is not asserting identity. It is asserting that
    the artifact is well-formed and genuinely signed by the key it names. The
    claim text above says so in as many words, so the receipt does not overstate
    what the check establishes.
    """
    if not isinstance(cert, dict) or not isinstance(cert.get("public_key"), str):
        raise NotarizationRefused(["MALFORMED"], ["not a certificate envelope"])
    result = verify_certificate_json(cert, trusted_public_key=cert["public_key"])
    if not result["valid"]:
        raise NotarizationRefused(result["reasons"], result["detail"])


def build_receipt(cert: dict, *, signer, witnessed_at: str | None = None) -> dict:
    """Verify `cert` and return a signed receipt. Refuses an invalid one.

    Countersigning something that does not verify would be worse than useless:
    it would lend the notary's signature to an artifact the notary had not
    actually checked.
    """
    _check_certificate(cert)
    payload = cert["payload"]
    receipt_payload = {
        "schema": NOTARY_SCHEMA,
        "notary_key_id": key_id_for(signer.public_key_b64()),
        "certificate_payload_hash": cert["payload_hash"],
        "certificate_key_id": payload.get("key_id"),
        "certificate_public_key": cert["public_key"],
        # Pseudonymous (HMAC under the issuer's own salt), so it is not
        # reversible by the notary and does not correlate across issuers. Kept
        # because a dispute is usually about one data subject.
        "subject_hash": payload.get("subject_hash"),
        "audit_head": payload.get("audit_head"),
        "certificate_issued_at": payload.get("issued_at"),
        "witnessed_at": witnessed_at or datetime.now(UTC).isoformat(),
        "claim": CLAIM,
    }
    data = canonical_payload_bytes(receipt_payload)
    return {
        "payload": receipt_payload,
        "payload_hash": hashlib.sha256(data).hexdigest(),
        "signature": signer.sign(data),
        "public_key": signer.public_key_b64(),
    }


def verify_receipt(
    receipt: dict,
    trusted_public_key: str | None = None,
    *,
    trusted_keys: dict[str, str] | None = None,
) -> dict:
    """Check a receipt against the notary's published key.

    Key-pinned like Lethe's own verifier, and for the same reason: a receipt
    checked only against the key inside it proves nothing, because anyone can
    mint that pair.

    Pass `trusted_keys={key_id: public_key}` — the `keys` list from
    /.well-known/notary — rather than a single key when the notary may have
    rotated. A receipt names the key that signed it, so without a registry a
    rotation would silently invalidate every receipt already sold, which is the
    opposite of what a durable piece of evidence is for. Exactly one of the two
    arguments is required; neither is an unpinned check.

    Returns {valid, reasons, detail}.
    """
    def fail(reason: str, detail: str) -> dict:
        return {"valid": False, "reasons": [reason], "detail": [detail]}

    if (trusted_public_key is None) == (trusted_keys is None):
        raise ValueError("pass exactly one of trusted_public_key or trusted_keys")

    if not isinstance(receipt, dict):
        return fail("MALFORMED", "receipt is not an object")
    for field in ("payload", "payload_hash", "signature", "public_key"):
        if field not in receipt:
            return fail("MALFORMED", f"missing {field}")
    payload = receipt["payload"]
    if not isinstance(payload, dict) or payload.get("schema") != NOTARY_SCHEMA:
        return fail("SCHEMA_MISMATCH", f"payload schema is not {NOTARY_SCHEMA}")

    if trusted_keys is not None:
        declared_key = payload.get("notary_key_id")
        if declared_key is None or declared_key not in trusted_keys:
            return fail(
                "UNKNOWN_KEY_ID",
                f"receipt names notary key {declared_key!r}, which is not in the "
                f"provided registry (known: {sorted(trusted_keys)})",
            )
        pinned_b64 = trusted_keys[declared_key]
    else:
        # Bound explicitly rather than leaning on the exactly-one check above
        # holding across a refactor — the same narrowing mypy flagged in
        # lethe.cert_schema, and the same reason to be explicit about it.
        assert trusted_public_key is not None
        pinned_b64 = trusted_public_key

    try:
        embedded = base64.b64decode(receipt["public_key"], validate=True)
        pinned = base64.b64decode(pinned_b64, validate=True)
    except Exception:
        return fail("KEY_MISMATCH", "public key is not valid base64")
    if not hmac.compare_digest(embedded, pinned):
        return fail("KEY_MISMATCH", "receipt was not signed by the trusted notary key")

    declared = payload.get("notary_key_id")
    if declared is None or not hmac.compare_digest(
        str(declared).encode(), key_id_for(receipt["public_key"]).encode()
    ):
        return fail("KEY_ID_MISMATCH", "notary_key_id does not match the signing key")

    data = canonical_payload_bytes(payload)
    if hashlib.sha256(data).hexdigest() != receipt["payload_hash"]:
        return fail("PAYLOAD_TAMPERED", "payload hash does not match the payload")
    if not verify_signature(receipt["public_key"], data, receipt["signature"]):
        return fail("BAD_SIGNATURE", "signature does not verify")
    return {"valid": True, "reasons": [], "detail": []}


def binds_certificate(receipt: dict, cert: dict) -> bool:
    """Does this receipt actually cover this certificate?

    A valid receipt for some *other* certificate proves nothing about this one,
    and checking the signature alone would not catch that.
    """
    return hmac.compare_digest(
        str(receipt.get("payload", {}).get("certificate_payload_hash", "")),
        str(cert.get("payload_hash", "")),
    ) and hmac.compare_digest(
        hashlib.sha256(canonical_payload_bytes(cert["payload"])).hexdigest().encode(),
        str(cert.get("payload_hash", "")).encode(),
    )


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

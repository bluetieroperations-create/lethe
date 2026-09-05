import base64
import hashlib

from lethe.cert_schema import schema_errors, verify_certificate_json
from lethe.certificate import build_certificate, canonical_payload_bytes, certificate_to_dict
from lethe.models import LayerResult
from lethe.signing import Signer


def _v1_payload() -> dict:
    """A genuine v1 payload, exactly matching schemas/certificate-v1.json (no v2
    fields). Hand-built because build_certificate now always emits v2."""
    return {
        "schema": "lethe.cert/1",
        "request_id": "req-1", "subject_hash": "subjA",
        "issued_at": "2026-06-21T00:00:00+00:00", "lethe_version": "0.1.0",
        "claim": "legacy v1 claim", "all_verified": True, "layers_found": 1,
        "records_deleted": 1, "all_layers_handled": True,
        "layers": [{
            "store": "pgvector", "namespace": "docs", "deleted_count": 1,
            "verified_absent": True, "requested_count": 1, "handled": True,
            "erased": True,
        }],
    }


def _signed_v1() -> tuple[dict, str]:
    signer = Signer.generate()
    payload = _v1_payload()
    data = canonical_payload_bytes(payload)
    cert = {
        "payload": payload,
        "payload_hash": hashlib.sha256(data).hexdigest(),
        "signature": signer.sign(data),
        "public_key": signer.public_key_b64(),
    }
    return cert, signer.public_key_b64()


def test_v1_certificate_still_validates_and_verifies():
    """Backward-compat: a v1 cert must still schema-validate AND cryptographically
    verify under the version-aware verifier — 'verifiable forever'."""
    cert, pub = _signed_v1()
    assert schema_errors(cert) == []
    assert verify_certificate_json(cert, trusted_public_key=pub) == {
        "valid": True, "reasons": [], "detail": []
    }


def test_v1_declared_cert_carrying_v2_field_is_rejected():
    """Downgrade-to-strip-evidence defense: a cert declaring schema v1 but
    carrying a v2-only field must fail (v1 additionalProperties:false)."""
    cert, pub = _signed_v1()
    cert["payload"]["valid_until"] = "2099-01-01T00:00:00+00:00"  # v2-only field
    assert schema_errors(cert) != []
    assert verify_certificate_json(cert, trusted_public_key=pub)["reasons"] == [
        "SCHEMA_MISMATCH"
    ]


def _golden() -> dict:
    signer = Signer.generate()
    cert = build_certificate(
        request_id="req-1", subject_hash="subjA",
        layers=[LayerResult("pgvector", "docs", 2, True, requested_count=2)],
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    return certificate_to_dict(cert)


def test_golden_certificate_validates():
    assert schema_errors(_golden()) == []


def test_missing_signature_fails():
    data = _golden()
    del data["signature"]
    assert any("signature" in e for e in schema_errors(data))


def test_wrong_schema_version_fails():
    data = _golden()
    data["payload"]["schema"] = "lethe.cert/999"
    assert schema_errors(data) != []


def test_extra_top_level_key_fails():
    data = _golden()
    data["extra"] = "sneaky"
    assert schema_errors(data) != []


def test_layer_missing_handled_fails():
    data = _golden()
    del data["payload"]["layers"][0]["handled"]
    assert schema_errors(data) != []


def test_non_dict_input_fails_not_crashes():
    assert schema_errors("not a cert") != []


def test_extra_key_inside_layer_fails():
    data = _golden()
    data["payload"]["layers"][0]["sneaky"] = True
    assert schema_errors(data) != []


def test_wrong_type_returns_errors_not_raises():
    data = _golden()
    data["payload"]["request_id"] = 123
    assert any("request_id" in e for e in schema_errors(data))


def test_oversized_layers_rejected():
    data = _golden()
    layer = dict(data["payload"]["layers"][0])
    data["payload"]["layers"] = [dict(layer) for _ in range(1001)]
    assert schema_errors(data) != []


def _signed_golden() -> tuple[dict, str]:
    signer = Signer.generate()
    cert = build_certificate(
        request_id="req-1", subject_hash="subjA",
        layers=[LayerResult("pgvector", "docs", 2, True, requested_count=2)],
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    return certificate_to_dict(cert), signer.public_key_b64()


def test_verify_json_valid_when_pinned():
    data, pub = _signed_golden()
    result = verify_certificate_json(data, trusted_public_key=pub)
    assert result == {"valid": True, "reasons": [], "detail": []}


def test_verify_json_schema_mismatch():
    data, pub = _signed_golden()
    del data["payload"]["claim"]
    result = verify_certificate_json(data, trusted_public_key=pub)
    assert result["valid"] is False
    assert result["reasons"] == ["SCHEMA_MISMATCH"]


def test_verify_json_key_mismatch_on_forged_cert():
    data, _ = _signed_golden()          # attacker's self-consistent cert
    _, operator_pub = _signed_golden()  # pinned to the REAL operator key
    result = verify_certificate_json(data, trusted_public_key=operator_pub)
    assert result["reasons"] == ["KEY_MISMATCH"]


def test_verify_json_key_substitution_is_key_id_mismatch():
    """Swapping in another operator's key to satisfy the pin check is now caught
    by key_id — which is derived from the public key — before the signature is
    even checked. Stricter and more specific than the old BAD_SIGNATURE."""
    data, _ = _signed_golden()
    _, operator_pub = _signed_golden()
    data["public_key"] = operator_pub  # spoof the pin check
    result = verify_certificate_json(data, trusted_public_key=operator_pub)
    assert result["reasons"] == ["KEY_ID_MISMATCH"]


def test_verify_json_bad_signature_still_reachable():
    """key_id must not mask a plain signature failure: corrupt only the
    signature, leaving key and payload internally consistent."""
    data, pub = _signed_golden()
    sig = bytearray(base64.b64decode(data["signature"]))
    sig[0] ^= 0xFF
    data["signature"] = base64.b64encode(bytes(sig)).decode()
    result = verify_certificate_json(data, trusted_public_key=pub)
    assert result["reasons"] == ["BAD_SIGNATURE"]


def test_verify_json_payload_tampered():
    data, pub = _signed_golden()
    data["payload"]["records_deleted"] = 9999
    result = verify_certificate_json(data, trusted_public_key=pub)
    assert result["reasons"] == ["PAYLOAD_TAMPERED"]


def test_verify_json_garbage_key_is_key_mismatch_not_crash():
    data, _ = _signed_golden()
    result = verify_certificate_json(data, trusted_public_key="!!!not-base64")
    assert result["valid"] is False
    assert result["reasons"] == ["KEY_MISMATCH"]


def test_verify_json_wrong_length_trusted_key_is_key_mismatch():
    data, _ = _signed_golden()
    short_but_valid_b64 = "QUJD"  # "ABC" — 3 bytes, valid base64
    result = verify_certificate_json(data, trusted_public_key=short_but_valid_b64)
    assert result["valid"] is False
    assert result["reasons"] == ["KEY_MISMATCH"]

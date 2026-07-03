from lethe.certificate import CLAIM, build_certificate, verify_certificate
from lethe.models import Certificate, LayerResult
from lethe.signing import Signer


def _layers():
    return [
        LayerResult("pgvector", "docs", 2, True),
        LayerResult("pgvector", "chats", 1, True),
    ]


def test_certificate_payload_contents():
    signer = Signer.generate()
    cert = build_certificate(
        request_id="req-1",
        subject_hash="subjA",
        layers=_layers(),
        issued_at="2026-06-21T00:00:00+00:00",
        version="0.1.0",
        signer=signer,
    )
    assert cert.payload["request_id"] == "req-1"
    assert cert.payload["subject_hash"] == "subjA"
    assert cert.payload["all_verified"] is True
    assert cert.payload["claim"] == CLAIM
    assert len(cert.payload["layers"]) == 2


def test_certificate_verifies():
    signer = Signer.generate()
    cert = build_certificate(
        request_id="req-1", subject_hash="subjA", layers=_layers(),
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    assert verify_certificate(cert, signer.public_key_b64()) is True


def test_all_verified_false_when_a_layer_fails():
    signer = Signer.generate()
    layers = [LayerResult("pgvector", "docs", 2, True), LayerResult("pgvector", "chats", 0, False)]
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=layers,
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    assert cert.payload["all_verified"] is False


def test_tampering_breaks_verification():
    signer = Signer.generate()
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=_layers(),
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    cert.payload["subject_hash"] = "someone-else"  # mutate after signing
    assert verify_certificate(cert, signer.public_key_b64()) is False


def test_layers_are_canonically_ordered():
    signer = Signer.generate()
    unordered = [LayerResult("pgvector", "z", 1, True), LayerResult("pgvector", "a", 1, True)]
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=unordered,
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    namespaces = [l["namespace"] for l in cert.payload["layers"]]
    assert namespaces == ["a", "z"]


def test_forged_cert_with_attacker_key_is_rejected_when_pinned():
    """An attacker mints a fully self-consistent certificate with their OWN key,
    claiming a victim's data was deleted. Verified against the TRUSTED operator
    key, it must be rejected. This is the certificate's whole reason to exist."""
    operator = Signer.generate()
    attacker = Signer.generate()
    forged = build_certificate(
        request_id="req-victim", subject_hash="victim-subject",
        layers=[LayerResult("pgvector", "docs", 9999, True)],
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=attacker,
    )
    # Self-consistent: attacker's embedded key signs attacker's payload.
    # Pinned to the operator's real public key, it MUST fail.
    assert verify_certificate(forged, trusted_public_key=operator.public_key_b64()) is False


def test_genuine_cert_passes_when_pinned_to_trusted_key():
    operator = Signer.generate()
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=_layers(),
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=operator,
    )
    assert verify_certificate(cert, trusted_public_key=operator.public_key_b64()) is True


def test_key_substitution_spoof_is_rejected_when_pinned():
    """Attacker signs with their own key but pastes the operator's public key
    string into the certificate so the pin check passes. The signature, made by
    the attacker's key, must still fail against the operator's public key."""
    operator = Signer.generate()
    attacker = Signer.generate()
    forged = build_certificate(
        request_id="r", subject_hash="victim",
        layers=[LayerResult("pgvector", "docs", 9999, True)],
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=attacker,
    )
    spoofed = Certificate(
        payload=forged.payload, payload_hash=forged.payload_hash,
        signature=forged.signature, public_key=operator.public_key_b64(),
    )
    assert verify_certificate(spoofed, trusted_public_key=operator.public_key_b64()) is False


def test_malformed_trusted_key_is_rejected_not_crashed():
    operator = Signer.generate()
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=_layers(),
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=operator,
    )
    assert verify_certificate(cert, trusted_public_key="!!!not-base64") is False


def test_certificate_payload_declares_schema_version():
    signer = Signer.generate()
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=_layers(),
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    assert cert.payload["schema"] == "lethe.cert/1"

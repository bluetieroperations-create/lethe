import pytest

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
    assert cert.payload["schema"] == "lethe.cert/2"


def test_v2_fields_present_and_signed():
    signer = Signer.generate()
    layers = [
        LayerResult(
            "pgvector", "docs", 2, True, requested_count=2,
            residual_count=0, verify_method="pgvector: count", index_version="idx-7",
        )
    ]
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=layers,
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
        valid_until="2026-07-21T00:00:00+00:00", declared_scope=["pinecone", "pgvector"],
    )
    # payload-level v2 fields
    assert cert.payload["valid_until"] == "2026-07-21T00:00:00+00:00"
    # declared_scope is sorted for determinism
    assert cert.payload["declared_scope"] == ["pgvector", "pinecone"]
    # per-layer verification evidence
    layer = cert.payload["layers"][0]
    assert layer["residual_count"] == 0
    assert layer["verify_method"] == "pgvector: count"
    assert layer["index_version"] == "idx-7"
    # the new fields are inside the signed payload, so tampering breaks the sig
    assert verify_certificate(cert, signer.public_key_b64()) is True
    cert.payload["valid_until"] = "2099-01-01T00:00:00+00:00"
    assert verify_certificate(cert, signer.public_key_b64()) is False


def test_v2_defaults_are_null_not_missing():
    """A bare build_certificate (no valid_until / declared_scope / evidence)
    still emits the keys, as null / empty — the cert is self-describing."""
    signer = Signer.generate()
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=[LayerResult("pgvector", "docs", 1, True)],
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    assert cert.payload["valid_until"] is None
    assert cert.payload["declared_scope"] == []
    assert cert.payload["layers"][0]["residual_count"] is None
    assert cert.payload["layers"][0]["verify_method"] is None
    assert cert.payload["layers"][0]["index_version"] is None


def test_valid_until_before_issued_at_is_rejected():
    """The trust anchor must never mint a self-contradictory window: a
    valid_until at or before issued_at means the absence is asserted for a
    zero/negative interval, yet the cert would still sign and verify. That is a
    nonsensical signed artifact and must be refused at build time."""
    signer = Signer.generate()
    with pytest.raises(ValueError):
        build_certificate(
            request_id="r", subject_hash="s",
            layers=[LayerResult("pgvector", "docs", 1, True)],
            issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
            valid_until="2026-06-16T00:00:00+00:00",  # 5 days BEFORE issue
        )


def test_valid_until_equal_issued_at_is_rejected():
    signer = Signer.generate()
    with pytest.raises(ValueError):
        build_certificate(
            request_id="r", subject_hash="s",
            layers=[LayerResult("pgvector", "docs", 1, True)],
            issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
            valid_until="2026-06-21T00:00:00+00:00",  # equal => empty window
        )

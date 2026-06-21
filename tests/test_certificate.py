from lethe.certificate import CLAIM, build_certificate, verify_certificate
from lethe.models import LayerResult
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
    assert verify_certificate(cert) is True


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
    assert verify_certificate(cert) is False


def test_layers_are_canonically_ordered():
    signer = Signer.generate()
    unordered = [LayerResult("pgvector", "z", 1, True), LayerResult("pgvector", "a", 1, True)]
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=unordered,
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    namespaces = [l["namespace"] for l in cert.payload["layers"]]
    assert namespaces == ["a", "z"]

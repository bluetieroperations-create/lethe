from lethe.cert_schema import schema_errors
from lethe.certificate import build_certificate, certificate_to_dict
from lethe.models import LayerResult
from lethe.signing import Signer


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

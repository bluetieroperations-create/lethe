"""The service, end to end over the real Starlette stack."""

import json

import pytest
from conftest import make_cert
from lethe_notary.receipt import verify_receipt
from lethe_notary.service import challenge_message, create_app
from starlette.testclient import TestClient

from lethe.signing import Signer, key_id_for


@pytest.fixture
def client(notary_signer, log, free_config):
    app = create_app(signer=notary_signer, log=log, config=free_config)
    with TestClient(app) as c:
        yield c


def test_notarize_returns_a_verifiable_receipt(client, operator, notary_signer):
    cert = make_cert(operator)
    r = client.post("/notarize", content=json.dumps(cert))

    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert verify_receipt(body["receipt"], notary_signer.public_key_b64())["valid"] is True
    assert body["receipt"]["payload"]["audit_head"] == cert["payload"]["audit_head"]


def test_an_invalid_certificate_is_refused_with_a_reason(client, operator):
    """An agent needs to branch on this, so it must not be a generic 500."""
    cert = make_cert(operator)
    cert["payload"]["records_deleted"] = 9999

    r = client.post("/notarize", content=json.dumps(cert))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "CERTIFICATE_INVALID"
    assert r.json()["reasons"] == ["PAYLOAD_TAMPERED"]
    assert r.json()["error"]["retriable"] is False


def test_the_same_certificate_is_witnessed_once_and_not_charged_twice(client, operator):
    """Two receipts for one certificate would disagree about when it was seen,
    which is the only thing the receipt is for."""
    cert = make_cert(operator)
    first = client.post("/notarize", content=json.dumps(cert)).json()
    second = client.post("/notarize", content=json.dumps(cert)).json()

    assert second["already_witnessed"] is True
    assert second["charged"] is False
    assert second["receipt"] == first["receipt"]
    assert second["receipt"]["payload"]["witnessed_at"] == \
        first["receipt"]["payload"]["witnessed_at"]


def test_an_oversized_body_is_rejected_before_parsing(client):
    r = client.post("/notarize", content=b"x" * (64 * 1024 + 1))
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "CERTIFICATE_TOO_LARGE"


def test_malformed_json_is_a_400_not_a_crash(client):
    r = client.post("/notarize", content=b"{not json")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "MALFORMED"


# -- witness retrieval ------------------------------------------------------

def _witness(client, signer, nonce=None):
    """A compliant client: signs the domain-separated message, never the bare
    nonce (see CHALLENGE_DOMAIN in service.py for why that distinction is the
    difference between a proof and a signing oracle)."""
    if nonce is None:
        issued = client.get("/challenge").json()
        nonce, message = issued["nonce"], issued["sign"].encode()
    else:
        message = challenge_message(client.app.state.notary.key_id, nonce)
    return client.post("/witness", content=json.dumps({
        "public_key": signer.public_key_b64(),
        "nonce": nonce,
        "signature": signer.sign(message),
    }))


def test_the_key_holder_can_read_back_every_head_witnessed(client, operator):
    heads = ["a" * 64, "b" * 64, "c" * 64]
    for i, head in enumerate(heads):
        client.post("/notarize",
                    content=json.dumps(make_cert(operator, audit_head=head,
                                                 request_id=f"r{i}")))

    body = _witness(client, operator).json()
    assert body["ok"] is True
    assert body["key_id"] == key_id_for(operator.public_key_b64())
    assert [w["audit_head"] for w in body["witnessed"]] == heads


def test_someone_elses_key_cannot_read_your_log(client, operator):
    """The log is private. Holding a valid key proves control of THAT key, and
    grants nothing about anyone else's."""
    client.post("/notarize", content=json.dumps(make_cert(operator)))
    stranger = Signer.generate()

    assert _witness(client, stranger).json()["witnessed"] == []


def test_a_signature_from_the_wrong_key_is_refused(client, operator):
    issued = client.get("/challenge").json()
    r = client.post("/witness", content=json.dumps({
        "public_key": operator.public_key_b64(),
        "nonce": issued["nonce"],
        "signature": Signer.generate().sign(issued["sign"].encode()),  # not operator's
    }))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "SIGNATURE_INVALID"


def test_signing_the_bare_nonce_is_refused(client, operator):
    """The naive reading of "sign the nonce" must FAIL, not be quietly
    accepted. Accepting both forms would leave the signing oracle wide open:
    the operator signs with the same key that signs certificates, and the
    server picks the nonce, so a malicious notary could serve a canonical
    certificate payload as the nonce and harvest a valid certificate
    signature. Prefixing makes the two message spaces disjoint — a certificate
    payload is canonical JSON and always starts with "{"."""
    nonce = client.get("/challenge").json()["nonce"]
    r = client.post("/witness", content=json.dumps({
        "public_key": operator.public_key_b64(),
        "nonce": nonce,
        "signature": operator.sign(nonce.encode()),  # the bare nonce
    }))
    assert r.status_code == 401
    assert "not the bare nonce" in r.json()["error"]["message"]


def test_the_challenge_tells_the_client_exactly_what_to_sign(client):
    """So a correct client never has to guess the construction."""
    issued = client.get("/challenge").json()
    key_id = client.app.state.notary.key_id
    assert issued["sign"] == f"lethe-notary/challenge/v1:{key_id}:{issued['nonce']}"
    # Structurally impossible to be a certificate payload.
    assert not issued["sign"].lstrip().startswith("{")


def test_a_signature_harvested_by_one_notary_is_useless_at_another(
    operator, notary_signer, log, free_config, tmp_path
):
    """The notary's own key id is in the signed message, so a signature
    obtained by notary A does not authenticate at notary B."""
    from lethe_notary.store import WitnessLog

    other_signer = Signer.generate()
    other = create_app(signer=other_signer, log=WitnessLog(str(tmp_path / "b.db")),
                       config=free_config)
    app_a = create_app(signer=notary_signer, log=log, config=free_config)

    with TestClient(app_a) as a, TestClient(other) as b:
        nonce = a.get("/challenge").json()["nonce"]
        harvested = operator.sign(challenge_message(app_a.state.notary.key_id, nonce))
        # Replay it at B, which happens to have issued the same nonce.
        b.app.state.notary._challenges[nonce] = __import__("time").monotonic() + 120
        r = b.post("/witness", content=json.dumps({
            "public_key": operator.public_key_b64(), "nonce": nonce,
            "signature": harvested,
        }))
    assert r.status_code == 401


def test_a_challenge_cannot_be_replayed(client, operator):
    """One challenge, one use. A replayable nonce is a bearer token with extra
    steps, and this endpoint exists precisely to avoid bearer tokens."""
    nonce = client.get("/challenge").json()["nonce"]
    assert _witness(client, operator, nonce).status_code == 200

    replay = _witness(client, operator, nonce)
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "CHALLENGE_INVALID"


def test_an_unknown_nonce_is_refused(client, operator):
    r = _witness(client, operator, "never-issued-by-this-notary")
    assert r.status_code == 401


# -- discovery --------------------------------------------------------------

def test_well_known_publishes_the_key_and_the_claim(client, notary_signer):
    body = client.get("/.well-known/notary").json()
    assert body["public_key"] == notary_signer.public_key_b64()
    assert body["notary_key_id"] == key_id_for(notary_signer.public_key_b64())
    # The limits must be discoverable, not buried in docs.
    assert "does NOT attest" in body["claim"]
    assert body["paid"] is False

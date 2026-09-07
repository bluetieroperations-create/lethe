"""Payment gating, including the ways it must refuse to run."""

import json

import pytest
from conftest import make_cert
from lethe_notary.payments import PaymentConfig, PaymentConfigError, PaymentGate
from lethe_notary.service import create_app
from starlette.responses import JSONResponse
from starlette.testclient import TestClient


def test_a_paid_notary_refuses_to_start_without_somewhere_to_be_paid():
    """The failure this prevents: one missing environment variable on a deploy,
    and the service quietly gives itself away. Free mode must be asked for."""
    with pytest.raises(PaymentConfigError) as e:
        PaymentConfig.from_env({})
    assert "LETHE_NOTARY_PAY_TO" in str(e.value)
    assert "LETHE_NOTARY_FREE" in str(e.value)


def test_free_mode_must_be_explicit_and_then_it_is_allowed():
    config = PaymentConfig.from_env({"LETHE_NOTARY_FREE": "1"})
    assert config.free_mode is True
    assert config.pay_to is None


def test_a_plaintext_facilitator_is_refused():
    """The facilitator is told what was paid and settles it. Over http that is
    an interceptable claim about money."""
    with pytest.raises(PaymentConfigError) as e:
        PaymentConfig.from_env({
            "LETHE_NOTARY_PAY_TO": "0x000000000000000000000000000000000000dEaD",
            "LETHE_NOTARY_FACILITATOR": "http://facilitator.example",
        })
    assert "https" in str(e.value)


def test_a_configured_notary_reads_price_and_network():
    config = PaymentConfig.from_env({
        "LETHE_NOTARY_PAY_TO": "0x000000000000000000000000000000000000dEaD", "LETHE_NOTARY_PRICE": "$0.05",
        "LETHE_NOTARY_NETWORK": "base-sepolia",
    })
    assert (config.price, config.network, config.free_mode) == ("$0.05", "base-sepolia", False)


def test_the_default_network_is_one_the_default_facilitator_can_settle():
    """The public x402.org facilitator advertises testnet kinds only.
    Defaulting to mainnet would give a notary that starts cleanly and fails
    every paid request."""
    assert PaymentConfig.from_env({"LETHE_NOTARY_PAY_TO": "0x000000000000000000000000000000000000dEaD"}).network == "base-sepolia"


# -- the real 402 branch, against the actual SDK ----------------------------
#
# This runs offline: building requirements and encoding the PAYMENT-REQUIRED
# header never contacts the facilitator. It is worth testing for real because
# the first version of this code passed its tests against a hand-written fake
# whose method signatures did not match the SDK's, and only failed when the
# server was actually run.


@pytest.mark.live
def test_an_unpaid_request_gets_a_real_decodable_payment_required_header(
    notary_signer, log, operator
):
    from x402.http import PAYMENT_REQUIRED_HEADER, decode_payment_required_header

    config = PaymentConfig(pay_to="0x000000000000000000000000000000000000dEaD",
                           price="$0.02", network="base-sepolia",
                           facilitator_url="https://x402.org/facilitator")
    app = create_app(signer=notary_signer, log=log, config=config)
    with TestClient(app) as client:
        r = client.post("/notarize", content=json.dumps(make_cert(operator)))

    assert r.status_code == 402
    assert r.json()["error"]["code"] == "PAYMENT_REQUIRED"
    assert r.json()["error"]["retriable"] is True

    # Not just "a header is present" — a client must be able to read it back.
    decoded = decode_payment_required_header(r.headers[PAYMENT_REQUIRED_HEADER])
    accepts = decoded.accepts if hasattr(decoded, "accepts") else decoded["accepts"]
    option = accepts[0]
    def get(o, k):
        return o.get(k) if isinstance(o, dict) else getattr(o, k, None)

    assert "84532" in str(get(option, "network")) or get(option, "network") == "base-sepolia"
    assert get(option, "payTo") or get(option, "pay_to") == config.pay_to


@pytest.mark.live
def test_a_garbled_payment_signature_is_a_402_not_a_500(notary_signer, log, operator):
    """A malformed payment is the caller's mistake. It must not reach the
    facilitator and must not look like a server fault."""
    config = PaymentConfig(pay_to="0x000000000000000000000000000000000000dEaD",
                           price="$0.02", network="base-sepolia",
                           facilitator_url="https://x402.org/facilitator")
    app = create_app(signer=notary_signer, log=log, config=config)
    with TestClient(app) as client:
        r = client.post("/notarize", content=json.dumps(make_cert(operator)),
                        headers={"PAYMENT-SIGNATURE": "not-a-real-payment"})

    assert r.status_code == 402
    assert r.json()["error"]["code"] == "PAYMENT_INVALID"


# -- accounting: money moves exactly when work is done ----------------------
#
# Settlement itself needs a funded wallet and a live facilitator, so the whole
# gate is replaced here. These tests are about WHEN the service charges, which
# is the part that is ours to get right.


class _FakeGate:
    """Replaces PaymentGate wholesale. Deliberately not a partial stub of the
    SDK: a fake that imitates someone else's method signatures is a fake that
    can be wrong about them."""

    enabled = True

    def __init__(self, accept=True):
        self.accept = accept
        self.charges = 0
        self.config = PaymentConfig(pay_to="0x000000000000000000000000000000000000dEaD", price="$0.01", network="base-sepolia",
                                    facilitator_url="https://x402.org/facilitator")

    def charge(self, request):
        if request.headers.get("PAYMENT-SIGNATURE") is None:
            return False, JSONResponse({"ok": False, "error": {
                "code": "PAYMENT_REQUIRED", "message": "pay and retry",
                "retriable": True}}, status_code=402)
        if not self.accept:
            return False, JSONResponse({"ok": False, "error": {
                "code": "PAYMENT_INVALID", "message": "declined",
                "retriable": True}}, status_code=402)
        self.charges += 1
        return True, None


@pytest.fixture
def paid(notary_signer, log, free_config):
    app = create_app(signer=notary_signer, log=log, config=free_config)
    gate = _FakeGate()
    app.state.notary.gate = gate
    with TestClient(app) as c:
        yield c, gate


PAY = {"PAYMENT-SIGNATURE": "stub"}


def test_a_paid_request_is_notarized_and_charged(paid, operator):
    client, gate = paid
    r = client.post("/notarize", content=json.dumps(make_cert(operator)), headers=PAY)

    assert r.status_code == 200
    assert r.json()["charged"] is True
    assert gate.charges == 1


def test_an_unpaid_request_is_not_notarized(paid, operator):
    client, gate = paid
    r = client.post("/notarize", content=json.dumps(make_cert(operator)))

    assert r.status_code == 402
    assert gate.charges == 0
    assert client.app.state.notary.log.count() == 0


def test_a_declined_payment_records_nothing(paid, operator):
    client, gate = paid
    gate.accept = False

    r = client.post("/notarize", content=json.dumps(make_cert(operator)), headers=PAY)
    assert r.status_code == 402
    assert gate.charges == 0
    assert client.app.state.notary.log.count() == 0


def test_an_invalid_certificate_is_never_charged_for(paid, operator):
    """Verification happens before charging on purpose: a customer must not pay
    for a refusal."""
    client, gate = paid
    cert = make_cert(operator)
    cert["payload"]["records_deleted"] = 9999

    r = client.post("/notarize", content=json.dumps(cert), headers=PAY)
    assert r.status_code == 422
    assert gate.charges == 0


def test_re_presenting_a_certificate_is_free(paid, operator):
    """No new work, no new money — and no second receipt disagreeing with the
    first about when the certificate was seen."""
    client, gate = paid
    cert = make_cert(operator)
    client.post("/notarize", content=json.dumps(cert), headers=PAY)
    assert gate.charges == 1

    again = client.post("/notarize", content=json.dumps(cert), headers=PAY)
    assert again.json()["charged"] is False
    assert again.json()["already_witnessed"] is True
    assert gate.charges == 1


def test_witness_retrieval_and_discovery_are_never_charged(paid, operator):
    """Witness retrieval is the query an operator runs during a dispute.
    Charging for it at that moment would make the evidence worthless."""
    client, gate = paid
    client.post("/notarize", content=json.dumps(make_cert(operator)), headers=PAY)
    gate.charges = 0

    issued = client.get("/challenge").json()
    r = client.post("/witness", content=json.dumps({
        "public_key": operator.public_key_b64(), "nonce": issued["nonce"],
        "signature": operator.sign(issued["sign"].encode()),
    }))
    assert r.status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/.well-known/notary").status_code == 200
    assert gate.charges == 0


def test_gate_is_disabled_only_in_free_mode(free_config):
    assert PaymentGate(free_config).enabled is False
    paid_config = PaymentConfig(pay_to="0x000000000000000000000000000000000000dEaD", price="$0.01", network="base-sepolia",
                                facilitator_url="https://x402.org/facilitator")
    assert PaymentGate(paid_config).enabled is True


# -- a payee that cannot receive money --------------------------------------


@pytest.mark.parametrize("bad", [
    "<PAY_TO address>",     # the placeholder from the setup instructions
    "0xdEaD",               # too short
    "not-an-address",
    "0x" + "g" * 40,        # not hex
])
def test_a_payee_that_cannot_receive_money_is_refused(bad):
    """Found by running the real thing: LETHE_NOTARY_PAY_TO="<PAY_TO address>"
    — the placeholder, left in verbatim — started the server, passed the
    facilitator preflight, and quoted payments to a destination that does not
    exist. Nothing complained until a customer had already signed.

    A misconfigured payee is worse than none: it fails silently, and it fails
    after taking someone's money."""
    with pytest.raises(PaymentConfigError, match="not a valid address"):
        PaymentConfig.from_env({"LETHE_NOTARY_PAY_TO": bad,
                                "LETHE_NOTARY_NETWORK": "base-sepolia"})


def test_a_transposed_character_is_caught_by_the_eip55_checksum():
    """A mixed-case address carries a checksum, so one wrong character is
    detectable — which is exactly the typo a human makes copying an address."""
    good = "0xd3eD2dD9ff7e7783E8FD8Df1f4e9803b2B6C5151"
    PaymentConfig.from_env({"LETHE_NOTARY_PAY_TO": good,
                            "LETHE_NOTARY_NETWORK": "base-sepolia"})   # fine

    with pytest.raises(PaymentConfigError, match="checksum"):
        PaymentConfig.from_env({"LETHE_NOTARY_PAY_TO": good[:-1] + "2",
                                "LETHE_NOTARY_NETWORK": "base-sepolia"})


def test_an_all_lowercase_address_is_allowed():
    """It carries no checksum to verify, so the shape check is all there is —
    and refusing it would reject addresses people legitimately paste."""
    PaymentConfig.from_env({
        "LETHE_NOTARY_PAY_TO": "0xd3ed2dd9ff7e7783e8fd8df1f4e9803b2b6c5151",
        "LETHE_NOTARY_NETWORK": "base-sepolia"})


def test_a_non_evm_network_skips_the_evm_shape_check():
    """Solana and friends use entirely different address formats; applying the
    EVM rule there would reject every valid payee."""
    PaymentConfig.from_env({
        "LETHE_NOTARY_PAY_TO": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
        "LETHE_NOTARY_NETWORK": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"})

"""The payment path, driven by a real x402 client rather than a fake.

Every other payment test replaces the gate, which is right for testing WHEN
the service charges. It cannot test whether the service can read what a paying
client actually sends — a stub never disagrees with itself. Two bugs lived in
that blind spot until a real client was pointed at the server:

  * decode_payment_signature_header already returns a PaymentPayload; the code
    parsed it a second time and died on 'PaymentPayload' object has no
    attribute 'get'.
  * match_payload_to_requirements is a THREE-argument predicate returning bool
    (version, payload, requirements), not a two-argument lookup returning the
    matching requirement.

Either one made every real payment fail. Both were invisible to 68 passing
tests. This builds a genuine signed payment with the client SDK and pushes it
through the server's own charge path.
"""

import json

import pytest
from conftest import make_cert
from lethe_notary.payments import PaymentConfig
from lethe_notary.service import create_app
from starlette.testclient import TestClient

pytest.importorskip("eth_account", reason="needs x402[evm]")

NETWORK = "eip155:84532"          # Base Sepolia, in CAIP-2 as clients require
PAYEE = "0x000000000000000000000000000000000000dEaD"


def _signed_payment_header(payment_required) -> str:
    """A real PAYMENT-SIGNATURE header, built the way a paying client builds
    one: an EIP-3009 authorization signed by an actual key."""
    import secrets

    from eth_account import Account
    from x402 import x402ClientSync
    from x402.http import encode_payment_signature_header
    from x402.mechanisms.evm.exact.register import register_exact_evm_client
    from x402.mechanisms.evm.signers import EthAccountSigner

    buyer = Account.from_key("0x" + secrets.token_hex(32))
    client = x402ClientSync()
    register_exact_evm_client(client, EthAccountSigner(buyer), networks=NETWORK)
    payload = client.create_payment_payload(payment_required)
    return encode_payment_signature_header(payload)


class _AcceptingFacilitator:
    """Stands in for the facilitator ONLY. Everything up to it — decoding the
    header, matching it to requirements — is the real SDK and the real code."""

    def __init__(self, server):
        self._server = server
        self.verified = []
        self.settled = []

    def __getattr__(self, name):
        return getattr(self._server, name)

    def verify_payment(self, payload, requirements, *a, **kw):
        self.verified.append((payload, requirements))
        return type("V", (), {"is_valid": True, "invalid_reason": None})()

    def settle_payment(self, payload, requirements, *a, **kw):
        self.settled.append((payload, requirements))
        return type("S", (), {"success": True})()


@pytest.mark.live
def test_a_real_signed_payment_is_read_matched_and_settled(
    notary_signer, log, operator
):
    """Builds requirements against the live facilitator (which is what makes
    this a live test), then proves the server can read a genuine payment."""
    config = PaymentConfig(pay_to=PAYEE, price="$0.01", network=NETWORK,
                           facilitator_url="https://x402.org/facilitator")
    app = create_app(signer=notary_signer, log=log, config=config)

    gate = app.state.notary.gate
    real_server = gate.server()
    fake = _AcceptingFacilitator(real_server)
    gate._server = fake

    requirements = real_server.build_payment_requirements(gate.resource_config())
    header = _signed_payment_header(
        real_server.create_payment_required_response(requirements))

    with TestClient(app) as client:
        r = client.post("/notarize", content=json.dumps(make_cert(operator)),
                        headers={"PAYMENT-SIGNATURE": header})

    assert r.status_code == 200, r.json()
    assert r.json()["charged"] is True
    # The header was decoded into a payload and matched to a requirement —
    # the two steps that were broken.
    assert len(fake.verified) == 1
    assert len(fake.settled) == 1
    payload, matched = fake.verified[0]
    assert matched.network == NETWORK
    assert matched.pay_to.lower() == PAYEE.lower()


@pytest.mark.live
def test_a_client_cannot_pay_requirements_quoted_under_a_network_alias():
    """The interop bug that made the documented default unpayable.

    The facilitator advertises BOTH "base-sepolia" and "eip155:84532" as
    separate kinds, so a server configured with the alias builds a perfectly
    well-formed 402 and looks healthy. A client registers under CAIP-2 and
    refuses to pay it: "no payment requirements match registered schemes".
    Nothing on the server side complains, which is why check_network has to.
    """
    import secrets

    from eth_account import Account
    from lethe_notary.payments import PaymentGate
    from x402 import x402ClientSync
    from x402.mechanisms.evm.exact.register import register_exact_evm_client
    from x402.mechanisms.evm.signers import EthAccountSigner

    # Constructed directly, bypassing from_env, precisely because the config
    # check now refuses to build this — that check is the fix.
    alias_config = PaymentConfig(pay_to=PAYEE, price="$0.01", network="base-sepolia",
                                 facilitator_url="https://x402.org/facilitator")
    alias_gate = PaymentGate(alias_config)
    alias_server = alias_gate.server()
    requirements = alias_server.build_payment_requirements(alias_gate.resource_config())
    assert requirements, "the alias really does produce requirements"
    alias_required = alias_server.create_payment_required_response(requirements)

    buyer = Account.from_key("0x" + secrets.token_hex(32))
    client = x402ClientSync()
    register_exact_evm_client(client, EthAccountSigner(buyer), networks=NETWORK)

    with pytest.raises(Exception, match="match|scheme"):
        client.create_payment_payload(alias_required)


def test_the_default_network_is_the_caip2_form():
    """Not live: pins that the default a fresh operator gets is payable."""
    config = PaymentConfig.from_env({"LETHE_NOTARY_PAY_TO": PAYEE})
    assert config.network == NETWORK

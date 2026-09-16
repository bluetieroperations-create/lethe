"""What the banner is allowed to claim.

The banner is the last thing an operator reads before the service is live, and
it gets read as a readiness signal — "it printed the address, so it's set up".
Only one line in it has been checked against the world. These tests hold that
line: every other claim must either be absent or marked unchecked.
"""

from lethe_notary.cli import startup_banner
from lethe_notary.payments import PaymentConfig

PAYEE = "0x000000000000000000000000000000000000dEaD"
KEY_ID = "abcd1234"
FACILITATOR = "https://facilitator.example/x402"


def config_for(network, *, free=False, pay_to=PAYEE):
    return PaymentConfig(pay_to=pay_to, price="$0.01", network=network,
                         facilitator_url=FACILITATOR, free_mode=free)


def banner(network, **kw):
    return "\n".join(startup_banner(config_for(network, **kw), KEY_ID))


def test_testnet_says_the_money_is_not_real():
    """The mixed-up-environments failure, in the direction that costs revenue:
    an operator believes a testnet notary is earning."""
    out = banner("eip155:84532")
    assert "TESTNET - payments are not real money" in out
    assert "MAINNET" not in out


def test_mainnet_says_the_money_is_real():
    """And the direction that costs money: real charges believed to be play."""
    out = banner("eip155:8453")
    assert "MAINNET - real money" in out
    assert "TESTNET" not in out


def test_an_unrecognized_network_is_neither_claimed_nor_guessed():
    """Guessing either way is a lie an operator would act on, so an unlisted
    network gets an answer of its own."""
    out = banner("eip155:31337")
    assert "unrecognized network" in out
    assert "TESTNET" not in out
    assert "MAINNET" not in out


def test_the_only_checked_claim_is_the_one_preflight_made():
    """Preflight asked the facilitator whether it settles this (scheme,
    network). That is the whole of what this process knows."""
    out = banner("eip155:84532")
    checked = [ln for ln in out.splitlines() if "checked:" in ln
               and "NOT checked:" not in ln]
    assert len(checked) == 1
    assert FACILITATOR in checked[0]
    assert "eip155:84532" in checked[0]


def test_the_checked_line_names_the_facilitator_actually_configured():
    """A hardcoded URL here would vouch for a service that was never asked."""
    other = "https://other-facilitator.example"
    out = "\n".join(startup_banner(
        PaymentConfig(pay_to=PAYEE, price="$0.01", network="eip155:84532",
                      facilitator_url=other, free_mode=False), KEY_ID))
    assert other in out
    assert FACILITATOR not in out


def test_mainnet_marks_the_payee_as_unverified_and_names_it():
    """The failure: a typo'd or borrowed address, a service that starts
    cleanly, and every payment landing in a wallet the operator cannot open.
    Nothing in this process can detect it, so the banner must not imply it
    did — and it names the address so the operator can read it back."""
    out = banner("eip155:8453")
    assert PAYEE in out
    payee_lines = [ln for ln in out.splitlines() if PAYEE in ln]
    assert all("NOT checked:" in ln for ln in payee_lines)


def test_mainnet_does_not_let_configured_be_read_as_earning():
    out = banner("eip155:8453")
    assert "NOT checked: that any payment has succeeded" in out
    assert "configured, not earning" in out


def test_an_unrecognized_network_gets_the_mainnet_caveats():
    """Unknown might be real money. The caveats are cheap; being wrong is not."""
    out = banner("eip155:31337")
    assert out.count("NOT checked:") == 2
    assert PAYEE in out


def test_testnet_is_not_padded_with_caveats_that_cost_nothing():
    """A caveat nobody needs is a caveat everybody learns to skip — including
    on the run where it is the mainnet one."""
    assert "NOT checked:" not in banner("eip155:84532")


def test_free_mode_says_free_and_quotes_no_price():
    """Free mode charges nobody. A price or a network in this line reads as a
    service that is billing."""
    out = banner("eip155:8453", free=True)
    assert "FREE (not charging)" in out
    assert "$0.01" not in out
    assert "eip155:8453" not in out
    assert "MAINNET" not in out


def test_free_mode_names_no_payee_even_if_one_is_configured():
    """Direct construction can carry both (from_env refuses to). Printing the
    address next to FREE would read as money moving to it."""
    out = banner("eip155:8453", free=True, pay_to=PAYEE)
    assert PAYEE not in out
    assert "FREE" in out


def test_every_variant_identifies_the_key_that_will_be_signing():
    """The key is the service; a receipt from the wrong one verifies against
    nothing the customer pinned."""
    for out in (banner("eip155:84532"), banner("eip155:8453"),
                banner("eip155:31337"), banner("eip155:8453", free=True)):
        assert KEY_ID in out.splitlines()[0]

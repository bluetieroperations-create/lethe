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


def test_the_readme_shows_what_the_banner_actually_prints():
    """The banner is quoted in notary/README.md, under the mainnet section an
    operator reads exactly once, right before they go live.

    This PR already carries a CHANGELOG entry for a README that documented
    mainnet wrongly, and the commit that made the banner honest left that same
    README quoting the old one-line form. A doc that describes a safety notice
    inaccurately is worse than no doc: it teaches the operator what to expect,
    so the line they should have read as new reads as normal. Pin it.
    """
    import re
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    blocks = re.findall(r"^```\n(lethe-notary .*?)```",
                        readme.read_text(), re.S | re.M)
    assert blocks, "no banner block found in notary/README.md"

    for block in blocks:
        lines = block.rstrip("\n").splitlines()
        # Drive the comparison from the README itself, so a block for a network
        # nobody has thought of yet is still checked rather than skipped.
        head = re.match(r"lethe-notary  key_id=…  (\S+) on (\S+) \[", lines[0])
        assert head, f"unrecognized banner block in README:\n{lines[0]}"
        price, network = head.groups()
        facilitator = re.search(r"checked:\s+(\S+) reports it", block)
        assert facilitator, f"README banner block has no checked: line:\n{block}"

        rendered = startup_banner(
            PaymentConfig(pay_to=PAYEE, price=price, network=network,
                          facilitator_url=facilitator.group(1), free_mode=False),
            KEY_ID)
        # The README elides the two operator-specific values.
        actual = [re.sub(r"0x[0-9a-fA-F]{40}", "0x…",
                         ln.replace(f"key_id={KEY_ID}", "key_id=…"))
                  for ln in rendered]
        assert actual == lines, (
            "notary/README.md shows a banner the code does not print.\n"
            "README:\n  " + "\n  ".join(lines) +
            "\nactual:\n  " + "\n  ".join(actual))


def test_an_authenticated_preflight_is_reported_as_checked():
    """With a credential, preflight sent a token and the facilitator accepted
    it — otherwise the process would have died before printing anything. That
    is a measurement, so it belongs under `checked:` rather than being implied
    by the credential merely being configured."""
    import base64

    from lethe_notary.cdp_auth import CdpCredentials

    creds = CdpCredentials(key_id="key-abc", secret=base64.b64encode(bytes(32)).decode())
    out = "\n".join(startup_banner(
        PaymentConfig(pay_to=PAYEE, price="$0.01", network="eip155:8453",
                      facilitator_url=FACILITATOR, cdp_credentials=creds),
        KEY_ID))
    assert "checked:     it accepted CDP credential key-abc" in out
    assert out.count("NOT checked:") == 2


def test_the_banner_never_prints_the_cdp_secret():
    """The banner goes to stderr, which lands in journalctl, a container log
    aggregator, and the screenshot an operator pastes when asking for help."""
    import base64

    from lethe_notary.cdp_auth import CdpCredentials

    secret = base64.b64encode(bytes(range(32))).decode()
    for network in ("eip155:84532", "eip155:8453", "eip155:31337"):
        out = "\n".join(startup_banner(
            PaymentConfig(pay_to=PAYEE, price="$0.01", network=network,
                          facilitator_url=FACILITATOR,
                          cdp_credentials=CdpCredentials(key_id="key-abc", secret=secret)),
            KEY_ID))
        assert secret not in out
        assert secret[:16] not in out


def test_without_a_credential_the_banner_says_nothing_about_one():
    out = "\n".join(startup_banner(config_for("eip155:8453"), KEY_ID))
    assert "CDP" not in out


def test_no_readme_line_claims_banner_output_the_code_cannot_produce():
    """The block guard above only covers fences that open with `lethe-notary`.
    A single continuation line quoted on its own — which the mainnet auth
    section does — slips past it, and that is exactly the shape that goes
    stale: it is the line an operator scans for to confirm their credential
    took.

    So the weaker, broader property: every line anywhere in the README that
    looks like banner output must be a line some configuration actually
    prints. Renders every variant and checks membership, which needs no
    parsing of the surrounding prose and cannot be fooled by a fence.
    """
    import base64
    import re
    from itertools import product
    from pathlib import Path

    from lethe_notary.cdp_auth import CdpCredentials

    def normalize(line):
        """Blur the parts that legitimately vary between one operator and
        another — which facilitator, which payee, which network. What is being
        checked is that the *wording* is something the code emits."""
        line = re.sub(r"0x[0-9a-fA-F]{40}", "0x…", line)
        line = re.sub(r"https?://\S+", "<url>", line)
        line = re.sub(r"eip155:\d+", "<network>", line)
        return line.rstrip()

    creds = CdpCredentials(key_id="<key id>",
                           secret=base64.b64encode(bytes(32)).decode())
    producible = set()
    for network, credential, free in product(
            ("eip155:84532", "eip155:8453", "eip155:31337"), (None, creds), (False, True)):
        if free and credential is not None:
            continue  # refused by check(); never rendered
        config = PaymentConfig(
            pay_to=None if free else PAYEE, price="$0.01", network=network,
            facilitator_url=FACILITATOR, free_mode=free, cdp_credentials=credential)
        producible.update(normalize(line) for line in startup_banner(config, KEY_ID))

    quoted = [normalize(ln) for ln in
              (Path(__file__).resolve().parents[1] / "README.md").read_text().splitlines()
              if re.match(r"^\s+(checked:|NOT checked:)", ln)]
    assert quoted, "no banner continuation lines found in the README"
    unproducible = [ln for ln in quoted if ln not in producible]
    assert not unproducible, (
        "notary/README.md quotes banner lines the code never prints:\n  "
        + "\n  ".join(unproducible))

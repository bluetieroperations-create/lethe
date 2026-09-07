"""x402 payment gating for the notarize endpoint.

WHY x402 FITS. The caller here is an agent, not a person. Agents cannot
complete signup flows, do not have email addresses, and do not survive token
rotation — but they sign structured payloads in milliseconds. x402 inverts the
credential problem: the server trusts a signature on a payment rather than a
token issued in advance. For a per-certificate service with no accounts, that
is the whole integration.

WHAT IS PAID FOR, AND WHAT IS NOT. Only notarization is charged, and it is
charged to the data CONTROLLER, who is buying evidence about their own
compliance. Nothing here sits between a data subject and their erasure: GDPR
Art. 12(5) requires actions under Arts. 15-22 to be free of charge, and a
paywall in that path would be both unlawful and self-defeating for a tool whose
product is provable compliance. Witness retrieval — the dispute-resolution
query the evidence is actually for — is free for the same reason: charging to
read back your own evidence at the moment you need it would make the evidence
worthless.
"""

import logging
import os
import re
from dataclasses import dataclass
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("lethe_notary.payments")


class PaymentConfigError(Exception):
    """The service was asked to charge but cannot be paid."""


# An EVM address is 0x plus 20 hex bytes. Non-EVM chains (Solana, and others
# x402 supports) use different formats entirely, so the shape check applies
# only where it is meaningful.
_EVM_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_CAIP2 = re.compile(r"^[a-z0-9-]{3,8}:[a-zA-Z0-9_-]{1,32}$")

# Only to make the error message actionable; not an exhaustive list.
_ALIAS_TO_CAIP2 = {
    "base": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "avalanche": "eip155:43114",
    "avalanche-fuji": "eip155:43113",
    "polygon": "eip155:137",
    "polygon-amoy": "eip155:80002",
}
_NON_EVM_PREFIXES = ("solana", "sui", "aptos", "stellar", "algorand", "near", "tron")

# Whether a quoted price is real money. Deliberately two closed lists and an
# "unknown" answer rather than one list and an assumption: guessing "mainnet"
# for an unrecognized id would tell an operator their testnet notary is
# earning, and guessing "testnet" would tell a paying agent that real money is
# play money. Neither error is safe, so an unlisted network says so.
_KNOWN_TESTNETS = frozenset({
    "eip155:84532",     # base sepolia
    "eip155:11155111",  # ethereum sepolia
    "eip155:11155420",  # optimism sepolia
    "eip155:421614",    # arbitrum sepolia
    "eip155:43113",     # avalanche fuji
    "eip155:80002",     # polygon amoy
})
_KNOWN_MAINNETS = frozenset({
    "eip155:1",      # ethereum
    "eip155:8453",   # base
    "eip155:10",     # optimism
    "eip155:42161",  # arbitrum
    "eip155:137",    # polygon
    "eip155:43114",  # avalanche
})


def network_kind(network: str) -> str:
    """Classify a CAIP-2 network id: testnet, mainnet, or unknown."""
    key = network.lower()
    if key in _KNOWN_TESTNETS:
        return "testnet"
    if key in _KNOWN_MAINNETS:
        return "mainnet"
    return "unknown"


def _looks_evm(network: str) -> bool:
    return network.lower().startswith("eip155:") or not network.lower().startswith(
        _NON_EVM_PREFIXES
    )


def check_network(network: str) -> None:
    """Refuse a network name a paying client will not match.

    The server builds payment requirements from whatever string it is given,
    and an alias like "base-sepolia" produces a perfectly well-formed 402. The
    official client then normalizes to CAIP-2, finds no match, and refuses to
    pay with "no payment requirements match registered schemes". The notary
    looks healthy and nobody can buy anything.

    Found by pointing a real x402 client at it. Nothing in the server-side SDK
    complains, so the check has to live here.
    """
    if _CAIP2.match(network):
        return
    suggestion = _ALIAS_TO_CAIP2.get(network.lower())
    hint = f" Use {suggestion!r}." if suggestion else (
        " Use the CAIP-2 form, e.g. 'eip155:8453' for Base mainnet."
    )
    raise PaymentConfigError(
        f"LETHE_NOTARY_NETWORK={network!r} is not a CAIP-2 network id, so the "
        f"payment requirements this notary quotes will not match what a paying "
        f"client registers, and every payment will be refused before it is "
        f"attempted.{hint}"
    )


def check_pay_to(pay_to: str, network: str) -> None:
    """Reject an address that cannot possibly receive money.

    Found the hard way: LETHE_NOTARY_PAY_TO="<PAY_TO address>" — the
    placeholder from the setup instructions, left in verbatim — started the
    server, passed the facilitator preflight, and quoted payments to a
    destination that does not exist. Nothing complained until a customer had
    already signed. A misconfigured payee is worse than no payee, because it
    fails silently and it fails after taking someone's money.

    Shape only: this cannot tell whether the operator owns the address, and it
    does not try to. It catches placeholders, truncation and typos.
    """
    if not _looks_evm(network):
        return
    if not _EVM_ADDRESS.match(pay_to):
        raise PaymentConfigError(
            f"LETHE_NOTARY_PAY_TO={pay_to!r} is not a valid address for network "
            f"{network!r}: expected 0x followed by 40 hex characters. Payments "
            f"quoted to this destination could never be collected."
        )
    try:
        from eth_utils import is_checksum_address, is_checksum_formatted_address
    except ImportError:
        return  # eth_utils ships with x402[evm]; the shape check stands alone.
    # A mixed-case address carries an EIP-55 checksum, so a transposed
    # character is detectable. An all-lower or all-upper address carries no
    # checksum and cannot be checked this way.
    if is_checksum_formatted_address(pay_to) and not is_checksum_address(pay_to):
        raise PaymentConfigError(
            f"LETHE_NOTARY_PAY_TO={pay_to!r} fails its EIP-55 checksum, which "
            f"means a character is wrong. Copy the address again."
        )


@dataclass(frozen=True)
class PaymentConfig:
    """Where the money goes, and how much.

    `free_mode` exists for development and self-hosting. It is never the
    default and must be asked for explicitly, because a paid service that
    silently falls back to free on a missing environment variable is a service
    that gives itself away on its first misconfigured deploy.
    """

    pay_to: str | None
    price: str
    network: str
    facilitator_url: str
    free_mode: bool = False

    @classmethod
    def from_env(cls, environ=None) -> "PaymentConfig":
        env = os.environ if environ is None else environ
        free = env.get("LETHE_NOTARY_FREE", "").lower() in ("1", "true", "yes")
        pay_to = env.get("LETHE_NOTARY_PAY_TO") or None
        config = cls(
            pay_to=pay_to,
            price=env.get("LETHE_NOTARY_PRICE", "$0.01"),
            # CAIP-2, and a testnet. Two separate reasons:
            #
            # CAIP-2 ("eip155:84532") rather than the alias ("base-sepolia"):
            # the server will happily build requirements from an alias, but the
            # official x402 client normalizes to CAIP-2 and then reports "no
            # payment requirements match registered schemes" — so an
            # alias-configured notary quotes prices nobody can pay. Found by
            # running a real client against it.
            #
            # A testnet, because the default public facilitator at x402.org
            # advertises testnet kinds only; defaulting to mainnet would
            # produce a notary that starts happily and fails every payment.
            network=env.get("LETHE_NOTARY_NETWORK", "eip155:84532"),
            facilitator_url=env.get(
                "LETHE_NOTARY_FACILITATOR", "https://x402.org/facilitator"
            ),
            free_mode=free,
        )
        config.check()
        return config

    def check(self) -> None:
        if self.free_mode:
            return
        if not self.pay_to:
            raise PaymentConfigError(
                "LETHE_NOTARY_PAY_TO is not set, so payments cannot be received. "
                "Set it to the address that should be paid, or set "
                "LETHE_NOTARY_FREE=1 to run the notary without charging "
                "(deliberately, not by accident)."
            )
        check_network(self.network)
        check_pay_to(self.pay_to, self.network)
        if not self.facilitator_url.startswith("https://"):
            # The facilitator is told what was paid and settles it. Over plain
            # HTTP that is an interceptable claim about money.
            raise PaymentConfigError(
                f"facilitator URL must be https, got {self.facilitator_url!r}"
            )


class PaymentGate:
    """Wraps the x402 resource server; injectable so tests run without a chain.

    Settlement is deliberately separate from verification: the handler runs
    between them, so a request that turns out to need no work (a certificate
    this notary has already witnessed) can be answered without taking money.
    """

    def __init__(self, config: PaymentConfig,
                 resource_server: Any | None = None) -> None:
        self.config = config
        self._server = resource_server

    @property
    def enabled(self) -> bool:
        return not self.config.free_mode

    def resource_config(self) -> Any:
        """One priced option: the exact scheme, on the configured network."""
        from x402 import ResourceConfig

        # PaymentConfig.check() refuses to start without a payee, so this is
        # unreachable in a served notary — but `pay_to` is optional for free
        # mode, and quoting a price to `None` is the one failure that takes a
        # customer's money and sends it nowhere. Raise rather than let the type
        # be assumed away.
        pay_to = self.config.pay_to
        if pay_to is None:
            raise PaymentConfigError("no payee is configured; nothing can be charged")
        return ResourceConfig(
            scheme="exact",
            pay_to=pay_to,
            price=self.config.price,
            network=self.config.network,
        )

    def server(self) -> Any:
        """Build the x402 resource server on first use.

        Constructed lazily, and cached, so that a notary running in free mode
        never reaches for a facilitator at all — and so the tests can inject a
        stub instead of a chain.
        """
        if self._server is None:
            from x402 import x402ResourceServerSync
            from x402.http import FacilitatorConfig, HTTPFacilitatorClientSync
            from x402.mechanisms.evm.exact.register import register_exact_evm_server

            server = x402ResourceServerSync(
                HTTPFacilitatorClientSync(
                    FacilitatorConfig(url=self.config.facilitator_url)
                )
            )
            # Without a scheme registered for the network, building payment
            # requirements raises SchemeNotFoundError at the first paid
            # request — in production, not at startup. Register before
            # initialize so a bad network fails here instead.
            register_exact_evm_server(server, networks=self.config.network)
            server.initialize()
            self._server = server
        return self._server

    def preflight(self) -> None:
        """Prove the notary can actually charge, before it starts serving.

        `initialize()` asks the facilitator which (scheme, network) kinds it
        supports; a network the facilitator does not settle raises only when
        the FIRST paid request tries to build requirements. Discovered the hard
        way: the public x402.org facilitator advertises testnet kinds only, so
        a notary configured for "base" mainnet against it starts cleanly and
        then fails every payment. Fail at boot instead.
        """
        if self.config.free_mode:
            return
        try:
            self.server().build_payment_requirements(self.resource_config())
        except Exception as exc:
            raise PaymentConfigError(
                f"facilitator {self.config.facilitator_url} cannot settle scheme "
                f"'exact' on network {self.config.network!r} ({exc}). "
                f"Check {self.config.facilitator_url.rstrip('/')}/supported for the "
                f"kinds it does settle, or point LETHE_NOTARY_FACILITATOR at one "
                f"that covers your network."
            ) from None

    # -- the protocol ----------------------------------------------------

    def charge(self, request: Request) -> JSONResponse | dict[str, object]:
        """Verify and settle a payment for this request.

        Returns EITHER the response to send back — a 402, always — OR the
        settlement record: transaction hash, network, payer, which the caller
        echoes so the payer has an on-chain reference and the operator can
        reconcile. Two return types rather than a (paid, detail) pair, because
        the pair let `detail` be typed `object`, and an `object` in the return
        position means a type checker cannot see inside this function's callers
        at all — which is how three payment-path bugs reached a real chain.
        The shape is the protocol's: no
        PAYMENT-SIGNATURE means answer 402 with the requirements encoded in
        PAYMENT-REQUIRED, and the client pays and retries. A present signature
        is decoded, matched against those requirements, verified with the
        facilitator, and only then settled.

        This lives on the gate rather than in the route so that a test can
        replace the whole payment mechanism with one object, and so the route
        reads as "charge, then do the work".
        """
        from x402 import match_payload_to_requirements
        from x402.http import (
            PAYMENT_REQUIRED_HEADER,
            PAYMENT_SIGNATURE_HEADER,
            decode_payment_signature_header,
            encode_payment_required_header,
        )

        server = self.server()
        requirements = server.build_payment_requirements(self.resource_config())
        header = request.headers.get(PAYMENT_SIGNATURE_HEADER)

        if not header:
            required = server.create_payment_required_response(requirements)
            return JSONResponse(
                {"ok": False, "error": {
                    "code": "PAYMENT_REQUIRED",
                    "message": "notarization is charged per certificate; pay and retry",
                    "retriable": True}},
                status_code=402,
                headers={PAYMENT_REQUIRED_HEADER: encode_payment_required_header(required)},
            )

        try:
            # decode_payment_signature_header already returns a PaymentPayload —
            # do not parse it again. And match_payload_to_requirements is a
            # THREE-argument predicate returning bool, not a lookup returning
            # the matching requirement: it takes the protocol version, and both
            # sides as dicts under their wire names. Getting either wrong is
            # invisible until a real payment arrives, because a stub cannot
            # disagree with itself — which is exactly how both survived here.
            payload = decode_payment_signature_header(header)
            version = getattr(payload, "x402_version", 2)
            payload_wire = payload.model_dump(by_alias=True, mode="json")
            matched = next(
                (
                    req for req in requirements
                    if match_payload_to_requirements(
                        version, payload_wire, req.model_dump(by_alias=True, mode="json")
                    )
                ),
                None,
            )
        except Exception as exc:
            # A malformed payment is the caller's to fix. It must not reach the
            # facilitator, and must not surface as a 500.
            return _payment_error(f"payment could not be read ({exc})")
        if matched is None:
            return _payment_error(
                "payment does not match this resource's requirements")

        try:
            verified = server.verify_payment(payload, matched)
        except Exception as exc:
            # Verification moves no money, so a facilitator that is down or
            # slow costs the caller nothing but a retry. Never a 500: this is
            # an upstream outage, not a fault in the request.
            return _payment_error(
                f"could not reach the facilitator to verify the payment ({exc})")
        if not getattr(verified, "is_valid", False):
            return _payment_error(
                getattr(verified, "invalid_reason", None) or "payment did not verify")

        try:
            settled = server.settle_payment(payload, matched)
        except Exception as exc:
            # SETTLEMENT STATUS IS NOW UNKNOWN. The facilitator may have moved
            # the money and lost the response. Refusing here would repeat the
            # pay-and-get-nothing failure through a different door, and worse:
            # the caller would retry with a FRESH authorization and could be
            # charged twice.
            #
            # So treat it as paid. The asymmetry decides it — issuing a receipt
            # that was not paid for costs the operator one receipt; refusing one
            # that was paid for costs the customer their money and their
            # evidence. Recording it also makes a retry free, because
            # idempotency keys on the certificate hash, which closes the
            # double-charge.
            #
            # The operator has to reconcile this by hand, so say so loudly.
            logger.exception(
                "SETTLEMENT STATUS UNKNOWN: the facilitator call raised after the "
                "payment was verified. The money may or may not have moved. "
                "Reconcile against the chain."
            )
            return {"settlement_confirmed": False, "error": str(exc),
                    "transaction": None, "network": None, "payer": None}
        # The settle response is the only thing that says money actually moved.
        # Discarding it -- which this code did until a real payment went
        # through and the 200 could not be distinguished from a 200 over a
        # failed settlement -- means handing out a signed receipt for a payment
        # that never landed. That is the mirror of charging for nothing, and it
        # is the operator who eats it.
        if not getattr(settled, "success", False):
            reason = (getattr(settled, "error_reason", None)
                      or getattr(settled, "error_message", None)
                      or "settlement did not succeed")
            return _payment_error(f"payment did not settle ({reason})")
        return {
            "settlement_confirmed": True,
            # Handed back so the payer has an on-chain reference for what they
            # bought, and the operator can reconcile without trusting this
            # service's own word for it.
            "transaction": getattr(settled, "transaction", None),
            "network": getattr(settled, "network", None),
            "payer": getattr(settled, "payer", None),
        }


def _payment_error(message: str) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": {"code": "PAYMENT_INVALID", "message": message,
                                "retriable": True}},
        status_code=402,
    )

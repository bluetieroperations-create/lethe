"""Authenticated facilitator requests, so the notary can settle on mainnet.

Every keyless facilitator this repo probed advertises testnet only. The ones
that settle mainnet want a credential, and Coinbase CDP — the one we document —
wants an `EdDSA` Bearer JWT minted per call and bound to the exact method, host
and path being requested, with a short TTL. So mainnet was never a URL swap: it
needed code. This is that code.

WHY THE JWS IS HAND-ROLLED. Producing a JWS is base64url of two JSON objects, a
signature over the two joined by a dot, and nothing else. `cryptography` is
already a hard dependency (the notary signs receipts with it), so doing it here
costs zero new supply chain, and a JWT library would have been a runtime
dependency this package does not otherwise need — the same mistake this
package already made once by relying on an undeclared transitive `httpx`.

The usual reason to refuse to hand-roll JWT is that *verifiers* are where the
vulnerabilities live: `alg: none`, algorithm confusion, key-type confusion,
unverified `kid` lookups. Every one of those is a bug in code that reads a
token. This module only ever writes one, always with the same algorithm, and
never parses or trusts a token from anyone. A test cross-checks its output
against PyJWT's reference implementation.

WHAT THIS DOES NOT DO. It cannot tell you the credential is correct, or that it
belongs to an account that can settle. It mints a token CDP *should* accept. If
it is wrong, `/supported` answers 401 and the preflight refuses to start — at
boot, before a customer. That is the whole of the guarantee.

ONE BOUNDED EXPOSURE, measured rather than assumed. A facilitator that reflects
the request headers into its response body puts one of our *tokens* into the
error the SDK raises, which the notary prints at boot. That is not an
escalation: the token is a signature, never the key; it is bound to a single
method, host and path; it dies in 120 seconds; and the only party who can see
it this way is the facilitator, who was just handed it anyway. The secret
itself does not appear in any error, log or banner — probed against a
facilitator that returns 500, one that returns garbage, and one that echoes
everything it receives.
"""

import base64
import json
import os
import secrets
import time
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_TOKEN_TTL_SECONDS = 120


class CdpAuthError(Exception):
    """The CDP credential is unusable. Never carries the secret itself."""


def _b64url(raw: bytes) -> str:
    """base64url without padding, as JWS requires."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def load_ed25519_key(secret: str) -> Any:
    """Parse a CDP API secret into a signing key.

    CDP issues the Ed25519 secret as base64 of 64 bytes: the 32-byte seed
    followed by the 32-byte public key. A bare 32-byte seed is accepted too,
    because that is what someone who has already stripped the public half will
    paste.

    Every error here is deliberately value-free. This function is the one place
    holding the credential, it is called during startup where output gets
    copied into issues and chat, and a secret in an exception message ends up
    in a traceback, a log aggregator and a screenshot.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    try:
        raw = base64.b64decode(secret.strip(), validate=True)
    except Exception:
        raise CdpAuthError(
            "LETHE_NOTARY_CDP_KEY_SECRET is not valid base64. Paste the Ed25519 "
            "secret exactly as CDP issued it. (Its value is not echoed here.)"
        ) from None
    if len(raw) == 64:
        raw = raw[:32]
    elif len(raw) != 32:
        raise CdpAuthError(
            f"LETHE_NOTARY_CDP_KEY_SECRET decodes to {len(raw)} bytes; an Ed25519 "
            f"secret is 64 (seed plus public key) or 32 (seed alone). A truncated "
            f"paste is the usual cause. (Its value is not echoed here.)"
        )
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def mint_jwt(key_id: str, signing_key: Any, method: str, url: str,
             *, now: int | None = None, nonce: str | None = None,
             ttl: int = _TOKEN_TTL_SECONDS) -> str:
    """Mint one Bearer token authorizing exactly `method url`.

    The `uris` claim is what makes the token narrow: a token minted for
    `POST .../settle` is not a token for anything else, so one captured in a
    log cannot be replayed against a different endpoint. It is built from the
    URL actually being requested rather than a hardcoded CDP path, so this
    works for any facilitator speaking CDP's auth and stays correct if the
    endpoint layout changes.

    `now` and `nonce` are injectable so a test can pin the output; nothing
    calls them with arguments in production.
    """
    parts = urllib.parse.urlsplit(url)
    # Everything after the last "@" is host[:port], taken verbatim — which is
    # what CDP's own client signs (it passes `urlparse(...).netloc`). Three
    # things ride on taking it verbatim rather than using `.hostname`:
    # `.hostname` drops a non-default port, lowercases the host, and returns an
    # IPv6 address with its brackets stripped, which is not a host at all. Any
    # of those makes a token the facilitator computes differently and rejects,
    # with a 401 that says nothing about why. (The bracket case is the same one
    # `lethe.anchor` hit, and `check_public_url` avoids the same way.)
    # Userinfo is dropped either way, so a credential in the URL cannot ride
    # along into a token.
    host = parts.netloc.rpartition("@")[2]
    if not host:
        raise CdpAuthError(f"cannot mint a CDP token for {url!r}: it names no host")
    uri = f"{method.upper()} {host}{parts.path}"

    issued = int(time.time()) if now is None else now
    header = {
        "alg": "EdDSA",
        "kid": key_id,
        "typ": "JWT",
        # CDP's SDK sends a per-token nonce. Replicated rather than reasoned
        # about: matching the reference implementation is the point.
        "nonce": secrets.token_hex(16) if nonce is None else nonce,
    }
    claims: dict[str, Any] = {
        "sub": key_id,
        "iss": "cdp",
        # Present and null, which is what CDP's SDK emits when no audience is
        # configured. Left as-is rather than tidied away: the reference
        # implementation is the specification here.
        "aud": None,
        "nbf": issued,
        "exp": issued + ttl,
        "uris": [uri],
    }

    signing_input = ".".join((
        _b64url(json.dumps(header, separators=(",", ":")).encode()),
        _b64url(json.dumps(claims, separators=(",", ":")).encode()),
    )).encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64url(signing_key.sign(signing_input))}"


@dataclass(frozen=True)
class CdpCredentials:
    """A CDP API key. Deliberately not printable.

    `__repr__` is overridden because a dataclass prints its fields, and this
    one ends up inside `PaymentConfig`, which is echoed in error messages and
    debugger output.
    """

    key_id: str
    secret: str

    def __repr__(self) -> str:
        return f"CdpCredentials(key_id={self.key_id!r}, secret=<redacted>)"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "CdpCredentials | None":
        """Both variables or neither.

        Half a credential pair is the failure this package already fixed once
        for `FREE` and `PAY_TO`: the operator believes a cutover happened, the
        code quietly falls back to unauthenticated, and the first sign of
        trouble is a 401 — or worse, a keyless facilitator that works and
        silently keeps them on testnet.
        """
        env = os.environ if environ is None else environ
        key_id = (env.get("LETHE_NOTARY_CDP_KEY_ID") or "").strip()
        secret = (env.get("LETHE_NOTARY_CDP_KEY_SECRET") or "").strip()
        if not key_id and not secret:
            return None
        if not key_id or not secret:
            missing, present = (
                ("LETHE_NOTARY_CDP_KEY_ID", "LETHE_NOTARY_CDP_KEY_SECRET")
                if not key_id else
                ("LETHE_NOTARY_CDP_KEY_SECRET", "LETHE_NOTARY_CDP_KEY_ID")
            )
            raise CdpAuthError(
                f"{present} is set but {missing} is not. A CDP credential is "
                f"both halves; with one the notary sends no credential at all "
                f"and falls back to an unauthenticated request. Set both, or "
                f"unset both."
            )
        return cls(key_id=key_id, secret=secret)


class CdpAuthProvider:
    """Supplies per-endpoint Bearer tokens to the x402 facilitator client.

    Implements x402's `AuthProvider` protocol. That protocol hands back headers
    for all four endpoints in one call and does not say which one is about to
    be used, so all four are minted each time. The SDK calls this fresh on
    every facilitator request — verified by reading it, not assumed — so tokens
    cannot go stale inside the 120-second TTL, and the cost of the three
    unused ones is three Ed25519 signatures, which is native code and
    measured in microseconds.

    The key is parsed once, at construction. That is deliberate: a bad
    credential raises while the notary is starting, not on the first request
    that tries to take money.
    """

    def __init__(self, credentials: CdpCredentials, facilitator_url: str) -> None:
        self._key_id = credentials.key_id
        self._signing_key = load_ed25519_key(credentials.secret)
        self._base = facilitator_url.rstrip("/")

    def _bearer(self, method: str, suffix: str) -> dict[str, str]:
        token = mint_jwt(self._key_id, self._signing_key, method,
                         f"{self._base}{suffix}")
        return {"Authorization": f"Bearer {token}"}

    def get_auth_headers(self) -> Any:
        from x402.http import AuthHeaders

        # Methods and paths mirror how the x402 client actually calls the
        # facilitator: GET /supported, POST /verify, POST /settle. A token
        # minted for the wrong method or path is rejected, so these are not
        # cosmetic.
        return AuthHeaders(
            verify=self._bearer("POST", "/verify"),
            settle=self._bearer("POST", "/settle"),
            supported=self._bearer("GET", "/supported"),
            bazaar=self._bearer("GET", "/discovery/resources"),
        )

"""The notary HTTP service.

    POST /notarize            paid    verify a certificate, countersign, record
    GET  /challenge           free    a nonce to prove key control with
    POST /witness             free    every head witnessed for your key
    GET  /.well-known/notary  free    the notary's public key and claim text
    GET  /health              free

NO ACCOUNTS. Callers are agents. Instead of signup and API keys, two proofs
are used, both of them signatures: x402 for payment, and a signed challenge for
reading your own witness log. An operator who can sign with the key their
certificates name is, by construction, the party entitled to that log.
"""

import asyncio
import json
import logging
import secrets
import time
from datetime import UTC, datetime
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lethe.signing import Signer, key_id_for, verify_signature

from .payments import PaymentConfig, PaymentGate, network_kind
from .ratelimit import TokenBucket, client_key
from .receipt import CLAIM, NOTARY_SCHEMA, NotarizationRefused, build_receipt
from .store import WitnessLog

# A challenge is a one-shot proof of key control. Short-lived and single-use:
# a replayable challenge is not a proof, it is a bearer token with extra steps.
CHALLENGE_TTL_SECONDS = 120

# DOMAIN SEPARATION. The operator proves key control with the SAME Ed25519 key
# that signs their deletion certificates, and the nonce is chosen by the
# server. Signing a raw server-supplied string with that key is a signing
# oracle: a malicious notary (or anyone who can tamper with the /challenge
# response) can serve a canonical certificate payload AS the nonce, and the
# operator's compliant client will sign it. The attacker then wraps that
# signature in an envelope and holds a certificate that verifies against the
# operator's published key, attesting to deletions that never happened.
# Demonstrated end to end before this prefix existed.
#
# A certificate payload is canonical JSON and always begins with "{", so
# prefixing the signed bytes makes the two message spaces structurally
# disjoint: no challenge can ever be a certificate payload. The notary's own
# key id is included so a signature harvested by one notary is not replayable
# at another.
CHALLENGE_DOMAIN = "lethe-notary/challenge/v1"


def challenge_message(notary_key_id: str, nonce: str) -> bytes:
    """The exact bytes a client must sign. Never sign the bare nonce."""
    return f"{CHALLENGE_DOMAIN}:{notary_key_id}:{nonce}".encode()


logger = logging.getLogger("lethe_notary")

MAX_CERTIFICATE_BYTES = 64 * 1024  # a real certificate is ~2.3 KB
MAX_WITNESS_REQUEST_BYTES = 8 * 1024
# Outstanding challenges are unauthenticated and free to request, so the store
# needs a ceiling as well as a TTL.
MAX_OUTSTANDING_CHALLENGES = 10_000

# Per-client ceilings. Notarizing is real work (verify + sign + write), so it
# is the tighter of the two; challenges are cheap but must not be usable to
# exhaust the challenge cap.
NOTARIZE_BURST, NOTARIZE_RATE = 20, 2.0        # 2/s, burst 20
CHALLENGE_BURST, CHALLENGE_RATE = 30, 5.0      # 5/s, burst 30


class ChallengeCapacityError(Exception):
    """Too many unconsumed challenges outstanding."""


def _error(code: str, message: str, status: int,
           retriable: bool = False) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": {"code": code, "message": message,
                                "retriable": retriable}},
        status_code=status,
    )


class Notary:
    def __init__(self, *, signer: Signer, log: WitnessLog, gate: PaymentGate,
                 previous_keys: tuple[str, ...] = (),
                 trust_proxy: bool = False) -> None:
        self.signer = signer
        self.previous_keys = previous_keys
        self.trust_proxy = trust_proxy
        self.notarize_limit = TokenBucket(NOTARIZE_BURST, NOTARIZE_RATE)
        self.challenge_limit = TokenBucket(CHALLENGE_BURST, CHALLENGE_RATE)
        self.log = log
        self.gate = gate
        self.key_id = key_id_for(signer.public_key_b64())
        self._challenges: dict[str, float] = {}
        # One lock per certificate in flight. Charging happens off the event
        # loop (see notarize), which introduces an await between "have we
        # witnessed this?" and "record it" — without this, two concurrent
        # presentations of the SAME certificate both miss the existing-receipt
        # check, both pay, and only one row survives the UNIQUE index. The key
        # is the payload hash, so different certificates still proceed
        # concurrently; only duplicates serialize.
        #
        # This is per-process. Running several notary workers against one
        # witness database reopens the race, so run a single process (or put
        # the idempotency arbitration in the database) before scaling out.
        self._inflight: dict[str, asyncio.Lock] = {}

    def lock_for(self, payload_hash: str) -> asyncio.Lock:
        return self._inflight.setdefault(payload_hash, asyncio.Lock())

    def release(self, payload_hash: str) -> None:
        lock = self._inflight.get(payload_hash)
        if lock is not None and not lock.locked():
            self._inflight.pop(payload_hash, None)

    # -- challenges ------------------------------------------------------
    def issue_challenge(self) -> dict[str, object]:
        self._reap()
        if len(self._challenges) >= MAX_OUTSTANDING_CHALLENGES:
            # Challenges are free and unauthenticated, so an unbounded store is
            # a memory-growth lever for anyone. Refusing is safe: the caller
            # retries, and a legitimate challenge is consumed seconds later.
            raise ChallengeCapacityError
        nonce = secrets.token_urlsafe(32)
        self._challenges[nonce] = time.monotonic() + CHALLENGE_TTL_SECONDS
        return {
            "nonce": nonce,
            "expires_in": CHALLENGE_TTL_SECONDS,
            # Told to the client explicitly so it never has to guess, and so a
            # client that signs the bare nonce is making a visible mistake
            # rather than following the obvious reading of the docs.
            "sign": challenge_message(self.key_id, nonce).decode(),
        }

    def _reap(self) -> None:
        now = time.monotonic()
        for nonce in [n for n, exp in self._challenges.items() if exp < now]:
            self._challenges.pop(nonce, None)

    def consume_challenge(self, nonce: str) -> bool:
        self._reap()
        # pop, not read: one challenge, one use.
        return self._challenges.pop(nonce, None) is not None


async def notarize(request: Request) -> JSONResponse:
    notary: Notary = request.app.state.notary
    gate = notary.gate

    if not notary.notarize_limit.allow(client_key(request)):
        return _error("RATE_LIMITED", "too many requests; slow down", 429,
                      retriable=True)

    # Checked BEFORE reading, when the client declares a length: awaiting the
    # body first would buffer the whole thing in memory and only then complain,
    # which turns the size limit into an amplifier rather than a guard.
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_CERTIFICATE_BYTES:
        return _error("CERTIFICATE_TOO_LARGE",
                      f"certificate exceeds {MAX_CERTIFICATE_BYTES} bytes", 413)
    raw = await request.body()
    if len(raw) > MAX_CERTIFICATE_BYTES:  # chunked, or a lying content-length
        return _error("CERTIFICATE_TOO_LARGE",
                      f"certificate exceeds {MAX_CERTIFICATE_BYTES} bytes", 413)
    try:
        cert = json.loads(raw)
    except json.JSONDecodeError:
        return _error("MALFORMED", "body is not valid JSON", 400)

    # Verify and countersign BEFORE settling. A certificate this notary has
    # already witnessed needs no new work and no new money: the caller gets the
    # original receipt back, free. Minting a second receipt with a later
    # timestamp would also mean two receipts disagreeing about when the
    # certificate was seen, which is the one thing it is for.
    try:
        receipt = build_receipt(cert, signer=notary.signer)
    except NotarizationRefused as refusal:
        return JSONResponse(
            {"ok": False, "error": {"code": "CERTIFICATE_INVALID",
                                    "message": str(refusal), "retriable": False},
             "reasons": refusal.reasons, "detail": refusal.detail},
            status_code=422,
        )

    payload_hash = cert["payload_hash"]
    settlement: dict[str, object] | None = None
    async with notary.lock_for(payload_hash):
        try:
            prior = notary.log.existing(payload_hash)
            if prior is not None:
                return JSONResponse({"ok": True, "receipt": prior,
                                     "already_witnessed": True,
                                     "witness_recorded": True, "charged": False})

            if gate.enabled:
                # Off the event loop: the facilitator call is synchronous
                # network I/O, and running it inline blocks every other
                # request for its whole round trip — including /witness, the
                # dispute query, and /health. Measured before this change:
                # four concurrent notarizations against a 0.3s facilitator
                # took 1.23s, i.e. fully serialized.
                charged = await run_in_threadpool(gate.charge, request)
                # A response instead of a settlement record means the gate
                # refused: no money moved, and its 402 is what the caller needs.
                if isinstance(charged, JSONResponse):
                    return charged
                settlement = charged

            try:
                stored, is_new = notary.log.record(receipt)
                witnessed = True
            except Exception:
                # Charged already. The signed receipt IS what the customer
                # bought — it is the authoritative artifact, and the witness
                # log is the notary's own convenience copy (see the README on
                # why the log is not chained). Failing the whole request here
                # would take their money and hand back nothing, which is the
                # one outcome that must never happen.
                #
                # So return the receipt, say plainly that the off-site copy did
                # not land, and make the operator's logs scream: this needs
                # reconciling, and until it is, this certificate's head is not
                # covered by the truncation argument.
                logger.exception(
                    "WITNESS LOG WRITE FAILED after payment: certificate %s was "
                    "countersigned and charged but not recorded. Reconcile from "
                    "the customer's receipt.", payload_hash,
                )
                body = {
                    "ok": True, "receipt": receipt, "already_witnessed": False,
                    "charged": bool(gate.enabled),
                    "witness_recorded": False,
                    "warning": "The receipt is valid and signed, but the notary "
                               "could not record it in its witness log. Keep this "
                               "receipt: it is the evidence. This certificate's "
                               "audit head is not covered by the notary's "
                               "truncation check until the operator reconciles.",
                }
                if settlement:
                    # They need the on-chain reference most in exactly this
                    # case: they paid, and the notary lost its own copy.
                    body["payment"] = settlement
                return JSONResponse(body, status_code=200)
        finally:
            notary.release(payload_hash)

    body = {"ok": True, "receipt": stored,
            "already_witnessed": not is_new,
            "witness_recorded": witnessed,
            "charged": bool(gate.enabled and is_new)}
    if settlement:
        body["payment"] = settlement
    return JSONResponse(body)


async def challenge(request: Request) -> JSONResponse:
    if not request.app.state.notary.challenge_limit.allow(client_key(request)):
        return _error("RATE_LIMITED", "too many requests; slow down", 429,
                      retriable=True)
    try:
        issued = request.app.state.notary.issue_challenge()
    except ChallengeCapacityError:
        return _error("BUSY", "too many outstanding challenges; retry shortly",
                      503, retriable=True)
    return JSONResponse({"ok": True, **issued})


async def witness(request: Request) -> JSONResponse:
    """Read back every head witnessed for a key. Free, and gated by signature.

    Free on purpose: this is the query an operator runs during a dispute or an
    audit. Charging for it — or worse, being unreachable — at the moment the
    evidence is needed would make the evidence worth nothing.
    """
    notary: Notary = request.app.state.notary
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_WITNESS_REQUEST_BYTES:
        return _error("MALFORMED", "request too large", 413)
    raw = await request.body()
    if len(raw) > MAX_WITNESS_REQUEST_BYTES:
        return _error("MALFORMED", "request too large", 413)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return _error("MALFORMED", "body is not valid JSON", 400)
    if not isinstance(body, dict):
        return _error("MALFORMED", "body must be an object", 400)

    # Bound one at a time rather than checked with a generator over the three:
    # `all(isinstance(v, str) for v in ...)` guards the values at runtime but
    # narrows nothing, so every use below stays `Any | None` and a type checker
    # cannot tell a validated string from a missing key.
    public_key = body.get("public_key")
    nonce = body.get("nonce")
    signature = body.get("signature")
    if not (isinstance(public_key, str) and isinstance(nonce, str)
            and isinstance(signature, str)):
        return _error("MALFORMED",
                      "public_key, nonce and signature are all required", 400)
    if not notary.consume_challenge(nonce):
        return _error("CHALLENGE_INVALID",
                      "nonce is unknown, expired, or already used", 401, retriable=True)
    # Only the domain-separated form is accepted. A client that signs the bare
    # nonce — the naive reading of "sign the nonce" — is refused rather than
    # quietly allowed, because accepting both would leave the oracle open.
    expected = challenge_message(notary.key_id, nonce)
    if not verify_signature(public_key, expected, signature):
        return _error("SIGNATURE_INVALID",
                      "signature does not prove control of that key; sign "
                      f"{CHALLENGE_DOMAIN}:<notary_key_id>:<nonce>, not the bare nonce",
                      401)

    after = body.get("after") or 0
    if not isinstance(after, int) or after < 0:
        return _error("MALFORMED", "after must be a non-negative integer", 400)

    heads, next_cursor = notary.log.heads_for(public_key, after=after)
    return JSONResponse({
        "ok": True,
        "key_id": key_id_for(public_key),
        "witnessed": heads,
        # Explicit, because a truncated list of witnessed heads reads exactly
        # like a shorter history — and the operator would conclude the notary
        # never saw entries it did see.
        "complete": next_cursor is None,
        "next_after": next_cursor,
        "note": "Your audit chain must still contain every head listed here. "
                "One missing means entries were dropped after the notary saw "
                "them. If complete is false, page with after=next_after before "
                "concluding anything.",
    })


async def well_known(request: Request) -> JSONResponse:
    notary: Notary = request.app.state.notary
    return JSONResponse({
        "schema": NOTARY_SCHEMA,
        "notary_key_id": notary.key_id,
        "public_key": notary.signer.public_key_b64(),
        # Every key this notary has ever signed with, current first. Receipts
        # name the key that signed them, and a receipt must stay verifiable
        # after a rotation — otherwise rotating the key silently invalidates
        # every piece of evidence already sold. Verifiers resolve
        # notary_key_id against this list (verify_receipt takes it as
        # trusted_keys, the same shape lethe uses for certificates).
        "keys": [
            {"key_id": key_id_for(pk), "public_key": pk}
            for pk in (notary.signer.public_key_b64(), *notary.previous_keys)
        ],
        "claim": CLAIM,
        "paid": notary.gate.enabled,
        "price": notary.gate.config.price if notary.gate.enabled else None,
        "network": notary.gate.config.network if notary.gate.enabled else None,
        # An agent deciding whether to pay should not have to keep its own
        # table of chain ids to find out whether the price is real money.
        "network_kind": (
            network_kind(notary.gate.config.network) if notary.gate.enabled else None
        ),
    })


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True, "witnessed": request.app.state.notary.log.count(),
                         "now": datetime.now(UTC).isoformat()})


def create_app(*, signer: Signer, log: WitnessLog,
               config: PaymentConfig | None = None,
               resource_server: Any | None = None,
               previous_keys: tuple[str, ...] = (),
               trust_proxy: bool = False) -> Starlette:
    config = config or PaymentConfig.from_env()
    app = Starlette(routes=[
        Route("/notarize", notarize, methods=["POST"]),
        Route("/challenge", challenge, methods=["GET"]),
        Route("/witness", witness, methods=["POST"]),
        Route("/.well-known/notary", well_known, methods=["GET"]),
        Route("/health", health, methods=["GET"]),
    ])
    app.state.notary = Notary(
        signer=signer, log=log,
        gate=PaymentGate(config, resource_server=resource_server),
        previous_keys=previous_keys, trust_proxy=trust_proxy,
    )
    return app

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

import json
import secrets
import time
from datetime import UTC, datetime

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from lethe.signing import key_id_for, verify_signature

from .payments import PaymentConfig, PaymentGate
from .receipt import CLAIM, NOTARY_SCHEMA, NotarizationRefused, build_receipt
from .store import WitnessLog

# A challenge is a one-shot proof of key control. Short-lived and single-use:
# a replayable challenge is not a proof, it is a bearer token with extra steps.
CHALLENGE_TTL_SECONDS = 120
MAX_CERTIFICATE_BYTES = 64 * 1024  # a real certificate is ~2.3 KB


def _error(code: str, message: str, status: int, retriable: bool = False):
    return JSONResponse(
        {"ok": False, "error": {"code": code, "message": message,
                                "retriable": retriable}},
        status_code=status,
    )


class Notary:
    def __init__(self, *, signer, log: WitnessLog, gate: PaymentGate):
        self.signer = signer
        self.log = log
        self.gate = gate
        self.key_id = key_id_for(signer.public_key_b64())
        self._challenges: dict[str, float] = {}

    # -- challenges ------------------------------------------------------
    def issue_challenge(self) -> dict:
        self._reap()
        nonce = secrets.token_urlsafe(32)
        self._challenges[nonce] = time.monotonic() + CHALLENGE_TTL_SECONDS
        return {"nonce": nonce, "expires_in": CHALLENGE_TTL_SECONDS}

    def _reap(self) -> None:
        now = time.monotonic()
        for nonce in [n for n, exp in self._challenges.items() if exp < now]:
            self._challenges.pop(nonce, None)

    def consume_challenge(self, nonce: str) -> bool:
        self._reap()
        # pop, not read: one challenge, one use.
        return self._challenges.pop(nonce, None) is not None


async def notarize(request):
    notary: Notary = request.app.state.notary
    gate = notary.gate

    raw = await request.body()
    if len(raw) > MAX_CERTIFICATE_BYTES:
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

    prior = notary.log.existing(cert["payload_hash"])
    if prior is not None:
        return JSONResponse({"ok": True, "receipt": prior, "already_witnessed": True,
                             "charged": False})

    if gate.enabled:
        paid, response = gate.charge(request)
        if not paid:
            return response

    stored, is_new = notary.log.record(receipt)
    return JSONResponse({"ok": True, "receipt": stored,
                         "already_witnessed": not is_new,
                         "charged": bool(gate.enabled and is_new)})


async def challenge(request):
    return JSONResponse({"ok": True, **request.app.state.notary.issue_challenge()})


async def witness(request):
    """Read back every head witnessed for a key. Free, and gated by signature.

    Free on purpose: this is the query an operator runs during a dispute or an
    audit. Charging for it — or worse, being unreachable — at the moment the
    evidence is needed would make the evidence worth nothing.
    """
    notary: Notary = request.app.state.notary
    try:
        body = json.loads(await request.body())
    except json.JSONDecodeError:
        return _error("MALFORMED", "body is not valid JSON", 400)

    public_key = body.get("public_key")
    nonce = body.get("nonce")
    signature = body.get("signature")
    if not all(isinstance(v, str) for v in (public_key, nonce, signature)):
        return _error("MALFORMED",
                      "public_key, nonce and signature are all required", 400)
    if not notary.consume_challenge(nonce):
        return _error("CHALLENGE_INVALID",
                      "nonce is unknown, expired, or already used", 401, retriable=True)
    if not verify_signature(public_key, nonce.encode(), signature):
        return _error("SIGNATURE_INVALID",
                      "signature does not prove control of that key", 401)

    heads = notary.log.heads_for(public_key)
    return JSONResponse({
        "ok": True,
        "key_id": key_id_for(public_key),
        "witnessed": heads,
        "note": "Your audit chain must still contain every head listed here. "
                "One missing means entries were dropped after the notary saw them.",
    })


async def well_known(request):
    notary: Notary = request.app.state.notary
    return JSONResponse({
        "schema": NOTARY_SCHEMA,
        "notary_key_id": notary.key_id,
        "public_key": notary.signer.public_key_b64(),
        "claim": CLAIM,
        "paid": notary.gate.enabled,
        "price": notary.gate.config.price if notary.gate.enabled else None,
        "network": notary.gate.config.network if notary.gate.enabled else None,
    })


async def health(request):
    return JSONResponse({"ok": True, "witnessed": request.app.state.notary.log.count(),
                         "now": datetime.now(UTC).isoformat()})


def create_app(*, signer, log: WitnessLog, config: PaymentConfig | None = None,
               resource_server=None) -> Starlette:
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
    )
    return app

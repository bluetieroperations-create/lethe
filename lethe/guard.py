"""Two-step destructive-action guard for machine callers.

forget_preview mints a single-use HMAC token bound to (subject, exact per-layer
counts, expiry). forget only executes with a token whose fingerprint still
matches — so the caller provably SAW the blast radius it is confirming, and a
hallucinated subject id or mid-flight data change cannot silently delete.
State is process-local by design (stdio server inside one operator's
perimeter); a restart voids outstanding tokens and the caller re-previews."""

import hashlib
import hmac
import json
import secrets
import time

DEFAULT_TTL_SECONDS = 600


class GuardError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def preview_fingerprint(subject_hash: str, layers: list[tuple[str, str, int]]) -> str:
    canon = json.dumps(
        {"subject_hash": subject_hash, "layers": sorted(layers)},
        separators=(",", ":"),
    )
    return hashlib.sha256(canon.encode()).hexdigest()


class ConfirmGuard:
    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        secret: bytes | None = None,
        clock=time.time,
    ):
        self.ttl_seconds = ttl_seconds
        self._secret = secret or secrets.token_bytes(32)
        self._clock = clock
        self._used: set[str] = set()

    def _mac(self, subject_hash: str, fingerprint: str, expiry: int, nonce: str) -> str:
        msg = f"{subject_hash}|{fingerprint}|{expiry}|{nonce}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def mint(self, subject_hash: str, layers: list[tuple[str, str, int]]) -> str:
        expiry = int(self._clock()) + self.ttl_seconds
        nonce = secrets.token_hex(16)
        fp = preview_fingerprint(subject_hash, layers)
        mac = self._mac(subject_hash, fp, expiry, nonce)
        return f"v1.{expiry}.{nonce}.{fp}.{mac}"

    def check_and_consume(
        self, subject_hash: str, layers: list[tuple[str, str, int]], token: str
    ) -> None:
        try:
            version, expiry_s, nonce, fp, mac = token.split(".")
            expiry = int(expiry_s)
        except ValueError:
            raise GuardError("TOKEN_INVALID", "malformed confirm token")
        if version != "v1":
            raise GuardError("TOKEN_INVALID", "unknown confirm-token version")
        if not hmac.compare_digest(mac, self._mac(subject_hash, fp, expiry, nonce)):
            raise GuardError(
                "TOKEN_INVALID",
                "token does not match this subject (or was minted by another server)",
            )
        if self._clock() > expiry:
            raise GuardError(
                "TOKEN_EXPIRED", "confirm token expired; call lethe_forget_preview again"
            )
        if nonce in self._used:
            raise GuardError(
                "TOKEN_REUSED",
                "confirm token already used; call lethe_forget_preview again",
            )
        if not hmac.compare_digest(fp, preview_fingerprint(subject_hash, layers)):
            raise GuardError(
                "STALE_PREVIEW",
                "data changed since the preview; call lethe_forget_preview again",
            )
        self._used.add(nonce)

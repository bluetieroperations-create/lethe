import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def key_id_for(public_key_b64: str) -> str:
    """Deterministic identifier for a signing key: an algorithm tag plus a
    truncated SHA-256 of the raw public key.

    Derived, never configured, so it can never disagree with the key that
    actually signed — a verifier recomputes it from the embedded key and
    rejects a mismatch. The algorithm tag keeps the identifier meaningful if
    Lethe ever signs with something other than Ed25519.
    """
    raw = base64.b64decode(public_key_b64)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:32]


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Signer":
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def private_bytes(self) -> bytes:
        return self._sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def public_key_b64(self) -> str:
        pub = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return base64.b64encode(pub).decode()

    def key_id(self) -> str:
        return key_id_for(self.public_key_b64())

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._sk.sign(data)).decode()


def verify_signature(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    try:
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except Exception:
        return False

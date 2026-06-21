import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._sk.sign(data)).decode()


def verify_signature(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    try:
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except Exception:
        return False

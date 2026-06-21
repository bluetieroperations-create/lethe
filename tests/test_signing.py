from lethe.signing import Signer, verify_signature


def test_sign_and_verify_roundtrip():
    signer = Signer.generate()
    sig = signer.sign(b"hello")
    assert verify_signature(signer.public_key_b64(), b"hello", sig) is True


def test_verify_fails_on_tampered_data():
    signer = Signer.generate()
    sig = signer.sign(b"hello")
    assert verify_signature(signer.public_key_b64(), b"goodbye", sig) is False


def test_key_persists_via_raw_bytes():
    signer = Signer.generate()
    raw = signer.private_bytes()
    restored = Signer.from_private_bytes(raw)
    assert restored.public_key_b64() == signer.public_key_b64()
    sig = restored.sign(b"data")
    assert verify_signature(signer.public_key_b64(), b"data", sig) is True

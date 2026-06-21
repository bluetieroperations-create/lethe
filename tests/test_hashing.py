from lethe.hashing import hash_subject


def test_deterministic_for_same_inputs():
    assert hash_subject("user-42", "salt") == hash_subject("user-42", "salt")


def test_differs_by_subject():
    assert hash_subject("user-42", "salt") != hash_subject("user-99", "salt")


def test_differs_by_salt():
    assert hash_subject("user-42", "salt-a") != hash_subject("user-42", "salt-b")


def test_is_hex_and_not_raw_pii():
    h = hash_subject("user-42", "salt")
    assert "user-42" not in h
    assert len(h) == 64  # sha256 hex
    int(h, 16)  # raises if not hex

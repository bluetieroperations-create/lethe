import pytest

from lethe.guard import ConfirmGuard, GuardError

LAYERS = [("pgvector", "docs", 3), ("pgvector", "chats", 1)]
SUBJ_A = "a" * 64
SUBJ_B = "b" * 64


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_happy_path_mint_then_consume():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint(SUBJ_A, LAYERS)
    g.check_and_consume(SUBJ_A, LAYERS, token)  # no raise


def test_wrong_subject_is_invalid():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint(SUBJ_A, LAYERS)
    with pytest.raises(GuardError) as e:
        g.check_and_consume(SUBJ_B, LAYERS, token)
    assert e.value.code == "TOKEN_INVALID"


def test_expired_token():
    clock = FakeClock(1000.0)
    g = ConfirmGuard(ttl_seconds=600, clock=clock)
    token = g.mint(SUBJ_A, LAYERS)
    clock.t = 1601.0
    with pytest.raises(GuardError) as e:
        g.check_and_consume(SUBJ_A, LAYERS, token)
    assert e.value.code == "TOKEN_EXPIRED"


def test_reused_token():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint(SUBJ_A, LAYERS)
    g.check_and_consume(SUBJ_A, LAYERS, token)
    with pytest.raises(GuardError) as e:
        g.check_and_consume(SUBJ_A, LAYERS, token)
    assert e.value.code == "TOKEN_REUSED"


def test_changed_layers_is_stale_preview():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint(SUBJ_A, LAYERS)
    grown = LAYERS + [("pgvector", "notes", 1)]
    with pytest.raises(GuardError) as e:
        g.check_and_consume(SUBJ_A, grown, token)
    assert e.value.code == "STALE_PREVIEW"


def test_malformed_token_is_invalid():
    g = ConfirmGuard(clock=FakeClock())
    with pytest.raises(GuardError) as e:
        g.check_and_consume(SUBJ_A, LAYERS, "garbage")
    assert e.value.code == "TOKEN_INVALID"


def test_token_from_another_server_is_invalid():
    g1 = ConfirmGuard(clock=FakeClock())
    g2 = ConfirmGuard(clock=FakeClock())  # different per-process secret
    token = g1.mint(SUBJ_A, LAYERS)
    with pytest.raises(GuardError) as e:
        g2.check_and_consume(SUBJ_A, LAYERS, token)
    assert e.value.code == "TOKEN_INVALID"


def test_expiry_tamper_is_invalid():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint(SUBJ_A, LAYERS)
    parts = token.split(".")
    parts[1] = str(int(parts[1]) + 9999)  # extend expiry without the secret
    with pytest.raises(GuardError) as e:
        g.check_and_consume(SUBJ_A, LAYERS, ".".join(parts))
    assert e.value.code == "TOKEN_INVALID"


def test_used_nonces_are_pruned_after_expiry():
    clock = FakeClock(1000.0)
    g = ConfirmGuard(ttl_seconds=600, clock=clock)
    token = g.mint(SUBJ_A, LAYERS)
    g.check_and_consume(SUBJ_A, LAYERS, token)
    assert len(g._used) == 1
    clock.t = 1700.0  # past expiry
    token2 = g.mint(SUBJ_A, LAYERS)
    g.check_and_consume(SUBJ_A, LAYERS, token2)
    assert len(g._used) == 1  # old nonce pruned, only the new one remains


def test_non_hex_subject_hash_is_rejected():
    g = ConfirmGuard(clock=FakeClock())
    with pytest.raises(ValueError):
        g.mint("alice@example.com", LAYERS)
    with pytest.raises(ValueError):
        g.check_and_consume("alice|evil", LAYERS, "v1.1.a.b.c")

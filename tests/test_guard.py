import pytest

from lethe.guard import ConfirmGuard, GuardError

LAYERS = [("pgvector", "docs", 3), ("pgvector", "chats", 1)]


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_happy_path_mint_then_consume():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint("subjA", LAYERS)
    g.check_and_consume("subjA", LAYERS, token)  # no raise


def test_wrong_subject_is_invalid():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint("subjA", LAYERS)
    with pytest.raises(GuardError) as e:
        g.check_and_consume("subjB", LAYERS, token)
    assert e.value.code == "TOKEN_INVALID"


def test_expired_token():
    clock = FakeClock(1000.0)
    g = ConfirmGuard(ttl_seconds=600, clock=clock)
    token = g.mint("subjA", LAYERS)
    clock.t = 1601.0
    with pytest.raises(GuardError) as e:
        g.check_and_consume("subjA", LAYERS, token)
    assert e.value.code == "TOKEN_EXPIRED"


def test_reused_token():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint("subjA", LAYERS)
    g.check_and_consume("subjA", LAYERS, token)
    with pytest.raises(GuardError) as e:
        g.check_and_consume("subjA", LAYERS, token)
    assert e.value.code == "TOKEN_REUSED"


def test_changed_layers_is_stale_preview():
    g = ConfirmGuard(clock=FakeClock())
    token = g.mint("subjA", LAYERS)
    grown = LAYERS + [("pgvector", "notes", 1)]
    with pytest.raises(GuardError) as e:
        g.check_and_consume("subjA", grown, token)
    assert e.value.code == "STALE_PREVIEW"


def test_malformed_token_is_invalid():
    g = ConfirmGuard(clock=FakeClock())
    with pytest.raises(GuardError) as e:
        g.check_and_consume("subjA", LAYERS, "garbage")
    assert e.value.code == "TOKEN_INVALID"


def test_token_from_another_server_is_invalid():
    g1 = ConfirmGuard(clock=FakeClock())
    g2 = ConfirmGuard(clock=FakeClock())  # different per-process secret
    token = g1.mint("subjA", LAYERS)
    with pytest.raises(GuardError) as e:
        g2.check_and_consume("subjA", LAYERS, token)
    assert e.value.code == "TOKEN_INVALID"

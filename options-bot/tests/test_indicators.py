import math

import pytest

from optbot.indicators import analyze, realized_vol, rsi, sma
from tests.fakes import trending_closes


def test_sma():
    assert sma([1, 2, 3, 4], 2) == 3.5
    with pytest.raises(ValueError):
        sma([1], 2)


def test_rsi_extremes():
    assert rsi(list(range(1, 30))) == 100.0
    assert rsi(list(range(30, 1, -1))) < 1


def test_realized_vol_of_constant_returns_is_zero():
    closes = [100 * 1.01**i for i in range(30)]
    assert realized_vol(closes) == pytest.approx(0, abs=1e-9)


def test_realized_vol_scale():
    closes = trending_closes(100, 0, n=40, wiggle=0.01)
    # alternating +/-1% moves -> ~1% daily stdev of log returns
    assert realized_vol(closes) == pytest.approx(0.01 * math.sqrt(252), rel=0.05)


def test_trend_detection():
    up = trending_closes(100, 0.004)
    assert analyze(up, up[-1], 0.3).trend == 1
    down = trending_closes(100, -0.004)
    assert analyze(down, down[-1], 0.3).trend == -1
    flat = trending_closes(100, 0)
    assert analyze(flat, flat[-1], 0.3).trend == 0

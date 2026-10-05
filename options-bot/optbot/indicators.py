"""Technical signals: trend, momentum and realized volatility from daily closes."""

from __future__ import annotations

import math
from dataclasses import dataclass


def sma(values: list[float], n: int) -> float:
    if len(values) < n:
        raise ValueError(f"need {n} values, have {len(values)}")
    return sum(values[-n:]) / n


def rsi(closes: list[float], n: int = 14) -> float:
    """Wilder's RSI."""
    if len(closes) < n + 1:
        raise ValueError(f"need {n + 1} closes, have {len(closes)}")
    deltas = [b - a for a, b in zip(closes, closes[1:])]
    gain = sum(max(d, 0) for d in deltas[:n]) / n
    loss = sum(max(-d, 0) for d in deltas[:n]) / n
    for d in deltas[n:]:
        gain = (gain * (n - 1) + max(d, 0)) / n
        loss = (loss * (n - 1) + max(-d, 0)) / n
    if loss == 0:
        return 100.0
    return 100 - 100 / (1 + gain / loss)


def realized_vol(closes: list[float], n: int = 20) -> float:
    """Annualized close-to-close volatility over the last n returns."""
    if len(closes) < n + 1:
        raise ValueError(f"need {n + 1} closes, have {len(closes)}")
    rets = [math.log(b / a) for a, b in zip(closes[-n - 1 :], closes[-n:])]
    mean = sum(rets) / n
    var = sum((r - mean) ** 2 for r in rets) / (n - 1)
    return math.sqrt(var) * math.sqrt(252)


@dataclass(frozen=True)
class Signals:
    price: float
    trend: int  # +1 up, -1 down, 0 neutral
    rsi: float
    hv20: float
    atm_iv: float | None

    @property
    def iv_hv_ratio(self) -> float | None:
        if self.atm_iv is None or self.hv20 <= 0:
            return None
        return self.atm_iv / self.hv20


def analyze(closes: list[float], price: float, atm_iv: float | None) -> Signals:
    s20, s50 = sma(closes, 20), sma(closes, 50)
    if price > s20 > s50:
        trend = 1
    elif price < s20 < s50:
        trend = -1
    else:
        trend = 0
    return Signals(price=price, trend=trend, rsi=rsi(closes), hv20=realized_vol(closes),
                   atm_iv=atm_iv)

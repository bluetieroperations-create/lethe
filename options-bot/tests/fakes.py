"""A deterministic in-memory market for tests: Black-Scholes chains, scripted prices."""

from __future__ import annotations

import math
from datetime import date, timedelta

from optbot.brokers.base import Broker
from optbot.models import OptionQuote


def _ncdf(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def bs(spot, strike, years, vol, kind):
    d1 = (math.log(spot / strike) + 0.5 * vol * vol * years) / (vol * math.sqrt(years))
    d2 = d1 - vol * math.sqrt(years)
    if kind == "call":
        return spot * _ncdf(d1) - strike * _ncdf(d2), _ncdf(d1)
    return strike * _ncdf(-d2) - spot * _ncdf(-d1), _ncdf(d1) - 1


def trending_closes(start: float, daily: float, n: int = 80, wiggle: float = 0.01):
    """Closes with drift `daily` and a fixed zig-zag so realized vol is non-zero."""
    out, p = [], start
    for i in range(n):
        p *= 1 + daily + (wiggle if i % 2 else -wiggle)
        out.append(p)
    return out


class FakeMarket(Broker):
    def __init__(self, today: date, spot: float, closes: list[float], iv: float,
                 equity: float = 10_000.0) -> None:
        self.today, self.spot, self.closes, self.iv = today, spot, closes, iv
        self._equity = equity
        self.open = True
        self.earnings: date | None = None
        self.orders: list[tuple] = []
        self.fill = True

    def is_market_open(self):
        return self.open

    def equity(self):
        return self._equity

    def buying_power(self):
        return self._equity

    def price(self, symbol):
        return self.spot

    def daily_closes(self, symbol):
        return self.closes

    def expirations(self, symbol):
        return [self.today + timedelta(days=d) for d in (7, 14, 21, 35, 63)]

    def next_earnings(self, symbol):
        return self.earnings

    def chain(self, symbol, expiration):
        years = max((expiration - self.today).days, 1) / 365
        quotes = []
        lo, hi = int(self.spot * 0.8), int(self.spot * 1.2)
        for strike in range(lo, hi + 1):
            for kind in ("call", "put"):
                px, delta = bs(self.spot, strike, years, self.iv, kind)
                px = max(px, 0.01)
                half = max(0.01, px * 0.03)
                quotes.append(OptionQuote(symbol, expiration, float(strike), kind,
                                          round(px - half, 2) if px > half else 0.0,
                                          round(px + half, 2), delta, self.iv, 1000))
        return quotes

    def submit_spread(self, symbol, legs, quantity, net_debit, opening):
        self.orders.append((symbol, legs, quantity, net_debit, opening))
        if not self.fill:
            return None
        from optbot.models import Fill

        return Fill(net_debit, quantity, f"o{len(self.orders)}")

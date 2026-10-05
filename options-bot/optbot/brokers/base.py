"""Broker interface. The engine only talks to this, so brokers are swappable."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import date

from ..models import Fill, Leg, OptionQuote


class Broker(ABC):
    @abstractmethod
    def is_market_open(self) -> bool: ...

    @abstractmethod
    def equity(self) -> float: ...

    @abstractmethod
    def buying_power(self) -> float: ...

    @abstractmethod
    def price(self, symbol: str) -> float: ...

    @abstractmethod
    def daily_closes(self, symbol: str) -> list[float]:
        """At least ~60 daily closes, oldest first."""

    @abstractmethod
    def expirations(self, symbol: str) -> list[date]: ...

    @abstractmethod
    def chain(self, symbol: str, expiration: date) -> list[OptionQuote]: ...

    def quotes_for(self, symbol: str, legs: tuple[Leg, ...] | list[Leg]) -> dict:
        """Quotes keyed by (expiration, strike, type) for every leg."""
        out: dict = {}
        for exp in {leg.expiration for leg in legs}:
            for q in self.chain(symbol, exp):
                out[q.key()] = q
        missing = [leg for leg in legs if leg.key() not in out]
        if missing:
            raise LookupError(f"{symbol}: no quote for {missing}")
        return out

    def next_earnings(self, symbol: str) -> date | None:
        return None

    @abstractmethod
    def submit_spread(self, symbol: str, legs: tuple[Leg, ...], quantity: int,
                      net_debit: float, opening: bool) -> Fill | None:
        """Limit order for the whole spread at `net_debit` per share (negative = credit).

        Returns the fill, or None if it did not fill (the order must be cancelled)."""

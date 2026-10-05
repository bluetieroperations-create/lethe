"""Plain data types shared by the strategy, risk, broker and engine layers.

Price convention: an order's price is a *net debit per share*, signed. Positive means we
pay, negative means we receive a credit. Multiply by 100 for dollars per contract.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime

CONTRACT_MULTIPLIER = 100


@dataclass(frozen=True)
class OptionQuote:
    symbol: str
    expiration: date
    strike: float
    type: str  # "call" | "put"
    bid: float
    ask: float
    delta: float | None = None
    iv: float | None = None
    open_interest: int = 0

    @property
    def mid(self) -> float:
        return (self.bid + self.ask) / 2

    @property
    def spread_pct(self) -> float:
        mid = self.mid
        return (self.ask - self.bid) / mid if mid > 0 else float("inf")

    def key(self) -> tuple[date, float, str]:
        return (self.expiration, self.strike, self.type)


@dataclass(frozen=True)
class Leg:
    expiration: date
    strike: float
    type: str  # "call" | "put"
    action: str  # "buy" | "sell"

    def key(self) -> tuple[date, float, str]:
        return (self.expiration, self.strike, self.type)

    def flipped(self) -> Leg:
        return replace(self, action="sell" if self.action == "buy" else "buy")

    def to_dict(self) -> dict:
        return {
            "expiration": self.expiration.isoformat(),
            "strike": self.strike,
            "type": self.type,
            "action": self.action,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Leg:
        return cls(date.fromisoformat(d["expiration"]), float(d["strike"]), d["type"], d["action"])


def spread_width(legs: tuple[Leg, ...] | list[Leg]) -> float:
    """Widest wing: the per-share max payoff range of a vertical or iron condor."""
    widths = []
    for t in ("call", "put"):
        strikes = [leg.strike for leg in legs if leg.type == t]
        if len(strikes) >= 2:
            widths.append(max(strikes) - min(strikes))
    return max(widths, default=0.0)


@dataclass(frozen=True)
class Proposal:
    symbol: str
    strategy: str
    legs: tuple[Leg, ...]
    price: float  # positive: credit received if is_credit, else debit paid (per share)
    is_credit: bool
    reason: str = ""

    @property
    def width(self) -> float:
        return spread_width(self.legs)

    @property
    def expiration(self) -> date:
        return min(leg.expiration for leg in self.legs)

    @property
    def max_loss_per_contract(self) -> float:
        per_share = self.width - self.price if self.is_credit else self.price
        return per_share * CONTRACT_MULTIPLIER

    @property
    def max_profit_per_contract(self) -> float:
        per_share = self.price if self.is_credit else self.width - self.price
        return per_share * CONTRACT_MULTIPLIER


@dataclass(frozen=True)
class Position:
    id: int
    symbol: str
    strategy: str
    legs: tuple[Leg, ...]
    quantity: int
    entry_price: float  # positive, same convention as Proposal.price
    is_credit: bool
    opened_at: datetime

    @property
    def width(self) -> float:
        return spread_width(self.legs)

    @property
    def expiration(self) -> date:
        return min(leg.expiration for leg in self.legs)

    @property
    def max_loss(self) -> float:
        per_share = self.width - self.entry_price if self.is_credit else self.entry_price
        return per_share * CONTRACT_MULTIPLIER * self.quantity

    def pnl_per_share(self, value: float) -> float:
        """value: what the position is worth now, per share, as `position_value` returns."""
        return self.entry_price + value if self.is_credit else value - self.entry_price


@dataclass(frozen=True)
class Fill:
    net_debit: float  # signed, per share
    quantity: int
    order_id: str = ""


def position_value(legs: tuple[Leg, ...] | list[Leg], quotes: dict) -> float:
    """Mark-to-mid value per share of holding `legs`: longs count +, shorts count -.

    A credit spread therefore has a negative value (it costs money to close)."""
    total = 0.0
    for leg in legs:
        q = quotes[leg.key()]
        total += q.mid if leg.action == "buy" else -q.mid
    return total


def order_prices(legs: tuple[Leg, ...] | list[Leg], quotes: dict) -> tuple[float, float]:
    """(mid, natural) net debit per share to execute `legs`. natural >= mid always."""
    mid = natural = 0.0
    for leg in legs:
        q = quotes[leg.key()]
        if leg.action == "buy":
            mid += q.mid
            natural += q.ask
        else:
            mid -= q.mid
            natural -= q.bid
    return mid, natural


def describe(legs: tuple[Leg, ...] | list[Leg]) -> str:
    exp = min(leg.expiration for leg in legs).isoformat()
    body = " / ".join(f"{leg.action} {leg.strike:g}{leg.type[0].upper()}" for leg in legs)
    return f"{exp} {body}"

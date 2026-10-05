"""Paper broker: real market data from another broker, simulated fills and cash.

Fills are deliberately a little pessimistic: a limit order only fills once it concedes
`paper_slippage` of the way from mid toward the natural price, mimicking real spreads.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from ..models import CONTRACT_MULTIPLIER, Fill, Leg, order_prices, position_value, spread_width
from .base import Broker


class PaperBroker(Broker):
    def __init__(self, data: Broker, starting_cash: float, slippage: float,
                 state_path: str | None = None) -> None:
        self.data = data
        self.slippage = slippage
        self.state_path = Path(state_path) if state_path else None
        self.cash = starting_cash
        self.positions: list[dict] = []  # {"symbol", "legs": [leg dicts], "quantity"}
        if self.state_path and self.state_path.exists():
            state = json.loads(self.state_path.read_text())
            self.cash, self.positions = state["cash"], state["positions"]

    def _save(self) -> None:
        if self.state_path:
            self.state_path.write_text(json.dumps({"cash": self.cash,
                                                   "positions": self.positions}, indent=2))

    # --- market data passes through -------------------------------------------
    def is_market_open(self) -> bool:
        return self.data.is_market_open()

    def price(self, symbol: str) -> float:
        return self.data.price(symbol)

    def daily_closes(self, symbol: str) -> list[float]:
        return self.data.daily_closes(symbol)

    def expirations(self, symbol: str) -> list[date]:
        return self.data.expirations(symbol)

    def chain(self, symbol: str, expiration: date):
        return self.data.chain(symbol, expiration)

    def next_earnings(self, symbol: str) -> date | None:
        return self.data.next_earnings(symbol)

    # --- simulated account -----------------------------------------------------
    def _legs(self, pos: dict) -> list[Leg]:
        return [Leg.from_dict(d) for d in pos["legs"]]

    def equity(self) -> float:
        value = 0.0
        for pos in self.positions:
            legs = self._legs(pos)
            value += position_value(legs, self.quotes_for(pos["symbol"], legs)) \
                * CONTRACT_MULTIPLIER * pos["quantity"]
        return self.cash + value

    def buying_power(self) -> float:
        held = 0.0
        for pos in self.positions:
            legs = self._legs(pos)
            if any(leg.action == "sell" for leg in legs):
                held += spread_width(legs) * CONTRACT_MULTIPLIER * pos["quantity"]
        return self.cash - held

    def submit_spread(self, symbol, legs, quantity, net_debit, opening) -> Fill | None:
        mid, natural = order_prices(legs, self.quotes_for(symbol, legs))
        if net_debit < mid + self.slippage * (natural - mid) - 1e-9:
            return None
        self.cash -= net_debit * CONTRACT_MULTIPLIER * quantity
        if opening:
            self.positions.append({"symbol": symbol, "quantity": quantity,
                                   "legs": [leg.to_dict() for leg in legs]})
        else:
            held = sorted(leg.flipped().key() for leg in legs)
            for pos in self.positions:
                if pos["symbol"] == symbol and sorted(
                        leg.key() for leg in self._legs(pos)) == held:
                    pos["quantity"] -= quantity
                    break
            else:
                raise LookupError(f"paper: closing a position we don't hold: {symbol} {legs}")
            self.positions = [p for p in self.positions if p["quantity"] > 0]
        self._save()
        return Fill(net_debit, quantity, "paper")

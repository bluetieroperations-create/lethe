"""Risk management: sizing, portfolio limits, loss circuit breakers and exit rules."""

from __future__ import annotations

import math
from datetime import date

from .config import Config
from .journal import Journal
from .models import Position, Proposal


class RiskManager:
    def __init__(self, cfg: Config, journal: Journal) -> None:
        self.cfg = cfg
        self.journal = journal

    # --- circuit breakers ----------------------------------------------------
    def update(self, equity: float, today: date) -> None:
        """Roll the day's starting equity, track the high-water mark, trip the kill switch."""
        j = self.journal
        if j.get("day") != today.isoformat():
            j.set("day", today.isoformat())
            j.set("day_start_equity", equity)
        hwm = max(float(j.get("high_water", equity)), equity)
        j.set("high_water", hwm)
        if equity <= hwm * (1 - self.cfg.max_drawdown_pct):
            j.set("halted", f"drawdown {1 - equity / hwm:.1%} from high-water {hwm:,.2f}")

    @property
    def halted(self) -> str | None:
        return self.journal.get("halted") or None

    def resume(self, equity: float) -> None:
        """Clear the kill switch and reset the high-water mark to current equity."""
        self.journal.set("halted", "")
        self.journal.set("high_water", equity)

    def entry_block_reason(self, equity: float, open_positions: list[Position]) -> str | None:
        if self.halted:
            return f"KILL SWITCH: {self.halted} (run `optbot resume` to re-enable)"
        start = float(self.journal.get("day_start_equity", equity))
        if equity <= start * (1 - self.cfg.daily_loss_limit_pct):
            return f"daily loss limit hit ({equity / start - 1:.1%} today)"
        if len(open_positions) >= self.cfg.max_positions:
            return f"max positions ({self.cfg.max_positions}) open"
        return None

    # --- sizing --------------------------------------------------------------
    def size(self, p: Proposal, equity: float, buying_power: float,
             open_positions: list[Position]) -> int:
        """Contracts to trade so that worst case stays inside every budget."""
        per_contract = p.max_loss_per_contract
        if per_contract <= 0:
            return 0
        used = sum(pos.max_loss for pos in open_positions)
        budget = min(
            equity * self.cfg.risk_per_trade_pct,
            equity * self.cfg.max_total_risk_pct - used,
            buying_power,
        )
        return max(0, math.floor(budget / per_contract))

    # --- exits ---------------------------------------------------------------
    def exit_reason(self, pos: Position, value: float, today: date) -> str | None:
        """value: current mark of the position per share (see models.position_value)."""
        c = self.cfg
        pnl = pos.pnl_per_share(value)
        dte = (pos.expiration - today).days
        if pos.is_credit:
            if pnl >= c.credit_take_profit * pos.entry_price:
                return "take_profit"
            max_loss = pos.width - pos.entry_price
            stop = min(c.credit_stop_loss * pos.entry_price, c.credit_stop_max_loss_frac * max_loss)
            if -pnl >= stop:
                return "stop_loss"
            if dte <= c.credit_exit_dte:
                return "time_exit"
        else:
            if pnl >= c.debit_take_profit * pos.entry_price:
                return "take_profit"
            if -pnl >= c.debit_stop_loss * pos.entry_price:
                return "stop_loss"
            if dte <= c.debit_exit_dte:
                return "time_exit"
        return None

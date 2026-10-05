"""Bot configuration. Defaults follow the "aggressive, medium safety" profile.

Every trade the bot opens has a defined maximum loss (verticals and iron condors only,
no naked options). The aggression comes from position size and delta choice, not from
taking on unlimited risk.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields
from pathlib import Path


@dataclass(frozen=True)
class Config:
    # --- general -------------------------------------------------------------
    mode: str = "paper"  # "paper" or "live"
    universe: tuple[str, ...] = (
        "SPY", "QQQ", "IWM", "AAPL", "MSFT", "NVDA", "AMD", "META", "AMZN", "GOOGL",
    )
    poll_seconds: int = 300
    db_path: str = "optbot.sqlite3"
    paper_state_path: str = "paper_state.json"
    paper_starting_cash: float = 10_000.0

    # --- entry selection -----------------------------------------------------
    target_dte: int = 35
    min_dte: int = 25
    max_dte: int = 50
    credit_short_delta: float = 0.30  # short strike delta for credit spreads/condors
    debit_long_delta: float = 0.55  # long strike delta for debit spreads
    debit_short_delta: float = 0.30  # short strike delta for debit spreads
    spread_width_pct: float = 0.02  # target wing width as a fraction of the stock price
    min_credit_to_width: float = 0.25  # credit must be >= 25% of the width
    max_debit_to_width: float = 0.50  # debit must be <= 50% of width (reward >= risk)
    iv_rich_ratio: float = 1.10  # ATM IV / 20-day realized vol at or above this: sell premium
    iv_cheap_ratio: float = 0.90  # at or below this: buy premium
    rsi_overbought: float = 75.0
    rsi_oversold: float = 25.0
    min_open_interest: int = 100
    max_leg_spread_pct: float = 0.25  # (ask - bid) / mid, per leg
    avoid_earnings: bool = True

    # --- risk ----------------------------------------------------------------
    risk_per_trade_pct: float = 0.04  # max loss of one trade, as a fraction of equity
    max_total_risk_pct: float = 0.35  # sum of max losses of all open trades
    max_positions: int = 8
    max_positions_per_symbol: int = 1
    reentry_cooldown_days: int = 1  # after closing a symbol, wait before trading it again
    daily_loss_limit_pct: float = 0.06  # no new entries for the rest of the day
    max_drawdown_pct: float = 0.20  # kill switch: halts entries until `optbot resume`

    # --- exits ---------------------------------------------------------------
    credit_take_profit: float = 0.50  # close at 50% of max profit
    credit_stop_loss: float = 2.0  # close when the loss reaches 2x the credit...
    credit_stop_max_loss_frac: float = 0.5  # ...or half the max loss, whichever is first
    credit_exit_dte: int = 21  # close before gamma risk ramps up
    debit_take_profit: float = 0.80  # close at +80% on the debit paid
    debit_stop_loss: float = 0.50  # close at -50% on the debit paid
    debit_exit_dte: int = 10

    # --- execution -----------------------------------------------------------
    entry_max_concession: float = 0.5  # how far from mid toward natural we will walk on entry
    ladder_steps: int = 3
    fill_timeout_seconds: int = 20  # per ladder step (live)
    paper_slippage: float = 0.25  # paper fills need this fraction of mid->natural concession

    def __post_init__(self) -> None:
        if self.mode not in ("paper", "live"):
            raise ValueError(f"mode must be 'paper' or 'live', not {self.mode!r}")
        if not 0 < self.risk_per_trade_pct <= 0.10:
            raise ValueError("risk_per_trade_pct must be in (0, 0.10]")
        if not self.risk_per_trade_pct <= self.max_total_risk_pct <= 1:
            raise ValueError("max_total_risk_pct must be between risk_per_trade_pct and 1")
        if not self.min_dte <= self.target_dte <= self.max_dte:
            raise ValueError("need min_dte <= target_dte <= max_dte")
        if not 0 < self.max_drawdown_pct < 1 or not 0 < self.daily_loss_limit_pct < 1:
            raise ValueError("loss limits must be fractions between 0 and 1")

    @classmethod
    def load(cls, path: str | Path | None) -> Config:
        if path is None:
            return cls()
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
        known = {f.name for f in fields(cls)}
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        if "universe" in raw:
            raw["universe"] = tuple(s.upper() for s in raw["universe"])
        return cls(**raw)

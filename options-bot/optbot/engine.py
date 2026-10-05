"""The trading loop: manage exits first, then look for new entries."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime

from .brokers.base import Broker
from .config import Config
from .indicators import analyze
from .journal import Journal
from .models import Fill, Leg, Position, Proposal, describe, order_prices, position_value
from .risk import RiskManager
from .strategies import atm_iv, choose_expiration, propose

log = logging.getLogger("optbot")


class Engine:
    def __init__(self, broker: Broker, cfg: Config, journal: Journal,
                 clock: Callable[[], datetime] = datetime.now) -> None:
        self.broker = broker
        self.cfg = cfg
        self.journal = journal
        self.risk = RiskManager(cfg, journal)
        self.clock = clock

    # --- execution -------------------------------------------------------------
    def _ladder(self, symbol: str, legs: tuple[Leg, ...], quantity: int, opening: bool,
                max_concession: float, accept: Callable[[float], bool] = lambda _: True,
                ) -> Fill | None:
        """Work a limit order from mid toward natural; stop at the first fill."""
        steps = max(self.cfg.ladder_steps, 1)
        for i in range(steps):
            frac = max_concession * (i / (steps - 1) if steps > 1 else 1.0)
            mid, natural = order_prices(legs, self.broker.quotes_for(symbol, legs))
            price = round(mid + frac * (natural - mid), 2)
            if not accept(price):
                log.info("%s: price %.2f no longer meets entry rules, giving up", symbol, price)
                return None
            fill = self.broker.submit_spread(symbol, legs, quantity, price, opening)
            if fill:
                return fill
        return None

    # --- exits -------------------------------------------------------------------
    def manage_exits(self, now: datetime) -> None:
        for pos in self.journal.open_positions():
            try:
                self._manage(pos, now)
            except Exception:
                log.exception("%s #%d: exit check failed", pos.symbol, pos.id)

    def _manage(self, pos: Position, now: datetime) -> None:
        value = position_value(pos.legs, self.broker.quotes_for(pos.symbol, pos.legs))
        reason = self.risk.exit_reason(pos, value, now.date())
        if reason is None:
            return
        # Losing or expiring positions must get out: walk all the way to natural.
        concession = 0.5 if reason == "take_profit" else 1.0
        close_legs = tuple(leg.flipped() for leg in pos.legs)
        fill = self._ladder(pos.symbol, close_legs, pos.quantity, False, concession)
        if fill is None:
            log.warning("%s #%d: %s exit did not fill, will retry", pos.symbol, pos.id, reason)
            return
        exit_value = -fill.net_debit  # what we received for the position
        pnl = self.journal.close_position(pos, exit_value, reason, now, fill.quantity)
        log.info("CLOSE %s #%d %s x%d (%s) pnl=%+.2f", pos.symbol, pos.id, pos.strategy,
                 fill.quantity, reason, pnl)

    # --- entries -----------------------------------------------------------------
    def proposals(self, now: datetime) -> list[Proposal]:
        out = []
        for symbol in self.cfg.universe:
            try:
                p = self._propose(symbol, now)
            except Exception:
                log.exception("%s: analysis failed", symbol)
                continue
            if p:
                out.append(p)
        return out

    def _propose(self, symbol: str, now: datetime) -> Proposal | None:
        today = now.date()
        expiration = choose_expiration(self.broker.expirations(symbol), today, self.cfg)
        if expiration is None:
            return None
        if self.cfg.avoid_earnings:
            earnings = self.broker.next_earnings(symbol)
            if earnings and today <= earnings <= expiration:
                log.debug("%s: earnings %s before expiration, skipping", symbol, earnings)
                return None
        price = self.broker.price(symbol)
        chain = self.broker.chain(symbol, expiration)
        sig = analyze(self.broker.daily_closes(symbol), price, atm_iv(chain, price))
        return propose(symbol, sig, chain, self.cfg)

    def scan_entries(self, now: datetime) -> None:
        equity = self.broker.equity()
        open_positions = self.journal.open_positions()
        if block := self.risk.entry_block_reason(equity, open_positions):
            log.info("no new entries: %s", block)
            return
        held = {}
        for pos in open_positions:
            held[pos.symbol] = held.get(pos.symbol, 0) + 1
        for p in self.proposals(now):
            if held.get(p.symbol, 0) >= self.cfg.max_positions_per_symbol:
                continue
            last = self.journal.last_closed(p.symbol)
            if last and (now.date() - last.date()).days < self.cfg.reentry_cooldown_days:
                continue
            open_positions = self.journal.open_positions()
            if self.risk.entry_block_reason(equity, open_positions):
                return
            qty = self.risk.size(p, equity, self.broker.buying_power(), open_positions)
            if qty < 1:
                log.info("%s %s: too large for the risk budget", p.symbol, p.strategy)
                continue
            fill = self._ladder(p.symbol, p.legs, qty, True, self.cfg.entry_max_concession,
                                accept=self._still_acceptable(p))
            if fill is None:
                log.info("%s %s: entry did not fill", p.symbol, p.strategy)
                continue
            entry = -fill.net_debit if p.is_credit else fill.net_debit
            pos = self.journal.open_position(p, fill.quantity, entry, now)
            held[p.symbol] = held.get(p.symbol, 0) + 1
            log.info("OPEN %s #%d %s x%d @ %.2f %s | %s | max loss $%.0f", p.symbol, pos.id,
                     p.strategy, fill.quantity, entry, "cr" if p.is_credit else "db",
                     describe(p.legs), pos.max_loss)

    def _still_acceptable(self, p: Proposal) -> Callable[[float], bool]:
        width = p.width

        def accept(net_debit: float) -> bool:
            if p.is_credit:
                return -net_debit / width >= self.cfg.min_credit_to_width
            return 0 < net_debit / width <= self.cfg.max_debit_to_width

        return accept

    # --- loop --------------------------------------------------------------------
    def run_once(self) -> None:
        now = self.clock()
        if not self.broker.is_market_open():
            log.debug("market closed")
            return
        equity = self.broker.equity()
        self.risk.update(equity, now.date())
        self.manage_exits(now)
        self.scan_entries(now)

    def run_forever(self) -> None:
        log.info("optbot running in %s mode on %s", self.cfg.mode.upper(),
                 ", ".join(self.cfg.universe))
        while True:
            try:
                self.run_once()
            except Exception:
                log.exception("cycle failed")
            time.sleep(self.cfg.poll_seconds)

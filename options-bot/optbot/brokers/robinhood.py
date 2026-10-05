"""Robinhood adapter built on the community `robin_stocks` library.

Robinhood has no official public API for stock or options trading. `robin_stocks` uses
the same private endpoints as the Robinhood app, so it can break without notice, and
automated trading through it may break Robinhood's terms; your account could be
restricted. Spreads need options trading level 3 on the account.

Credentials come from the environment, never from config files:
    RH_USERNAME, RH_PASSWORD, and RH_MFA_SECRET (the TOTP seed from enabling an
    authenticator app; omit it if you approve logins on your phone instead).
"""

from __future__ import annotations

import logging
import os
import time
from datetime import date, datetime, timedelta, timezone

from ..models import Fill, OptionQuote
from .base import Broker

log = logging.getLogger(__name__)

STRIKE_BAND = 0.20  # only pull quotes for strikes within +/-20% of the stock price
_BATCH = 40


def _f(x, default=0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


class RobinhoodBroker(Broker):
    def __init__(self, fill_timeout_seconds: int = 20) -> None:
        import robin_stocks.robinhood as rh  # optional dependency

        self.rh = rh
        self.fill_timeout = fill_timeout_seconds
        self._chain_cache: dict[tuple[str, date], tuple[float, list[OptionQuote]]] = {}
        self._login()

    def _login(self) -> None:
        user, pw = os.environ.get("RH_USERNAME"), os.environ.get("RH_PASSWORD")
        if not user or not pw:
            raise RuntimeError("set RH_USERNAME and RH_PASSWORD in the environment")
        mfa = None
        if secret := os.environ.get("RH_MFA_SECRET"):
            import pyotp

            mfa = pyotp.TOTP(secret).now()
        self.rh.login(user, pw, mfa_code=mfa, store_session=True)

    # --- account ---------------------------------------------------------------
    def is_market_open(self) -> bool:
        hours = self.rh.markets.get_market_today_hours("XNYS") or {}
        if not hours.get("is_open"):
            return False
        now = datetime.now(timezone.utc)
        opens = datetime.fromisoformat(hours["opens_at"].replace("Z", "+00:00"))
        closes = datetime.fromisoformat(hours["closes_at"].replace("Z", "+00:00"))
        # Skip the first and last 15 minutes: the widest, least reliable option quotes.
        return opens + timedelta(minutes=15) <= now <= closes - timedelta(minutes=15)

    def equity(self) -> float:
        profile = self.rh.profiles.load_portfolio_profile()
        return _f(profile.get("extended_hours_equity") or profile.get("equity"))

    def buying_power(self) -> float:
        return _f(self.rh.profiles.load_account_profile(info="buying_power"))

    # --- market data -----------------------------------------------------------
    def price(self, symbol: str) -> float:
        return _f(self.rh.stocks.get_latest_price(symbol)[0])

    def daily_closes(self, symbol: str) -> list[float]:
        bars = self.rh.stocks.get_stock_historicals(symbol, interval="day", span="year")
        return [_f(b["close_price"]) for b in bars if b and b.get("close_price")]

    def expirations(self, symbol: str) -> list[date]:
        chain = self.rh.options.get_chains(symbol) or {}
        return sorted(date.fromisoformat(d) for d in chain.get("expiration_dates", []))

    def _quote(self, symbol: str, expiration: date, instruments: list[dict]) -> list[OptionQuote]:
        from robin_stocks.robinhood.helper import request_get
        from robin_stocks.robinhood.urls import marketdata_options_url

        by_url = {i["url"]: i for i in instruments}
        urls = list(by_url)
        quotes = []
        for n in range(0, len(urls), _BATCH):
            data = request_get(marketdata_options_url(), "results",
                               {"instruments": ",".join(urls[n:n + _BATCH])}) or []
            for md in data:
                inst = by_url.get((md or {}).get("instrument"))
                if inst is None:
                    continue
                quotes.append(OptionQuote(
                    symbol=symbol,
                    expiration=expiration,
                    strike=_f(inst["strike_price"]),
                    type=inst["type"],
                    bid=_f(md.get("bid_price")),
                    ask=_f(md.get("ask_price")),
                    delta=_f(md.get("delta"), None),
                    iv=_f(md.get("implied_volatility"), None),
                    open_interest=int(_f(md.get("open_interest"))),
                ))
        return quotes

    def chain(self, symbol: str, expiration: date) -> list[OptionQuote]:
        key = (symbol, expiration)
        cached = self._chain_cache.get(key)
        if cached and time.monotonic() - cached[0] < 30:
            return cached[1]
        spot = self.price(symbol)
        instruments = [
            i for i in self.rh.options.find_tradable_options(symbol, expiration.isoformat())
            if i and i.get("expiration_date") == expiration.isoformat()
            and abs(_f(i["strike_price"]) / spot - 1) <= STRIKE_BAND
        ]
        quotes = self._quote(symbol, expiration, instruments)
        self._chain_cache[key] = (time.monotonic(), quotes)
        return quotes

    def quotes_for(self, symbol, legs) -> dict:
        """Quote exactly the held legs, so exits work even after a move past STRIKE_BAND."""
        out: dict = {}
        for leg in legs:
            found = self.rh.options.find_tradable_options(
                symbol, leg.expiration.isoformat(), f"{leg.strike:g}", leg.type) or []
            inst = [i for i in found if i and i.get("expiration_date") == leg.expiration.isoformat()
                    and abs(_f(i["strike_price"]) - leg.strike) < 1e-6]
            for q in self._quote(symbol, leg.expiration, inst[:1]):
                out[q.key()] = q
        missing = [leg for leg in legs if leg.key() not in out]
        if missing:
            raise LookupError(f"{symbol}: no quote for {missing}")
        return out

    def next_earnings(self, symbol: str) -> date | None:
        try:
            rows = self.rh.stocks.get_earnings(symbol) or []
        except Exception:  # earnings data is best-effort
            log.warning("%s: earnings lookup failed", symbol)
            return None
        today = date.today()
        dates = []
        for row in rows:
            report = (row or {}).get("report") or {}
            if report.get("date"):
                d = date.fromisoformat(report["date"])
                if d >= today:
                    dates.append(d)
        return min(dates, default=None)

    # --- orders ----------------------------------------------------------------
    def submit_spread(self, symbol, legs, quantity, net_debit, opening) -> Fill | None:
        spread = [{
            "expirationDate": leg.expiration.isoformat(),
            "strike": f"{leg.strike:g}",
            "optionType": leg.type,
            "effect": "open" if opening else "close",
            "action": leg.action,
            "ratio_quantity": 1,
        } for leg in legs]
        direction = "debit" if net_debit > 0 else "credit"
        price = max(round(abs(net_debit), 2), 0.01)
        order = self.rh.orders.order_option_spread(direction, price, symbol, quantity, spread,
                                                   timeInForce="gfd")
        order_id = (order or {}).get("id")
        if not order_id:
            log.error("%s: order rejected: %s", symbol, order)
            return None
        deadline = time.monotonic() + self.fill_timeout
        while time.monotonic() < deadline:
            time.sleep(2)
            info = self.rh.orders.get_option_order_info(order_id) or {}
            state = info.get("state")
            if state == "filled":
                return Fill(net_debit, quantity, order_id)
            if state in ("cancelled", "rejected", "failed"):
                log.warning("%s: order %s %s", symbol, order_id, state)
                return None
        self.rh.orders.cancel_option_order(order_id)
        time.sleep(2)
        info = self.rh.orders.get_option_order_info(order_id) or {}
        if info.get("state") == "filled":  # filled while we were cancelling
            return Fill(net_debit, quantity, order_id)
        filled = int(_f(info.get("processed_quantity")))
        if filled > 0:
            log.warning("%s: order %s partially filled %d/%d", symbol, order_id, filled, quantity)
            return Fill(net_debit, filled, order_id)
        return None


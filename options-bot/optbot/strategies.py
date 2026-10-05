"""Strategy selection: given signals and an option chain, propose one defined-risk trade.

Decision table (trend from 20/50-day SMAs, IV regime from ATM IV / 20-day realized vol):

    trend   | IV rich (sell premium)  | IV normal              | IV cheap (buy premium)
    --------+-------------------------+------------------------+------------------------
    up      | bull put credit spread  | bull put credit spread | bull call debit spread
    down    | bear call credit spread | bear call credit spread| bear put debit spread
    neutral | iron condor             | (no trade)             | (no trade)

An overextended trend (RSI past the overbought/oversold line) is treated as neutral: we
do not chase. Every structure has a defined maximum loss.
"""

from __future__ import annotations

from datetime import date

from .config import Config
from .indicators import Signals
from .models import Leg, OptionQuote, Proposal


def choose_expiration(expirations: list[date], today: date, cfg: Config) -> date | None:
    eligible = [e for e in expirations if cfg.min_dte <= (e - today).days <= cfg.max_dte]
    if not eligible:
        return None
    return min(eligible, key=lambda e: abs((e - today).days - cfg.target_dte))


def atm_iv(chain: list[OptionQuote], price: float) -> float | None:
    ivs = []
    for t in ("call", "put"):
        side = [q for q in chain if q.type == t and q.iv]
        if side:
            ivs.append(min(side, key=lambda q: abs(q.strike - price)).iv)
    return sum(ivs) / len(ivs) if ivs else None


def _liquid(chain: list[OptionQuote], t: str, cfg: Config) -> list[OptionQuote]:
    return sorted(
        (
            q for q in chain
            if q.type == t
            and q.bid > 0
            and q.delta is not None
            and q.open_interest >= cfg.min_open_interest
            and q.spread_pct <= cfg.max_leg_spread_pct
        ),
        key=lambda q: q.strike,
    )


def _closest_delta(quotes: list[OptionQuote], target: float) -> OptionQuote | None:
    return min(quotes, key=lambda q: abs(abs(q.delta) - target), default=None)


def _wing(quotes: list[OptionQuote], short: OptionQuote, width: float) -> OptionQuote | None:
    """The long protective leg: further OTM than `short`, about `width` away."""
    if short.type == "put":
        further = [q for q in quotes if q.strike < short.strike]
    else:
        further = [q for q in quotes if q.strike > short.strike]
    return min(further, key=lambda q: abs(abs(q.strike - short.strike) - width), default=None)


def _credit_vertical(chain, t, price, cfg) -> tuple[OptionQuote, OptionQuote] | None:
    quotes = _liquid(chain, t, cfg)
    otm = [q for q in quotes if (q.strike < price if t == "put" else q.strike > price)]
    short = _closest_delta(otm, cfg.credit_short_delta)
    if short is None:
        return None
    long = _wing(quotes, short, price * cfg.spread_width_pct)
    if long is None:
        return None
    return short, long


def _legs(short: OptionQuote, long: OptionQuote) -> tuple[Leg, Leg]:
    return (
        Leg(short.expiration, short.strike, short.type, "sell"),
        Leg(long.expiration, long.strike, long.type, "buy"),
    )


def credit_spread(symbol, chain, t, price, cfg, reason="") -> Proposal | None:
    pair = _credit_vertical(chain, t, price, cfg)
    if pair is None:
        return None
    short, long = pair
    credit = round(short.mid - long.mid, 2)
    width = abs(short.strike - long.strike)
    if credit <= 0 or credit / width < cfg.min_credit_to_width:
        return None
    name = "bull_put_credit" if t == "put" else "bear_call_credit"
    return Proposal(symbol, name, _legs(short, long), credit, True, reason)


def debit_spread(symbol, chain, t, price, cfg, reason="") -> Proposal | None:
    quotes = _liquid(chain, t, cfg)
    long = _closest_delta(quotes, cfg.debit_long_delta)
    if long is None:
        return None
    if t == "call":
        further = [q for q in quotes if q.strike > long.strike]
    else:
        further = [q for q in quotes if q.strike < long.strike]
    short = _closest_delta(further, cfg.debit_short_delta)
    if short is None:
        return None
    debit = round(long.mid - short.mid, 2)
    width = abs(short.strike - long.strike)
    if debit <= 0 or debit / width > cfg.max_debit_to_width:
        return None
    legs = (
        Leg(long.expiration, long.strike, long.type, "buy"),
        Leg(short.expiration, short.strike, short.type, "sell"),
    )
    name = "bull_call_debit" if t == "call" else "bear_put_debit"
    return Proposal(symbol, name, legs, debit, False, reason)


def iron_condor(symbol, chain, price, cfg, reason="") -> Proposal | None:
    puts = _credit_vertical(chain, "put", price, cfg)
    calls = _credit_vertical(chain, "call", price, cfg)
    if puts is None or calls is None:
        return None
    credit = round(puts[0].mid - puts[1].mid + calls[0].mid - calls[1].mid, 2)
    width = max(abs(puts[0].strike - puts[1].strike), abs(calls[0].strike - calls[1].strike))
    if credit <= 0 or credit / width < cfg.min_credit_to_width:
        return None
    return Proposal(symbol, "iron_condor", _legs(*puts) + _legs(*calls), credit, True, reason)


def propose(symbol: str, sig: Signals, chain: list[OptionQuote], cfg: Config) -> Proposal | None:
    ratio = sig.iv_hv_ratio
    if ratio is None:
        return None
    trend = sig.trend
    if (trend > 0 and sig.rsi >= cfg.rsi_overbought) or (trend < 0 and sig.rsi <= cfg.rsi_oversold):
        trend = 0  # overextended: don't chase
    why = f"trend={trend:+d} rsi={sig.rsi:.0f} iv/hv={ratio:.2f}"

    if trend == 0:
        if ratio >= cfg.iv_rich_ratio:
            return iron_condor(symbol, chain, sig.price, cfg, why)
        return None
    if ratio <= cfg.iv_cheap_ratio:
        return debit_spread(symbol, chain, "call" if trend > 0 else "put", sig.price, cfg, why)
    return credit_spread(symbol, chain, "put" if trend > 0 else "call", sig.price, cfg, why)

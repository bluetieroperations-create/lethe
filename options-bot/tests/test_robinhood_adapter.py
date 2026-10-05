"""The Robinhood adapter against a mocked robin_stocks: parsing and order plumbing only."""

from datetime import date
from types import SimpleNamespace

import pytest

pytest.importorskip("robin_stocks")

from optbot.brokers import robinhood as rhmod  # noqa: E402
from optbot.models import Leg  # noqa: E402

EXP = date(2026, 11, 9)


def make(states, instruments, marketdata, monkeypatch):
    placed, cancelled = [], []
    rh = SimpleNamespace(
        stocks=SimpleNamespace(get_latest_price=lambda s: ["100.00"]),
        options=SimpleNamespace(find_tradable_options=lambda *a, **k: instruments),
        orders=SimpleNamespace(
            order_option_spread=lambda *a, **k: placed.append((a, k)) or {"id": "abc"},
            get_option_order_info=lambda oid: {"state": states.pop(0) if states else "queued",
                                               "processed_quantity": "0"},
            cancel_option_order=lambda oid: cancelled.append(oid),
        ),
    )
    import robin_stocks.robinhood.helper as helper

    monkeypatch.setattr(helper, "request_get", lambda url, kind, payload: marketdata)
    monkeypatch.setattr(rhmod.time, "sleep", lambda s: None)
    b = object.__new__(rhmod.RobinhoodBroker)
    b.rh, b.fill_timeout, b._chain_cache = rh, 5, {}
    return b, placed, cancelled


INST = [
    {"url": "u1", "strike_price": "95.0000", "type": "put", "expiration_date": "2026-11-09"},
    {"url": "u2", "strike_price": "150.0000", "type": "put", "expiration_date": "2026-11-09"},
]
MD = [{"instrument": "u1", "bid_price": "1.10", "ask_price": "1.20", "delta": "-0.30",
       "implied_volatility": "0.35", "open_interest": 1234}]


def test_chain_parses_and_filters_band(monkeypatch):
    b, *_ = make([], INST, MD, monkeypatch)
    [q] = b.chain("XYZ", EXP)  # 150 strike is outside the +/-20% band
    assert (q.strike, q.type, q.bid, q.ask, q.delta, q.open_interest) == \
        (95.0, "put", 1.10, 1.20, -0.30, 1234)


def test_credit_order_fills(monkeypatch):
    b, placed, cancelled = make(["queued", "filled"], INST, MD, monkeypatch)
    legs = (Leg(EXP, 95, "put", "sell"), Leg(EXP, 90, "put", "buy"))
    fill = b.submit_spread("XYZ", legs, 2, -1.234, opening=True)
    assert fill and fill.quantity == 2
    (direction, price, symbol, qty, spread), _ = placed[0]
    assert (direction, price, symbol, qty) == ("credit", 1.23, "XYZ", 2)
    assert spread[0] == {"expirationDate": "2026-11-09", "strike": "95", "optionType": "put",
                         "effect": "open", "action": "sell", "ratio_quantity": 1}
    assert cancelled == []


def test_unfilled_order_is_cancelled(monkeypatch):
    b, placed, cancelled = make([], INST, MD, monkeypatch)
    b.fill_timeout = 0
    legs = (Leg(EXP, 95, "put", "buy"), Leg(EXP, 90, "put", "sell"))
    assert b.submit_spread("XYZ", legs, 1, 0.5, opening=False) is None
    assert placed[0][0][0] == "debit" and placed[0][0][4][0]["effect"] == "close"
    assert cancelled == ["abc"]

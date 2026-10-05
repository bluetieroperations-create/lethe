from datetime import date, timedelta

from optbot.config import Config
from optbot.indicators import Signals
from optbot.strategies import atm_iv, choose_expiration, propose
from tests.fakes import FakeMarket, trending_closes

TODAY = date(2026, 10, 5)
CFG = Config()


def market(iv=0.35):
    return FakeMarket(TODAY, 100.0, trending_closes(100, 0), iv)


def chain(iv=0.35):
    m = market(iv)
    return m.chain("XYZ", TODAY + timedelta(days=35))


def sig(trend, ratio, rsi=55.0):
    return Signals(price=100.0, trend=trend, rsi=rsi, hv20=0.30, atm_iv=0.30 * ratio)


def test_choose_expiration_prefers_target_dte():
    exps = [TODAY + timedelta(days=d) for d in (7, 21, 33, 45, 70)]
    assert choose_expiration(exps, TODAY, CFG) == TODAY + timedelta(days=33)
    assert choose_expiration([TODAY + timedelta(days=7)], TODAY, CFG) is None


def test_atm_iv():
    assert atm_iv(chain(0.4), 100.0) == 0.4


def test_uptrend_rich_iv_sells_put_spread():
    p = propose("XYZ", sig(1, 1.3), chain(), CFG)
    assert p.strategy == "bull_put_credit" and p.is_credit
    short = next(leg for leg in p.legs if leg.action == "sell")
    long = next(leg for leg in p.legs if leg.action == "buy")
    assert long.strike < short.strike < 100
    assert p.price / p.width >= CFG.min_credit_to_width
    assert p.max_loss_per_contract == (p.width - p.price) * 100


def test_downtrend_sells_call_spread():
    p = propose("XYZ", sig(-1, 1.0), chain(), CFG)
    assert p.strategy == "bear_call_credit"
    short = next(leg for leg in p.legs if leg.action == "sell")
    assert short.type == "call" and short.strike > 100


def test_cheap_iv_buys_debit_spread():
    p = propose("XYZ", sig(1, 0.8), chain(), CFG)
    assert p.strategy == "bull_call_debit" and not p.is_credit
    assert 0 < p.price <= p.width * CFG.max_debit_to_width
    p = propose("XYZ", sig(-1, 0.8), chain(), CFG)
    assert p.strategy == "bear_put_debit"


def test_neutral_rich_iv_iron_condor():
    p = propose("XYZ", sig(0, 1.3), chain(), CFG)
    assert p.strategy == "iron_condor" and len(p.legs) == 4
    puts = sorted(leg.strike for leg in p.legs if leg.type == "put")
    calls = sorted(leg.strike for leg in p.legs if leg.type == "call")
    assert puts[1] < 100 < calls[0]


def test_no_trade_when_neutral_and_iv_not_rich():
    assert propose("XYZ", sig(0, 1.0), chain(), CFG) is None


def test_overextended_trend_is_not_chased():
    p = propose("XYZ", sig(1, 0.8, rsi=85), chain(), CFG)
    assert p is None  # treated as neutral; IV not rich -> no trade


def test_illiquid_chain_yields_nothing():
    cfg = Config(min_open_interest=10_000)
    assert propose("XYZ", sig(1, 1.3), chain(), cfg) is None

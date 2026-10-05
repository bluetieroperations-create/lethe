from datetime import date, datetime, timedelta

from optbot.config import Config
from optbot.journal import Journal
from optbot.models import Leg, Position, Proposal
from optbot.risk import RiskManager

TODAY = date(2026, 10, 5)
EXP = TODAY + timedelta(days=35)


def put_spread(credit=1.5):
    legs = (Leg(EXP, 95, "put", "sell"), Leg(EXP, 90, "put", "buy"))
    return Proposal("XYZ", "bull_put_credit", legs, credit, True)


def position(p, qty=1, dte=35):
    legs = tuple(Leg(TODAY + timedelta(days=dte), leg.strike, leg.type, leg.action)
                 for leg in p.legs)
    return Position(1, p.symbol, p.strategy, legs, qty, p.price, p.is_credit, datetime.now())


def rm(**kw):
    return RiskManager(Config(**kw), Journal())


def test_size_respects_per_trade_risk():
    r = rm()
    # max loss 350/contract, 4% of 10k = 400 -> 1 contract
    assert r.size(put_spread(), 10_000, 10_000, []) == 1
    assert r.size(put_spread(), 100_000, 100_000, []) == 11


def test_size_respects_total_risk_and_buying_power():
    r = rm()
    existing = [position(put_spread(), qty=10)]  # 3500 at risk: budget spent
    assert r.size(put_spread(), 10_000, 10_000, existing) == 0
    assert r.size(put_spread(), 100_000, 700, []) == 2


def test_daily_loss_limit_blocks_entries():
    r = rm()
    r.update(10_000, TODAY)
    assert r.entry_block_reason(9_500, []) is None
    assert "daily loss" in r.entry_block_reason(9_300, [])
    r.update(9_300, TODAY + timedelta(days=1))  # new day resets the baseline
    assert r.entry_block_reason(9_300, []) is None


def test_drawdown_kill_switch_latches_until_resume():
    r = rm()
    r.update(10_000, TODAY)
    r.update(12_000, TODAY + timedelta(days=1))
    r.update(9_500, TODAY + timedelta(days=2))  # -20.8% from 12k
    assert "KILL SWITCH" in r.entry_block_reason(9_500, [])
    r.update(11_000, TODAY + timedelta(days=3))
    assert r.halted  # stays latched even after recovering
    r.resume(11_000)
    assert r.entry_block_reason(11_000, []) is None


def test_max_positions():
    r = rm(max_positions=1)
    assert "max positions" in r.entry_block_reason(10_000, [position(put_spread())])


def test_credit_exits():
    r = rm()
    pos = position(put_spread(1.5))
    assert r.exit_reason(pos, -1.0, TODAY) is None
    assert r.exit_reason(pos, -0.75, TODAY) == "take_profit"  # kept 50% of the credit
    assert r.exit_reason(pos, -4.5, TODAY) == "stop_loss"  # lost 2x the credit
    # width 5, credit 1.5 -> max loss 3.5; half of it (1.75) comes before 2x credit (3.0)
    assert r.exit_reason(pos, -3.2, TODAY) is None
    assert r.exit_reason(pos, -3.3, TODAY) == "stop_loss"
    assert r.exit_reason(position(put_spread(1.5), dte=21), -1.2, TODAY) == "time_exit"


def test_debit_exits():
    r = rm()
    legs = (Leg(EXP, 100, "call", "buy"), Leg(EXP, 105, "call", "sell"))
    pos = Position(1, "XYZ", "bull_call_debit", legs, 1, 2.0, False, datetime.now())
    assert r.exit_reason(pos, 2.5, TODAY) is None
    assert r.exit_reason(pos, 3.6, TODAY) == "take_profit"
    assert r.exit_reason(pos, 1.0, TODAY) == "stop_loss"

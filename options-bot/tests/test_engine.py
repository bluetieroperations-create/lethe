from datetime import date, datetime, timedelta

from optbot.brokers.paper import PaperBroker
from optbot.config import Config
from optbot.engine import Engine
from optbot.journal import Journal
from tests.fakes import FakeMarket, trending_closes

TODAY = date(2026, 10, 5)
NOW = datetime(2026, 10, 5, 11, 0)


def setup(daily=0.004, iv=0.45, **cfg):
    closes = trending_closes(100, daily)
    m = FakeMarket(TODAY, closes[-1], closes, iv)
    c = Config(universe=("XYZ",), **cfg)
    return m, Engine(m, c, Journal(), clock=lambda: NOW)


def test_opens_a_sized_credit_spread_in_uptrend():
    m, e = setup()
    e.run_once()
    [pos] = e.journal.open_positions()
    assert pos.strategy == "bull_put_credit"
    assert pos.max_loss <= 10_000 * e.cfg.risk_per_trade_pct
    assert m.orders[0][3] < 0  # opened for a credit
    e.run_once()  # one per symbol: no duplicate
    assert len(e.journal.open_positions()) == 1


def test_closed_market_does_nothing():
    m, e = setup()
    m.open = False
    e.run_once()
    assert m.orders == []


def test_earnings_before_expiration_blocks_entry():
    m, e = setup()
    m.earnings = TODAY + timedelta(days=10)
    e.run_once()
    assert m.orders == []


def test_unfilled_entry_is_not_journaled():
    m, e = setup(ladder_steps=3)
    m.fill = False
    e.run_once()
    assert len(m.orders) == 3  # walked the ladder
    prices = [o[3] for o in m.orders]
    assert prices == sorted(prices)  # each step concedes more (less credit)
    assert e.journal.open_positions() == []


def test_take_profit_after_rally():
    m, e = setup()
    e.run_once()
    m.spot *= 1.10  # puts collapse
    e.run_once()
    [trade] = e.journal.closed_trades()
    assert trade[6] == "take_profit" and trade[5] > 0
    assert m.orders[-1][4] is False  # closing order


def test_stop_loss_after_crash():
    m, e = setup()
    e.run_once()
    m.spot *= 0.88
    e.run_once()
    [trade] = e.journal.closed_trades()
    assert trade[6] == "stop_loss" and trade[5] < 0


def test_paper_broker_round_trip(tmp_path):
    closes = trending_closes(100, 0.004)
    m = FakeMarket(TODAY, closes[-1], closes, 0.45)
    state = tmp_path / "paper.json"
    paper = PaperBroker(m, 10_000, 0.25, str(state))
    e = Engine(paper, Config(universe=("XYZ",)), Journal(), clock=lambda: NOW)
    e.run_once()
    [pos] = e.journal.open_positions()
    assert paper.cash > 10_000  # credit received
    assert paper.buying_power() < 10_000  # collateral held
    assert abs(paper.equity() - 10_000) < 50  # marked near entry
    reloaded = PaperBroker(m, 0, 0.25, str(state))
    assert reloaded.cash == paper.cash and len(reloaded.positions) == 1
    m.spot *= 1.10
    e.run_once()
    assert e.journal.open_positions() == []
    assert paper.positions == []
    assert paper.equity() > 10_000

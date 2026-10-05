"""Command line: `optbot run | scan | status | resume`."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime

from .config import Config
from .engine import Engine
from .journal import Journal
from .models import describe


def _broker(cfg: Config, live_flag: bool):
    from .brokers.robinhood import RobinhoodBroker

    rh = RobinhoodBroker(cfg.fill_timeout_seconds)
    if cfg.mode == "live":
        if not live_flag:
            sys.exit("config says mode = \"live\"; pass --live as well to trade real money")
        return rh
    if live_flag:
        sys.exit("--live given but config mode is \"paper\"; set mode = \"live\" to trade")
    from .brokers.paper import PaperBroker

    return PaperBroker(rh, cfg.paper_starting_cash, cfg.paper_slippage, cfg.paper_state_path)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="optbot", description=__doc__)
    ap.add_argument("--config", help="TOML config file (defaults are used if omitted)")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the trading loop")
    run.add_argument("--once", action="store_true", help="run one cycle and exit")
    run.add_argument("--live", action="store_true", help="required to trade real money")
    sub.add_parser("scan", help="show what the bot would trade right now; places nothing")
    sub.add_parser("status", help="open positions, closed trades and risk state")
    sub.add_parser("resume", help="clear the drawdown kill switch")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = Config.load(args.config)
    journal = Journal(cfg.db_path)

    if args.cmd == "status":
        _status(journal)
        return

    broker = _broker(cfg, getattr(args, "live", False))
    engine = Engine(broker, cfg, journal)

    if args.cmd == "scan":
        for p in engine.proposals(datetime.now()):
            print(f"{p.symbol:6} {p.strategy:17} {describe(p.legs)}  "
                  f"{'credit' if p.is_credit else 'debit'} {p.price:.2f}  "
                  f"max loss ${p.max_loss_per_contract:.0f}/contract  ({p.reason})")
    elif args.cmd == "resume":
        engine.risk.resume(broker.equity())
        print("kill switch cleared")
    elif args.cmd == "run":
        if args.once:
            engine.run_once()
        else:
            engine.run_forever()


def _status(journal: Journal) -> None:
    halted = journal.get("halted")
    print(f"kill switch: {halted or 'off'}   high-water: {journal.get('high_water', '-')}")
    print("\nOPEN")
    for pos in journal.open_positions():
        print(f"  #{pos.id} {pos.symbol:6} {pos.strategy:17} x{pos.quantity} @ "
              f"{pos.entry_price:.2f}  {describe(pos.legs)}  max loss ${pos.max_loss:.0f}")
    trades = journal.closed_trades()
    print("\nCLOSED")
    for t in trades:
        print(f"  {t[0]:6} {t[1]:17} x{t[2]} {t[3]:.2f} -> {t[4]:+.2f}  "
              f"pnl {t[5]:+9.2f}  {t[6]}")
    if trades:
        pnls = [t[5] for t in trades]
        wins = sum(1 for x in pnls if x > 0)
        print(f"\n  {len(pnls)} trades, win rate {wins / len(pnls):.0%}, "
              f"total pnl {sum(pnls):+.2f}")


if __name__ == "__main__":
    main()

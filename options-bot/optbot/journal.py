"""SQLite journal: the bot's record of its own positions, closed trades and risk state."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from .models import Leg, Position, Proposal

_SCHEMA = """
CREATE TABLE IF NOT EXISTS positions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,
    strategy TEXT NOT NULL,
    legs TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    entry_price REAL NOT NULL,
    is_credit INTEGER NOT NULL,
    opened_at TEXT NOT NULL,
    reason TEXT,
    closed_at TEXT,
    exit_value REAL,
    pnl REAL,
    exit_reason TEXT
);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Journal:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path)
        self.db.executescript(_SCHEMA)

    # --- positions -----------------------------------------------------------
    def open_position(self, p: Proposal, quantity: int, entry_price: float,
                      now: datetime) -> Position:
        cur = self.db.execute(
            "INSERT INTO positions (symbol, strategy, legs, quantity, entry_price, is_credit,"
            " opened_at, reason) VALUES (?,?,?,?,?,?,?,?)",
            (p.symbol, p.strategy, json.dumps([leg.to_dict() for leg in p.legs]), quantity,
             entry_price, int(p.is_credit), now.isoformat(), p.reason),
        )
        self.db.commit()
        return Position(cur.lastrowid, p.symbol, p.strategy, p.legs, quantity, entry_price,
                        p.is_credit, now)

    def close_position(self, pos: Position, exit_value: float, reason: str,
                       now: datetime, quantity: int | None = None) -> float:
        """Close `quantity` contracts (default all). A partial close leaves the rest open."""
        qty = pos.quantity if quantity is None else quantity
        pnl = pos.pnl_per_share(exit_value) * 100 * qty
        if qty < pos.quantity:
            self.db.execute("UPDATE positions SET quantity=? WHERE id=?",
                            (pos.quantity - qty, pos.id))
            self.db.execute(
                "INSERT INTO positions (symbol, strategy, legs, quantity, entry_price, is_credit,"
                " opened_at, reason, closed_at, exit_value, pnl, exit_reason)"
                " SELECT symbol, strategy, legs, ?, entry_price, is_credit, opened_at, reason,"
                " ?, ?, ?, ? FROM positions WHERE id=?",
                (qty, now.isoformat(), exit_value, pnl, reason, pos.id),
            )
        else:
            self.db.execute(
                "UPDATE positions SET closed_at=?, exit_value=?, pnl=?, exit_reason=?"
                " WHERE id=?",
                (now.isoformat(), exit_value, pnl, reason, pos.id),
            )
        self.db.commit()
        return pnl

    def open_positions(self) -> list[Position]:
        rows = self.db.execute(
            "SELECT id, symbol, strategy, legs, quantity, entry_price, is_credit, opened_at"
            " FROM positions WHERE closed_at IS NULL ORDER BY id"
        ).fetchall()
        return [
            Position(r[0], r[1], r[2], tuple(Leg.from_dict(d) for d in json.loads(r[3])), r[4],
                     r[5], bool(r[6]), datetime.fromisoformat(r[7]))
            for r in rows
        ]

    def closed_trades(self) -> list[tuple]:
        return self.db.execute(
            "SELECT symbol, strategy, quantity, entry_price, exit_value, pnl, exit_reason,"
            " opened_at, closed_at FROM positions WHERE closed_at IS NOT NULL ORDER BY id"
        ).fetchall()

    def last_closed(self, symbol: str) -> datetime | None:
        row = self.db.execute(
            "SELECT MAX(closed_at) FROM positions WHERE symbol=? AND closed_at IS NOT NULL",
            (symbol,),
        ).fetchone()
        return datetime.fromisoformat(row[0]) if row and row[0] else None

    # --- key/value state -----------------------------------------------------
    def get(self, key: str, default: str | None = None) -> str | None:
        row = self.db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set(self, key: str, value: object) -> None:
        self.db.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)",
                        (key, str(value)))
        self.db.commit()

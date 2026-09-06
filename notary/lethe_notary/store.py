"""The private witness log.

PRIVATE BY DESIGN. A public log would make the truncation argument stronger —
anyone could check it — but it would publish deletion metadata: which key
deleted what, when, how often, under which table names. That is commercially
sensitive for the operator and is not the notary's to disclose. So the log is
private, and readable only by whoever controls the key that wrote to it, proven
by signature rather than by an account.

The log is append-only. Nothing here updates or deletes a row, because a
witness that can be edited is not a witness.
"""

import json
import sqlite3
from contextlib import closing

SCHEMA = """
CREATE TABLE IF NOT EXISTS witnessed (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_key_id     TEXT,
    certificate_public_key TEXT NOT NULL,
    payload_hash           TEXT NOT NULL UNIQUE,
    audit_head             TEXT,
    subject_hash           TEXT,
    witnessed_at           TEXT NOT NULL,
    receipt                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS witnessed_by_key
    ON witnessed (certificate_public_key, id);
"""
# payload_hash is UNIQUE so that presenting the same certificate twice returns
# the first receipt rather than minting a second one with a later timestamp.
# Two receipts for one certificate disagreeing about when it was witnessed
# would undermine the only thing the receipt is for.


class WitnessLog:
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with closing(self._conn.cursor()) as cur:
            cur.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def existing(self, payload_hash: str) -> dict | None:
        """The receipt already issued for this certificate, if any."""
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT receipt FROM witnessed WHERE payload_hash = ?", (payload_hash,)
            )
            row = cur.fetchone()
        return json.loads(row["receipt"]) if row else None

    def record(self, receipt: dict) -> tuple[dict, bool]:
        """Append a receipt. Returns (receipt, is_new).

        On a repeat presentation the stored receipt is returned unchanged and
        is_new is False — the caller uses that to avoid charging twice for one
        certificate.
        """
        p = receipt["payload"]
        try:
            with closing(self._conn.cursor()) as cur:
                cur.execute(
                    "INSERT INTO witnessed (certificate_key_id, certificate_public_key,"
                    " payload_hash, audit_head, subject_hash, witnessed_at, receipt)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        p.get("certificate_key_id"),
                        p["certificate_public_key"],
                        p["certificate_payload_hash"],
                        p.get("audit_head"),
                        p.get("subject_hash"),
                        p["witnessed_at"],
                        json.dumps(receipt),
                    ),
                )
            self._conn.commit()
            return receipt, True
        except sqlite3.IntegrityError:
            self._conn.rollback()
            prior = self.existing(p["certificate_payload_hash"])
            if prior is None:  # pragma: no cover — only on a concurrent delete
                raise
            return prior, False

    def heads_for(
        self, certificate_public_key: str, *, after: int = 0, limit: int = 1000
    ) -> tuple[list[dict], int | None]:
        """Heads witnessed for this key, oldest first, from `after` onward.

        This is the dispute-resolution query, and the reason the service
        exists: the operator's chain must still contain every head listed here,
        and one missing means entries were dropped after the notary saw them.

        Returns (rows, next_cursor). The cursor is not a nicety — silently
        truncating THIS query is the worst failure the service has, because a
        head that was witnessed but not returned reads exactly like a head that
        was never witnessed, and the operator draws the opposite conclusion
        from the one the evidence supports. One extra row is fetched purely to
        decide whether more exist.
        """
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT id, audit_head, witnessed_at, payload_hash, subject_hash"
                " FROM witnessed WHERE certificate_public_key = ? AND id > ?"
                " ORDER BY id ASC LIMIT ?",
                (certificate_public_key, after, limit + 1),
            )
            rows = [dict(r) for r in cur.fetchall()]
        if len(rows) > limit:
            return rows[:limit], rows[limit - 1]["id"]
        return rows, None

    def count(self) -> int:
        with closing(self._conn.cursor()) as cur:
            cur.execute("SELECT count(*) AS n FROM witnessed")
            return cur.fetchone()["n"]

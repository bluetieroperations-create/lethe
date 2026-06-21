import hashlib
import hmac
import json

import psycopg

GENESIS = "0" * 64

AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS lethe_audit (
    seq BIGSERIAL PRIMARY KEY,
    entry JSONB NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def _entry_hash(prev_hash: str, entry: dict) -> str:
    data = prev_hash + json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()


class AuditLog:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def init_schema(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute(AUDIT_SCHEMA)
        self.conn.commit()

    def _last_hash(self) -> str:
        with self.conn.cursor() as cur:
            cur.execute("SELECT entry_hash FROM lethe_audit ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
        return row[0] if row else GENESIS

    def append(self, entry: dict) -> str:
        prev = self._last_hash()
        h = _entry_hash(prev, entry)
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO lethe_audit (entry, prev_hash, entry_hash) VALUES (%s, %s, %s)",
                (json.dumps(entry), prev, h),
            )
        self.conn.commit()
        return h

    def head(self) -> str:
        """Current tip hash (GENESIS if the log is empty). Record this
        out-of-band; later pass it to verify_chain(expected_head=...) to detect
        tip-truncation (deletion of the most recent entries)."""
        return self._last_hash()

    def verify_chain(self, expected_head: str | None = None) -> bool:
        """Verify the hash chain links from genesis to the current tip.

        SECURITY: an internal walk proves no entry was *altered* or removed from
        the *middle* (that breaks a prev_hash link), but it CANNOT detect tip
        truncation — deleting the most recent entries leaves a self-consistent,
        merely shorter chain. To catch an attacker lopping off the tail (erasing
        evidence of recent erasures), the operator must record the head hash
        out-of-band and pass it as ``expected_head`` — the same pin-it-externally
        discipline the certificate uses for the trusted public key. With no
        entries the head is ``GENESIS``.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT entry, prev_hash, entry_hash FROM lethe_audit ORDER BY seq ASC"
            )
            rows = cur.fetchall()
        prev = GENESIS
        for entry, prev_hash, entry_hash in rows:
            if prev_hash != prev:
                return False
            if _entry_hash(prev_hash, entry) != entry_hash:
                return False
            prev = entry_hash
        if expected_head is not None and not hmac.compare_digest(prev, expected_head):
            return False
        return True

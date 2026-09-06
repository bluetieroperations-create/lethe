import hashlib
import hmac
import json
import random
import time
from typing import TYPE_CHECKING

import psycopg

if TYPE_CHECKING:  # pragma: no cover
    from .anchor import Anchor

GENESIS = "0" * 64

# How many times append() re-reads the tip and retries after losing a race.
# Each retry means another writer committed first, so the loop only spins as
# fast as the chain actually advances, and a bound is better than spinning
# forever. Losing every attempt raises rather than dropping the entry.
_APPEND_ATTEMPTS = 12

# Retries back off with full jitter. Without it, writers that collide once
# collide again in lockstep: measured with 24 concurrent writers and no
# backoff, 5 exhausted their attempts and lost their entries. The chain stayed
# intact — the constraint saw to that — but an unrecorded forget is its own
# kind of hole. Sleeps are tiny; this only ever runs when someone else is
# writing at the same instant.
_APPEND_BACKOFF_BASE = 0.005
_APPEND_BACKOFF_CAP = 0.2

AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS lethe_audit (
    seq BIGSERIAL PRIMARY KEY,
    entry JSONB NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

# In a linear chain every entry links to a distinct predecessor, so prev_hash
# is unique by construction — exactly one entry carries GENESIS, and exactly
# one carries each subsequent entry_hash. Stating that as a constraint is what
# makes a fork *impossible* rather than merely unlikely: append() reads the
# tip, hashes it and inserts, so two writers that read the same tip would
# otherwise both commit and leave two entries claiming the same predecessor.
# The database refuses the second one, and append() retries against the new
# tip. This is the only guard that works across processes — the MCP server's
# in-process lock cannot help a cron `lethe anchor` racing an operator's
# `lethe forget`, which is the documented deployment.
AUDIT_CHAIN_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS lethe_audit_prev_hash_key
    ON lethe_audit (prev_hash);
"""


class AuditChainForked(Exception):
    """An existing chain already contains two entries with the same
    predecessor, so the uniqueness constraint cannot be applied to it.

    This is not a migration problem to work around: it means the log already
    forked, and any verify_chain() over it returns False. Carries the
    offending prev_hash values and the rows that share them so an operator can
    see where the chain split before deciding what to do about it.
    """

    def __init__(self, forks: list[tuple[str, list[int]]]):
        self.forks = forks
        detail = "; ".join(f"{h[:16]}… at seq {seqs}" for h, seqs in forks)
        super().__init__(
            f"audit chain already contains {len(forks)} fork(s) and cannot be "
            f"made unique: {detail}. The log is not verifiable as it stands "
            f"(verify_chain() returns False). Preserve it, then investigate — "
            f"concurrent appends before this version could produce this "
            f"without tampering."
        )


class AuditContention(Exception):
    """append() lost the race for the chain tip too many times in a row."""


def _entry_hash(prev_hash: str, entry: dict) -> str:
    data = prev_hash + json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()


class AuditLog:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def init_schema(self) -> None:
        """Create the table and the chain-uniqueness index.

        Idempotent, and safe to run against a table created by an earlier
        version — the index is added in place. If that table already contains
        a fork the index cannot be built, and rather than surfacing a raw
        Postgres error this reports where the chain split.
        """
        with self.conn.cursor() as cur:
            cur.execute(AUDIT_SCHEMA)
        self.conn.commit()
        try:
            with self.conn.cursor() as cur:
                cur.execute(AUDIT_CHAIN_INDEX)
            self.conn.commit()
        except psycopg.errors.UniqueViolation:
            self.conn.rollback()
            raise AuditChainForked(self.forks()) from None

    def forks(self) -> list[tuple[str, list[int]]]:
        """Predecessors claimed by more than one entry, with the rows claiming
        them. Empty for an intact chain."""
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT prev_hash, array_agg(seq ORDER BY seq) FROM lethe_audit "
                "GROUP BY prev_hash HAVING count(*) > 1 ORDER BY min(seq)"
            )
            return [(h, list(seqs)) for h, seqs in cur.fetchall()]

    def _last_hash(self) -> str:
        with self.conn.cursor() as cur:
            cur.execute("SELECT entry_hash FROM lethe_audit ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
        return row[0] if row else GENESIS

    def append(self, entry: dict) -> str:
        """Link `entry` onto the chain tip and return its hash.

        Read-tip-then-insert is a race: two writers can read the same tip. The
        unique index on prev_hash means the loser's INSERT is rejected rather
        than committed, so instead of two entries claiming one predecessor we
        get one commit and one retry against the now-advanced tip. Correct
        across processes, which an in-process lock cannot be.

        LIMITATION: this makes concurrent *connections* safe, not one
        connection shared by concurrent threads. On a shared connection the
        transaction is shared too, so the rollback below aborts whatever
        another thread is mid-way through (`InFailedSqlTransaction`), and its
        commit would land this one's work. Give each thread its own
        connection, or serialize — which is what lethe/mcp.py's lock does for
        the MCP server, since it holds exactly one connection.
        """
        for attempt in range(_APPEND_ATTEMPTS):
            prev = self._last_hash()
            h = _entry_hash(prev, entry)
            try:
                with self.conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO lethe_audit (entry, prev_hash, entry_hash) "
                        "VALUES (%s, %s, %s)",
                        (json.dumps(entry), prev, h),
                    )
                self.conn.commit()
                return h
            except psycopg.errors.UniqueViolation:
                # Someone else linked onto this tip first. Roll back, re-read,
                # and link onto theirs — the entry is unchanged, only its
                # position moves.
                self.conn.rollback()
                time.sleep(random.uniform(0, min(
                    _APPEND_BACKOFF_CAP, _APPEND_BACKOFF_BASE * (2 ** attempt)
                )))
        raise AuditContention(
            f"could not append to the audit chain after {_APPEND_ATTEMPTS} attempts; "
            "another writer is advancing the chain faster than this one can follow"
        )

    def anchor_head(self, anchor: "Anchor") -> dict:
        """Timestamp the current chain head with an external authority and
        record the evidence as a chain entry.

        Order matters: the head is read and timestamped FIRST, then the anchor
        entry is appended. So the entry names the head as it stood when the
        authority saw it, and appending advances the chain past that point. An
        entry can never afterwards be inserted at the anchored position — that
        would change every hash from there on and contradict the token.

        The anchoring call happens before any write, so a failing or slow
        authority raises AnchorError and leaves the chain untouched.
        """
        head = self.head()
        result = anchor.anchor(head.encode())
        entry_hash = self.append({
            "event": "anchor",
            "anchored_head": head,
            "authority": result.authority,
            "anchored_at": result.anchored_at,
            "digest": result.digest,
            "digest_algorithm": result.digest_algorithm,
            "policy": result.policy,
            # The raw RFC 3161 response, base64. This is the evidence: it is
            # verifiable by any RFC 3161 implementation with the authority's
            # chain, without Lethe.
            "token": result.token,
        })
        return {
            "anchored_head": head,
            "anchored_at": result.anchored_at,
            "authority": result.authority,
            "entry_hash": entry_hash,
        }

    def entry_by_hash(self, entry_hash: str) -> dict:
        """The entry with this hash. Used to retrieve an anchor's token for
        publishing; the chain stores the evidence, so emitting reads it back
        rather than holding it in memory across the call."""
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT entry FROM lethe_audit WHERE entry_hash = %s", (entry_hash,)
            )
            row = cur.fetchone()
        if row is None:
            raise KeyError(f"no audit entry with hash {entry_hash!r}")
        return dict(row[0])

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
        return expected_head is None or hmac.compare_digest(prev, expected_head)

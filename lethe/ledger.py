import psycopg

from .models import TagRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS lethe_provenance (
    id BIGSERIAL PRIMARY KEY,
    subject_hash TEXT NOT NULL,
    store TEXT NOT NULL,
    namespace TEXT NOT NULL,
    record_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_lethe_provenance_subject
    ON lethe_provenance(subject_hash);

-- Opt-in retention of the record ids a completed forget deleted, so the
-- certificate's "re-verify after valid_until" advice can actually be followed.
-- Kept separate from lethe_provenance so it is never mistaken for live
-- provenance: rows here describe data that is already gone. Off by default —
-- retaining identifiers for a deleted subject is a real privacy cost and is
-- the operator's call, not Lethe's.
CREATE TABLE IF NOT EXISTS lethe_retained_ids (
    id BIGSERIAL PRIMARY KEY,
    subject_hash TEXT NOT NULL,
    request_id TEXT NOT NULL,
    store TEXT NOT NULL,
    namespace TEXT NOT NULL,
    record_id TEXT NOT NULL,
    retained_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_lethe_retained_subject
    ON lethe_retained_ids(subject_hash);
"""


class Ledger:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def init_schema(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute(SCHEMA)
        self.conn.commit()

    def record(self, tag: TagRecord) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO lethe_provenance (subject_hash, store, namespace, record_id) "
                "VALUES (%s, %s, %s, %s)",
                (tag.subject_hash, tag.store, tag.namespace, tag.record_id),
            )
        self.conn.commit()

    def lookup(self, subject_hash: str) -> list[TagRecord]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT subject_hash, store, namespace, record_id FROM lethe_provenance "
                "WHERE subject_hash = %s ORDER BY store, namespace, record_id",
                (subject_hash,),
            )
            return [TagRecord(*row) for row in cur.fetchall()]

    def retain_for_reverification(self, subject_hash: str, request_id: str) -> int:
        """Copy this subject's provenance rows into the retention table before
        purge, so a later re-query can address the same records. Returns rows
        retained. Call only when the operator opted in — see Lethe(
        retain_verification_ids=True)."""
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO lethe_retained_ids "
                "(subject_hash, request_id, store, namespace, record_id) "
                "SELECT subject_hash, %s, store, namespace, record_id "
                "FROM lethe_provenance WHERE subject_hash = %s",
                (request_id, subject_hash),
            )
            n = cur.rowcount
        self.conn.commit()
        return n

    def retained(self, subject_hash: str) -> list[TagRecord]:
        """Record ids kept for re-verification of an already-completed forget."""
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT subject_hash, store, namespace, record_id FROM lethe_retained_ids "
                "WHERE subject_hash = %s ORDER BY store, namespace, record_id",
                (subject_hash,),
            )
            return [TagRecord(*row) for row in cur.fetchall()]

    def purge(self, subject_hash: str) -> int:
        with self.conn.cursor() as cur:
            cur.execute(
                "DELETE FROM lethe_provenance WHERE subject_hash = %s", (subject_hash,)
            )
            n = cur.rowcount
        self.conn.commit()
        return n

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

    def purge(self, subject_hash: str) -> int:
        with self.conn.cursor() as cur:
            cur.execute(
                "DELETE FROM lethe_provenance WHERE subject_hash = %s", (subject_hash,)
            )
            n = cur.rowcount
        self.conn.commit()
        return n

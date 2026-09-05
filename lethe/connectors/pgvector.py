import psycopg
from psycopg import sql

from .base import VerifyResult


class PgVectorConnector:
    name = "pgvector"

    def __init__(self, conn: psycopg.Connection, id_column: str = "id"):
        self.conn = conn
        self.id_column = id_column

    def delete(self, namespace: str, record_ids: list[str]) -> int:
        if not record_ids:
            return 0
        query = sql.SQL("DELETE FROM {tbl} WHERE {col} = ANY(%s)").format(
            tbl=sql.Identifier(namespace), col=sql.Identifier(self.id_column)
        )
        with self.conn.cursor() as cur:
            cur.execute(query, (record_ids,))
            n = cur.rowcount
        self.conn.commit()
        return n

    def verify(self, namespace: str, record_ids: list[str]) -> bool:
        return self.verify_detail(namespace, record_ids).absent

    def verify_detail(self, namespace: str, record_ids: list[str]) -> VerifyResult:
        method = (
            f"pgvector: SELECT count(*) WHERE {self.id_column} = ANY(:ids); "
            f"n_ids={len(record_ids)}"
        )
        if not record_ids:
            return VerifyResult(absent=True, residual_count=0, method=method, index_version=None)
        query = sql.SQL("SELECT count(*) FROM {tbl} WHERE {col} = ANY(%s)").format(
            tbl=sql.Identifier(namespace), col=sql.Identifier(self.id_column)
        )
        with self.conn.cursor() as cur:
            cur.execute(query, (record_ids,))
            row = cur.fetchone()
        # SELECT count(*) always returns exactly one row; treat the impossible
        # empty result as zero residue rather than crashing on None.
        count = 0 if row is None else int(row[0])
        return VerifyResult(
            absent=count == 0, residual_count=count, method=method, index_version=None
        )

    def scan(self, namespace: str, subject_field: str, subject_value: str) -> list[str]:
        """Record ids the table itself holds for this subject.

        Asks the store directly instead of the ledger, so records written
        without passing through Lethe are visible. `subject_field` is the
        column naming the data subject (the same field the wrapper reads as
        `subject_key`); it and `namespace` are quoted as identifiers, never
        interpolated.
        """
        query = sql.SQL("SELECT {col} FROM {tbl} WHERE {subj} = %s").format(
            col=sql.Identifier(self.id_column),
            tbl=sql.Identifier(namespace),
            subj=sql.Identifier(subject_field),
        )
        with self.conn.cursor() as cur:
            cur.execute(query, (subject_value,))
            return [str(row[0]) for row in cur.fetchall()]

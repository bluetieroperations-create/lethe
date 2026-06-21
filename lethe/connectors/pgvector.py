import psycopg
from psycopg import sql


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
        if not record_ids:
            return True
        query = sql.SQL("SELECT count(*) FROM {tbl} WHERE {col} = ANY(%s)").format(
            tbl=sql.Identifier(namespace), col=sql.Identifier(self.id_column)
        )
        with self.conn.cursor() as cur:
            cur.execute(query, (record_ids,))
            (count,) = cur.fetchone()
        return count == 0

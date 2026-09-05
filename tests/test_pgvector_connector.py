import psycopg
import pytest

from lethe.connectors.pgvector import PgVectorConnector


@pytest.fixture
def vectors(conn):
    with conn.cursor() as cur:
        cur.execute("CREATE TABLE test_vectors (id TEXT PRIMARY KEY, body TEXT)")
        cur.executemany(
            "INSERT INTO test_vectors (id, body) VALUES (%s, %s)",
            [("r1", "a"), ("r2", "b"), ("r3", "c")],
        )
    conn.commit()
    return conn


def test_delete_returns_count_and_removes_rows(vectors):
    c = PgVectorConnector(vectors)
    deleted = c.delete("test_vectors", ["r1", "r2"])
    assert deleted == 2
    with vectors.cursor() as cur:
        cur.execute("SELECT id FROM test_vectors")
        remaining = {row[0] for row in cur.fetchall()}
    assert remaining == {"r3"}


def test_verify_true_when_absent(vectors):
    c = PgVectorConnector(vectors)
    c.delete("test_vectors", ["r1"])
    assert c.verify("test_vectors", ["r1"]) is True


def test_verify_false_when_still_present(vectors):
    c = PgVectorConnector(vectors)
    assert c.verify("test_vectors", ["r3"]) is False


def test_empty_ids_are_noops(vectors):
    c = PgVectorConnector(vectors)
    assert c.delete("test_vectors", []) == 0
    assert c.verify("test_vectors", []) is True


def test_namespace_is_safely_quoted(vectors):
    # A malicious namespace must not execute as SQL; it should error as a missing table.
    c = PgVectorConnector(vectors)
    with pytest.raises(psycopg.errors.UndefinedTable):
        c.delete("test_vectors; DROP TABLE test_vectors", ["r1"])
    vectors.rollback()
    with vectors.cursor() as cur:
        cur.execute("SELECT count(*) FROM test_vectors")
        assert cur.fetchone()[0] == 3  # table untouched


def test_scan_finds_records_by_subject_field(conn):
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS owned CASCADE")
        cur.execute("CREATE TABLE owned (id TEXT PRIMARY KEY, owner TEXT)")
        cur.executemany(
            "INSERT INTO owned (id, owner) VALUES (%s, %s)",
            [("a", "u1"), ("b", "u1"), ("c", "u2")],
        )
    conn.commit()
    c = PgVectorConnector(conn)
    assert sorted(c.scan("owned", "owner", "u1")) == ["a", "b"]
    assert c.scan("owned", "owner", "nobody") == []


def test_scan_quotes_identifiers(conn):
    """namespace and subject_field are identifiers, not interpolated text."""
    c = PgVectorConnector(conn)
    with pytest.raises(psycopg.errors.UndefinedTable):
        c.scan("owned; DROP TABLE owned", "owner", "u1")
    conn.rollback()

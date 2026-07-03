import pytest

from lethe.audit import AuditLog
from lethe.certificate import verify_certificate
from lethe.connectors.pgvector import PgVectorConnector
from lethe.core import Lethe
from lethe.ledger import Ledger
from lethe.signing import Signer


@pytest.fixture
def setup(conn):
    with conn.cursor() as cur:
        cur.execute("CREATE TABLE test_vectors (id TEXT PRIMARY KEY, body TEXT)")
        cur.executemany(
            "INSERT INTO test_vectors (id, body) VALUES (%s, %s)",
            [("r1", "a"), ("r2", "b"), ("r3", "c")],
        )
    conn.commit()

    ledger = Ledger(conn)
    ledger.init_schema()
    audit = AuditLog(conn)
    audit.init_schema()
    lethe = Lethe(
        ledger=ledger,
        audit=audit,
        signer=Signer.generate(),
        connectors={"pgvector": PgVectorConnector(conn)},
        salt="test-salt",
    )
    return conn, lethe


def test_forget_deletes_tagged_records_and_returns_valid_certificate(setup):
    conn, lethe = setup
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")
    lethe.tag("user-1", "pgvector", "test_vectors", "r2")
    lethe.tag("user-2", "pgvector", "test_vectors", "r3")

    cert = lethe.forget("user-1", request_id="req-1")

    with conn.cursor() as cur:
        cur.execute("SELECT id FROM test_vectors")
        assert {row[0] for row in cur.fetchall()} == {"r3"}

    assert cert.payload["all_verified"] is True
    assert cert.payload["layers"][0]["deleted_count"] == 2
    assert verify_certificate(cert, lethe.signer.public_key_b64()) is True


def test_forget_writes_audit_entry_and_purges_ledger(setup):
    conn, lethe = setup
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")

    lethe.forget("user-1", request_id="req-1")

    assert lethe.ledger.lookup(lethe._subject_hash("user-1")) == []
    assert lethe.audit.verify_chain() is True
    with conn.cursor() as cur:
        cur.execute("SELECT entry FROM lethe_audit")
        entries = [row[0] for row in cur.fetchall()]
    assert any(e["request_id"] == "req-1" for e in entries)


def test_forget_unknown_subject_is_empty_and_not_certified_as_erasure(setup):
    conn, lethe = setup
    cert = lethe.forget("nobody", request_id="req-x")
    assert cert.payload["layers"] == []
    # Nothing was found, so the certificate must NOT claim a verified erasure.
    # all([]) == True would otherwise let "found nothing" read as "deleted
    # everything" — a false certification (it-auditor C-1/H-2).
    assert cert.payload["all_verified"] is False
    assert cert.payload["layers_found"] == 0
    assert cert.payload["records_deleted"] == 0
    # The signed certificate itself is still internally valid and verifiable.
    assert verify_certificate(cert, lethe.signer.public_key_b64()) is True

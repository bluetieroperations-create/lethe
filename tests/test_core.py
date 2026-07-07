from datetime import timedelta

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


def test_forget_certificate_carries_v2_evidence(setup):
    conn, lethe = setup
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")
    lethe.tag("user-1", "pgvector", "test_vectors", "r2")

    cert = lethe.forget("user-1", request_id="req-1")
    p = cert.payload

    assert p["schema"] == "lethe.cert/2"
    # valid_until is set from issued_at + the validity window, and is after it
    assert p["valid_until"] is not None
    assert p["valid_until"] > p["issued_at"]
    # declared_scope names the configured connectors (the boundary drawn)
    assert p["declared_scope"] == ["pgvector"]
    # verify_detail supplied real evidence: a genuine erasure leaves 0 residual
    layer = p["layers"][0]
    assert layer["residual_count"] == 0
    assert layer["verify_method"] and "pgvector" in layer["verify_method"]
    assert verify_certificate(cert, lethe.signer.public_key_b64()) is True


def test_forget_rejects_non_positive_validity_window(setup):
    """A zero/negative valid_for must not mint a cert whose valid_until is at or
    before issued_at — that is a self-nullifying trust artifact."""
    conn, lethe = setup
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")
    with pytest.raises(ValueError):
        lethe.forget("user-1", request_id="req-1", valid_for=timedelta(0))
    with pytest.raises(ValueError):
        lethe.forget("user-1", request_id="req-2", valid_for=timedelta(days=-1))


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


def test_preview_counts_layers_without_deleting(conn):
    from lethe.audit import AuditLog
    from lethe.core import Lethe
    from lethe.ledger import Ledger
    from lethe.signing import Signer

    ledger = Ledger(conn)
    audit = AuditLog(conn)
    ledger.init_schema()
    audit.init_schema()
    lethe = Lethe(
        ledger=ledger, audit=audit, signer=Signer.generate(),
        connectors={}, salt="test-salt",
    )
    lethe.tag("alice@example.com", "pgvector", "docs", "d1")
    lethe.tag("alice@example.com", "pgvector", "docs", "d2")
    lethe.tag("alice@example.com", "pgvector", "chats", "c1")

    p = lethe.preview("alice@example.com")

    assert p["subject_hash"] == lethe._subject_hash("alice@example.com")
    assert p["layers"] == [
        {"store": "pgvector", "namespace": "chats", "count": 1},
        {"store": "pgvector", "namespace": "docs", "count": 2},
    ]
    # read-only: the ledger still holds all three rows
    assert len(ledger.lookup(p["subject_hash"])) == 3


def test_preview_unknown_subject_is_empty(conn):
    from lethe.audit import AuditLog
    from lethe.core import Lethe
    from lethe.ledger import Ledger
    from lethe.signing import Signer

    ledger = Ledger(conn)
    audit = AuditLog(conn)
    ledger.init_schema()
    audit.init_schema()
    lethe = Lethe(
        ledger=ledger, audit=audit, signer=Signer.generate(),
        connectors={}, salt="test-salt",
    )
    assert lethe.preview("nobody@example.com")["layers"] == []

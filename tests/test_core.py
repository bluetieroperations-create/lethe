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

    assert p["schema"] == "lethe.cert/3"
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


def test_certificate_binds_to_the_audit_chain(setup):
    """audit_head must be the real chain tip this run started from — not an
    arbitrary string — so the certificate and the tamper-evident log point at
    each other and neither can be rewritten alone."""
    conn, lethe = setup
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")

    cert = lethe.forget("user-1", request_id="req-1")
    head = cert.payload["audit_head"]
    assert head is not None

    with conn.cursor() as cur:
        cur.execute("SELECT entry, entry_hash FROM lethe_audit ORDER BY seq ASC")
        rows = cur.fetchall()

    # The cert names the forget_started entry's hash...
    assert rows[0][0]["event"] == "forget_started"
    assert rows[0][1] == head
    # ...and the completion entry chains forward from it carrying the cert hash.
    assert rows[1][0]["event"] == "forget"
    assert rows[1][0]["payload_hash"] == cert.payload_hash
    assert lethe.audit.verify_chain(expected_head=lethe.audit.head()) is True


# --- re-verification after valid_until (opt-in id retention) ---


def _lethe_with_retention(conn):
    return Lethe(
        ledger=Ledger(conn),
        audit=AuditLog(conn),
        signer=Signer.generate(),
        connectors={"pgvector": PgVectorConnector(conn)},
        salt="test-salt",
        retain_verification_ids=True,
    )


def test_default_deployment_is_honestly_not_reverifiable(setup):
    """Default purges the provenance map, so the record ids a re-query needs
    are gone. The certificate must say so rather than advising a re-check it
    cannot support, and reverify() must refuse rather than return a hollow
    'absent' derived from having nothing to check."""
    conn, lethe = setup
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")
    cert = lethe.forget("user-1", request_id="req-1")

    assert cert.payload["reverifiable"] is False
    result = lethe.reverify("user-1")
    assert result["reverifiable"] is False
    assert result["still_absent"] is None
    assert "retain_verification_ids" in result["reason"]


def test_retained_ids_make_reverification_possible(setup):
    conn, _ = setup
    lethe = _lethe_with_retention(conn)
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")
    lethe.tag("user-1", "pgvector", "test_vectors", "r2")

    cert = lethe.forget("user-1", request_id="req-1")
    assert cert.payload["reverifiable"] is True
    assert cert.payload["all_verified"] is True

    result = lethe.reverify("user-1")
    assert result["reverifiable"] is True
    assert result["still_absent"] is True
    assert result["layers"][0]["residual_count"] == 0


def test_reverify_catches_data_that_came_back(setup):
    """The reason valid_until exists: a restored backup or a re-ingest can put
    the subject's records back after a truthful certificate was issued."""
    conn, _ = setup
    lethe = _lethe_with_retention(conn)
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")
    lethe.forget("user-1", request_id="req-1")
    assert lethe.reverify("user-1")["still_absent"] is True

    with conn.cursor() as cur:
        cur.execute("INSERT INTO test_vectors (id, body) VALUES ('r1', 'restored')")
    conn.commit()

    result = lethe.reverify("user-1")
    assert result["still_absent"] is False
    assert result["layers"][0]["residual_count"] == 1


def test_retention_does_not_resurrect_the_provenance_map(setup):
    """Retained ids live in their own table and must never be mistaken for live
    provenance — a second forget must not re-delete from them."""
    conn, _ = setup
    lethe = _lethe_with_retention(conn)
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")
    lethe.forget("user-1", request_id="req-1")

    assert lethe.ledger.lookup(lethe._subject_hash("user-1")) == []
    assert len(lethe.ledger.retained(lethe._subject_hash("user-1"))) == 1
    # Nothing tagged now, so a second forget finds no layers and cannot certify.
    second = lethe.forget("user-1", request_id="req-2")
    assert second.payload["layers_found"] == 0
    assert second.payload["all_verified"] is False

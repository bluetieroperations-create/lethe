"""Adversarial tests for the complete forget loop (it-auditor).

Each test targets one of the catastrophic failure modes from the threat model:
over-deletion, false certification, or silent partial-failure inconsistency.
"""
import pytest

from lethe.audit import AuditLog
from lethe.connectors.pgvector import PgVectorConnector
from lethe.core import Lethe
from lethe.ledger import Ledger
from lethe.signing import Signer


@pytest.fixture
def env(conn):
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

    def make(connectors=None):
        return Lethe(
            ledger=ledger,
            audit=audit,
            signer=Signer.generate(),
            connectors=connectors if connectors is not None
            else {"pgvector": PgVectorConnector(conn)},
            salt="test-salt",
        )

    return conn, ledger, audit, make


# ---------------------------------------------------------------------------
# Angle 4: a tagged row references a store with no configured connector.
# ---------------------------------------------------------------------------
def test_unknown_store_does_not_silently_lose_data_or_skip_certificate(env):
    conn, ledger, audit, make = env
    lethe = make()
    # A real, deletable layer...
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")
    # ...and a layer whose store has NO configured connector.
    lethe.tag("user-1", "qdrant", "some_collection", "x1")

    # The operator runs forget. A missing connector must NOT crash mid-loop after
    # already deleting other layers and leaving no certificate / no audit trail.
    cert = lethe.forget("user-1", request_id="req-unknown-store")

    # The certificate must honestly reflect that not everything was verified.
    assert cert.payload["all_verified"] is False, (
        "unknown store left uncertified but cert claims all_verified"
    )
    # An audit entry must exist for the attempt.
    with conn.cursor() as cur:
        cur.execute("SELECT entry FROM lethe_audit")
        entries = [row[0] for row in cur.fetchall()]
    assert any(e["request_id"] == "req-unknown-store" for e in entries), (
        "data was touched but no audit entry was written"
    )
    # The ledger must NOT be purged while a layer remains unhandled.
    assert ledger.lookup(lethe._subject_hash("user-1")) != [], (
        "ledger purged despite an unhandled layer — retry impossible"
    )


# ---------------------------------------------------------------------------
# Angle 2: empty layers => all([]) => True. An unknown subject yields a cert
# with all_verified:true and zero layers, indistinguishable from a real erasure.
# ---------------------------------------------------------------------------
def test_unknown_subject_is_not_certified_as_a_successful_erasure(env):
    conn, ledger, audit, make = env
    lethe = make()
    cert = lethe.forget("ghost", request_id="req-ghost")

    # With nothing found, the cert must not claim a verified erasure.
    assert cert.payload["all_verified"] is False, (
        "found-nothing forget falsely certified as all_verified:true"
    )


# ---------------------------------------------------------------------------
# Angle 3 / partial failure: audit.append raises AFTER connector.delete commits.
# Data is already gone; the operator gets an exception. The system must not be
# left having destroyed data with no certificate AND a stale ledger that, on a
# blind retry, would now report deleted_count:0 + all_verified:true (a false cert).
# ---------------------------------------------------------------------------
def test_audit_failure_after_delete_does_not_yield_a_later_false_certificate(env):
    conn, ledger, audit, make = env
    lethe = make()
    lethe.tag("user-1", "pgvector", "test_vectors", "r1")

    # Make the audit append blow up after the delete has committed. The
    # pre-flight forget_started event must be let through: this test targets
    # the window where the delete is already committed but the COMPLETION
    # audit entry cannot be written.
    real_append = AuditLog.append.__get__(audit)

    def boom(entry):
        if entry.get("event") == "forget":
            raise RuntimeError("audit backend down")
        return real_append(entry)

    audit.append = boom  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        lethe.forget("user-1", request_id="req-1")

    # The delete already committed (connector commits independently), so r1 is gone.
    conn.rollback()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM test_vectors")
        remaining = {row[0] for row in cur.fetchall()}
    data_gone = "r1" not in remaining

    # Restore a working audit and retry exactly as an operator would.
    audit.append = AuditLog.append.__get__(audit)  # type: ignore[method-assign]
    cert2 = lethe.forget("user-1", request_id="req-1-retry")

    if data_gone:
        # The retried certificate must not present deleted_count:0 as a clean,
        # fully-verified erasure with no record that the data ever existed.
        # If the ledger still has the row, deleted_count:0 + all_verified is a
        # FALSE certificate: it claims "deleted & verified absent" for a layer
        # this run never actually deleted.
        assert not (
            cert2.payload["all_verified"]
            and all(lyr["deleted_count"] == 0 for lyr in cert2.payload["layers"])
            and cert2.payload["layers"]
        ), "retry produced a verified cert with zero real deletions (false certification)"


# ---------------------------------------------------------------------------
# Angle 1 (CATASTROPHIC): two subjects share the same vector row. forget(A)
# physically deletes the shared row; a later forget(B) then certifies B's data
# as "deleted & verified absent" with deleted_count:0 — i.e. it falsely claims
# to have erased data on B's behalf when in fact A's request already destroyed
# it and B was never the one who triggered/verified its removal. The deeper
# problem: forget(A) over-deletes data that another live subject still claims.
# ---------------------------------------------------------------------------
def test_shared_record_id_forget_does_not_falsely_certify_other_subject(env):
    conn, ledger, audit, make = env
    lethe = make()

    # Same physical row r1 is tagged to BOTH subjects (legitimate: one chat turn
    # mentions two people, both later request erasure).
    lethe.tag("alice", "pgvector", "test_vectors", "r1")
    lethe.tag("bob", "pgvector", "test_vectors", "r1")

    # Alice exercises her right to be forgotten first.
    cert_a = lethe.forget("alice", request_id="req-alice")
    assert cert_a.payload["all_verified"] is True
    assert cert_a.payload["layers"][0]["deleted_count"] == 1

    # The physical row is now gone.
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM test_vectors WHERE id = 'r1'")
        assert cur.fetchone()[0] == 0

    # Now Bob exercises HIS right. Lethe deletes nothing (already gone) but
    # certifies all_verified:true with deleted_count:0. That certificate is
    # handed to a regulator as proof Lethe erased Bob's data. It did not — it
    # found nothing to erase. A deleted_count:0 layer must not be presented as a
    # verified deletion Lethe performed for Bob.
    cert_b = lethe.forget("bob", request_id="req-bob")
    layer_b = cert_b.payload["layers"][0]
    assert not (
        cert_b.payload["all_verified"] and layer_b["deleted_count"] == 0
    ), (
        "Bob certified as 'deleted & verified absent' with zero actual deletions "
        "— Lethe certifies an erasure it did not perform"
    )


def test_a_forget_survives_an_audit_append_losing_the_race(env):
    """append() rolls back on a lost race before retrying, and it shares the
    caller's connection — so if a forget's deletions were still uncommitted at
    that point, the rollback would silently undo them and the retry would then
    record a deletion that no longer existed.

    They are not: the connector and the ledger each commit as they go. This
    pins that, because the invariant lives in three files and nothing else
    states it. Removing the commit from PgVectorConnector.delete() fails here.
    """
    conn, ledger, audit, make = env
    lethe = make()
    for rid in ("r1", "r2", "r3"):
        lethe.tag("alice@example.test", "pgvector", "test_vectors", rid)

    # Force the completion append to lose exactly once: hand it a prev_hash
    # that is already taken, which guarantees the UniqueViolation → rollback →
    # retry path runs on the same connection the deletes used.
    real_last_hash = audit._last_hash
    forced = []

    def stale_tip():
        if not forced:
            with conn.cursor() as cur:
                cur.execute("SELECT prev_hash FROM lethe_audit ORDER BY seq DESC LIMIT 1")
                row = cur.fetchone()
            if row:
                forced.append(True)
                return row[0]
        return real_last_hash()

    audit._last_hash = stale_tip
    try:
        cert = lethe.forget("alice@example.test")
    finally:
        audit._last_hash = real_last_hash

    assert forced, "the conflict path never ran; this test proved nothing"
    assert cert.payload["all_verified"] is True
    assert cert.payload["records_deleted"] == 3

    # The deletions survived the rollback.
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM test_vectors")
        assert cur.fetchone()[0] == 0
    assert audit.verify_chain() is True


def test_a_deletion_that_outruns_the_audit_chain_says_the_rows_are_gone(env):
    """If the completion append exhausts its retries, the rows are ALREADY
    deleted. A bare "could not append" reads as "the forget failed", and the
    operator retries a deletion that has in fact completed — finding nothing
    the second time and concluding, wrongly, that nothing was ever deleted.

    The error has to say the deletion happened, and carry the certificate,
    which at that point is the only record of the run outside the chain.
    """
    import pytest

    from lethe.audit import AuditContention
    from lethe.core import ForgetRecordedIncompletely

    conn, ledger, audit, make = env
    lethe = make()
    for rid in ("r1", "r2", "r3"):
        lethe.tag("alice@example.test", "pgvector", "test_vectors", rid)

    real_append = audit.append
    calls = {"n": 0}

    def append(entry):
        calls["n"] += 1
        if entry.get("event") == "forget":       # the completion entry only
            raise AuditContention("another writer is advancing the chain")
        return real_append(entry)

    audit.append = append
    try:
        with pytest.raises(ForgetRecordedIncompletely) as e:
            lethe.forget("alice@example.test")
    finally:
        audit.append = real_append

    message = str(e.value)
    assert "deletion COMPLETED" in message
    assert "Do not re-run it" in message
    assert e.value.certificate.payload["records_deleted"] == 3

    # The rows really are gone, so the message is telling the truth.
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM test_vectors")
        assert cur.fetchone()[0] == 0
    # And forget_started is on the chain, recording that the run began.
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM lethe_audit WHERE entry->>'event' = 'forget_started'")
        assert cur.fetchone()[0] == 1

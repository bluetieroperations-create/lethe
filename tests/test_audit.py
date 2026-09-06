import pytest

from lethe.audit import GENESIS as GENESIS_FOR_TEST
from lethe.audit import AuditLog


def test_append_and_chain_verifies(conn):
    log = AuditLog(conn)
    log.init_schema()
    log.append({"event": "forget", "request_id": "r1"})
    log.append({"event": "forget", "request_id": "r2"})
    assert log.verify_chain() is True


def test_tampering_with_an_entry_breaks_the_chain(conn):
    log = AuditLog(conn)
    log.init_schema()
    log.append({"event": "forget", "request_id": "r1"})
    log.append({"event": "forget", "request_id": "r2"})

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE lethe_audit SET entry = %s WHERE seq = 1",
            ('{"event": "forget", "request_id": "TAMPERED"}',),
        )
    conn.commit()

    assert log.verify_chain() is False


def test_empty_log_verifies(conn):
    log = AuditLog(conn)
    log.init_schema()
    assert log.verify_chain() is True


def test_tip_truncation_is_detected_when_head_is_pinned(conn):
    """Deleting the most recent entries leaves a self-consistent shorter chain
    that verify_chain() alone cannot distinguish from a legitimately shorter log.
    An operator who records the head hash out-of-band (like the certificate's
    pinned public key) must be able to detect that the tail was lopped off
    (it-auditor H-1: tamper-evident log truncation)."""
    log = AuditLog(conn)
    log.init_schema()
    log.append({"event": "forget", "request_id": "r1"})
    log.append({"event": "forget", "request_id": "r2"})
    head = log.append({"event": "forget", "request_id": "r3"})

    # Operator's recorded tip matches.
    assert log.verify_chain(expected_head=head) is True

    # Attacker truncates the tip to erase evidence of the most recent erasure(s).
    with conn.cursor() as cur:
        cur.execute("DELETE FROM lethe_audit WHERE seq >= 2")
    conn.commit()

    # Unanchored verify still (wrongly) passes — that's the inherent limit.
    assert log.verify_chain() is True
    # Pinned to the real head, truncation is caught.
    assert log.verify_chain(expected_head=head) is False


def test_pinned_head_on_empty_log(conn):
    log = AuditLog(conn)
    log.init_schema()
    # No entries: the head is the genesis sentinel; pinning to it verifies.
    from lethe.audit import GENESIS

    assert log.verify_chain(expected_head=GENESIS) is True
    assert log.verify_chain(expected_head="deadbeef") is False


# --- chain uniqueness -------------------------------------------------------
#
# append() reads the tip, hashes it, and inserts. Two writers that read the
# same tip would otherwise both commit and leave two entries claiming one
# predecessor. This is not an MCP-only concern: every CLI command opens its
# own connection, and docs/anchoring.md tells operators to run `lethe anchor`
# hourly on a timer, so a cron anchor overlapping an operator's `lethe forget`
# is the documented deployment. No in-process lock reaches across processes.


def _concurrent_appends(dsn, count, *, per_connection=True):
    """Append `count` entries at once. Each writer gets its own connection by
    default, which is what models separate processes."""
    import threading

    import psycopg

    from lethe.audit import AuditLog

    errors = []

    def worker(i):
        try:
            with psycopg.connect(dsn) as own:
                AuditLog(own).append({"event": "forget", "n": i})
        except Exception as exc:  # noqa: BLE001 — recorded, asserted on below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def test_concurrent_appends_across_connections_keep_the_chain_intact(conn):
    """The property the unique index buys. Before it, 8 concurrent appends
    produced 8 entries with 4 distinct prev_hash values and verify_chain()
    returning False — the log accusing its own operator of tampering."""
    import os

    log = AuditLog(conn)
    log.init_schema()

    errors = _concurrent_appends(os.environ["LETHE_TEST_DATABASE_URL"], 16)
    assert errors == []

    assert log.verify_chain() is True
    assert log.forks() == []
    with conn.cursor() as cur:
        cur.execute("SELECT count(*), count(DISTINCT prev_hash) FROM lethe_audit")
        entries, distinct_prev = cur.fetchone()
    # Every entry recorded, each linking to a distinct predecessor.
    assert entries == 16
    assert distinct_prev == 16


def test_a_losing_append_retries_rather_than_dropping_the_entry(conn):
    """Retrying without backoff makes collided writers collide again in
    lockstep: measured at 24 writers, 5 exhausted their attempts and their
    entries were never recorded. The chain stayed intact, but a forget with no
    audit entry is its own hole."""
    import os

    log = AuditLog(conn)
    log.init_schema()

    errors = _concurrent_appends(os.environ["LETHE_TEST_DATABASE_URL"], 32)
    assert errors == [], f"writers lost their entries: {errors[:3]}"
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM lethe_audit")
        assert cur.fetchone()[0] == 32
    assert log.verify_chain() is True


def test_the_database_refuses_a_second_entry_claiming_the_same_predecessor(conn):
    """The constraint itself, without concurrency: a fork cannot be written
    even by a caller going around append()."""
    import psycopg

    log = AuditLog(conn)
    log.init_schema()
    log.append({"event": "forget", "n": 1})

    with conn.cursor() as cur:
        cur.execute("SELECT prev_hash FROM lethe_audit ORDER BY seq LIMIT 1")
        taken = cur.fetchone()[0]

    with pytest.raises(psycopg.errors.UniqueViolation), conn.cursor() as cur:
        cur.execute(
            "INSERT INTO lethe_audit (entry, prev_hash, entry_hash) "
            "VALUES (%s, %s, %s)",
            ('{"event": "forged"}', taken, "f" * 64),
        )
    conn.rollback()


def test_init_schema_on_an_already_forked_chain_says_where_it_split(conn):
    """Upgrading a table written by an earlier version cannot build the index
    if that chain already forked. That must not surface as a raw Postgres
    error: the operator needs to know the log is unverifiable and where."""
    from lethe.audit import AUDIT_SCHEMA, AuditChainForked

    # A table from before the constraint existed, carrying a fork.
    with conn.cursor() as cur:
        cur.execute(AUDIT_SCHEMA)
        for entry_hash in ("a" * 64, "b" * 64):
            cur.execute(
                "INSERT INTO lethe_audit (entry, prev_hash, entry_hash) "
                "VALUES (%s, %s, %s)",
                ('{"event": "forget"}', GENESIS_FOR_TEST, entry_hash),
            )
    conn.commit()

    log = AuditLog(conn)
    assert log.verify_chain() is False  # already unverifiable
    assert log.forks() == [(GENESIS_FOR_TEST, [1, 2])]

    with pytest.raises(AuditChainForked) as e:
        log.init_schema()
    assert "seq [1, 2]" in str(e.value)
    assert "verify_chain() returns False" in str(e.value)
    # The rows are left alone — evidence, not something to clean up silently.
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM lethe_audit")
        assert cur.fetchone()[0] == 2


def test_init_schema_is_idempotent_and_upgrades_an_intact_chain(conn):
    """The ordinary upgrade: a pre-constraint table with a healthy chain gains
    the index in place, and running it again changes nothing."""
    from lethe.audit import AUDIT_SCHEMA

    with conn.cursor() as cur:
        cur.execute(AUDIT_SCHEMA)
    conn.commit()
    log = AuditLog(conn)
    log.append({"event": "forget", "n": 1})   # written before the index exists
    log.init_schema()                          # upgrade
    log.init_schema()                          # again
    log.append({"event": "forget", "n": 2})
    assert log.verify_chain() is True
    assert log.forks() == []

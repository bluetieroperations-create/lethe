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

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

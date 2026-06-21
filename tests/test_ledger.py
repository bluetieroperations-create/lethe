from lethe.ledger import Ledger
from lethe.models import TagRecord


def test_record_and_lookup(conn):
    ledger = Ledger(conn)
    ledger.init_schema()
    ledger.record(TagRecord("subjA", "pgvector", "docs", "r1"))
    ledger.record(TagRecord("subjA", "pgvector", "docs", "r2"))
    ledger.record(TagRecord("subjB", "pgvector", "docs", "r9"))

    rows = ledger.lookup("subjA")
    assert {r.record_id for r in rows} == {"r1", "r2"}
    assert all(r.store == "pgvector" for r in rows)


def test_lookup_unknown_subject_is_empty(conn):
    ledger = Ledger(conn)
    ledger.init_schema()
    assert ledger.lookup("nobody") == []


def test_purge_removes_only_that_subject(conn):
    ledger = Ledger(conn)
    ledger.init_schema()
    ledger.record(TagRecord("subjA", "pgvector", "docs", "r1"))
    ledger.record(TagRecord("subjB", "pgvector", "docs", "r9"))

    purged = ledger.purge("subjA")
    assert purged == 1
    assert ledger.lookup("subjA") == []
    assert len(ledger.lookup("subjB")) == 1

"""The reason to pay for this.

Lethe's audit chain cannot detect tip-truncation on its own: dropping the most
recent entries leaves a shorter chain that is perfectly self-consistent, and
verify_chain() still returns VALID. docs/anchoring.md says the only fix is a
copy of the head living somewhere the operator cannot reach.

This test is that claim, executed: a real forget against a real database, a
real notarization, then the operator drops the entries — and the notary's log
convicts them.
"""

import json
import os

import psycopg
import pytest
from lethe_notary.service import create_app
from starlette.testclient import TestClient

from lethe.audit import AuditLog
from lethe.connectors.pgvector import PgVectorConnector
from lethe.core import Lethe
from lethe.ledger import Ledger
from lethe.signing import Signer

DATABASE_URL = os.environ.get("LETHE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="set LETHE_TEST_DATABASE_URL to run the live-chain test"
)


@pytest.fixture
def conn():
    with psycopg.connect(DATABASE_URL) as c:
        with c.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS lethe_audit, lethe_provenance,"
                        " lethe_retained_ids, notary_docs CASCADE")
            cur.execute("CREATE TABLE notary_docs (id TEXT PRIMARY KEY, body TEXT)")
            cur.executemany("INSERT INTO notary_docs VALUES (%s, %s)",
                            [(f"d{i}", "x") for i in range(6)])
        c.commit()
        yield c


def test_the_notary_catches_a_truncated_chain(conn, notary_signer, log, free_config):
    operator = Signer.generate()
    audit = AuditLog(conn)
    audit.init_schema()
    ledger = Ledger(conn)
    ledger.init_schema()
    lethe = Lethe(ledger=ledger, audit=audit, signer=operator,
                  connectors={"pgvector": PgVectorConnector(conn)}, salt="s" * 32)

    client = TestClient(create_app(signer=notary_signer, log=log, config=free_config))

    # Three real deletions, each notarized as it happens.
    for i in range(3):
        lethe.tag(f"subject{i}@example.test", "pgvector", "notary_docs", f"d{i}")
        cert = lethe.forget(f"subject{i}@example.test")
        envelope = {"payload": cert.payload, "payload_hash": cert.payload_hash,
                    "signature": cert.signature, "public_key": cert.public_key}
        assert client.post("/notarize", content=json.dumps(envelope)).json()["ok"]

    assert audit.verify_chain() is True
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM lethe_audit")
        before = cur.fetchone()[0]

    # The operator now destroys the evidence of the most recent deletion.
    with conn.cursor() as cur:
        cur.execute("DELETE FROM lethe_audit WHERE seq IN ("
                    "  SELECT seq FROM lethe_audit ORDER BY seq DESC LIMIT 2)")
    conn.commit()

    # Lethe alone cannot tell. The shortened chain is entirely self-consistent:
    # this is exactly the hole the notary is sold to fill.
    assert audit.verify_chain() is True, "truncation is undetectable from inside"
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM lethe_audit")
        assert cur.fetchone()[0] < before

    # The notary can. Every head it witnessed must still be in the chain.
    nonce = client.get("/challenge").json()["nonce"]
    witnessed = client.post("/witness", content=json.dumps({
        "public_key": operator.public_key_b64(), "nonce": nonce,
        "signature": operator.sign(nonce.encode()),
    })).json()["witnessed"]

    with conn.cursor() as cur:
        cur.execute("SELECT entry_hash FROM lethe_audit")
        surviving = {r[0] for r in cur.fetchall()}

    missing = [w for w in witnessed if w["audit_head"] not in surviving]
    assert len(witnessed) == 3
    assert missing, "the notary failed to notice the operator dropped entries"


def test_an_intact_chain_produces_no_accusation(conn, notary_signer, log, free_config):
    """The control. A notary that cries truncation on an honest chain is worse
    than useless — it would make every customer look guilty."""
    operator = Signer.generate()
    audit = AuditLog(conn)
    audit.init_schema()
    ledger = Ledger(conn)
    ledger.init_schema()
    lethe = Lethe(ledger=ledger, audit=audit, signer=operator,
                  connectors={"pgvector": PgVectorConnector(conn)}, salt="s" * 32)
    client = TestClient(create_app(signer=notary_signer, log=log, config=free_config))

    for i in range(3):
        lethe.tag(f"subject{i}@example.test", "pgvector", "notary_docs", f"d{i}")
        cert = lethe.forget(f"subject{i}@example.test")
        client.post("/notarize", content=json.dumps(
            {"payload": cert.payload, "payload_hash": cert.payload_hash,
             "signature": cert.signature, "public_key": cert.public_key}))

    nonce = client.get("/challenge").json()["nonce"]
    witnessed = client.post("/witness", content=json.dumps({
        "public_key": operator.public_key_b64(), "nonce": nonce,
        "signature": operator.sign(nonce.encode()),
    })).json()["witnessed"]

    with conn.cursor() as cur:
        cur.execute("SELECT entry_hash FROM lethe_audit")
        surviving = {r[0] for r in cur.fetchall()}

    assert [w for w in witnessed if w["audit_head"] not in surviving] == []

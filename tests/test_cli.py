import json
import os

from click.testing import CliRunner

from lethe.cli import cli

DATABASE_URL = os.environ.get("LETHE_TEST_DATABASE_URL")


def _operator_pubkey(key_file):
    from lethe.signing import Signer

    return Signer.from_private_bytes(key_file.read_bytes()).public_key_b64()


def test_keygen_init_forget_verify(conn, tmp_path):
    if not DATABASE_URL:
        import pytest

        pytest.skip("needs LETHE_TEST_DATABASE_URL")

    with conn.cursor() as cur:
        cur.execute("CREATE TABLE test_vectors (id TEXT PRIMARY KEY, body TEXT)")
        cur.execute("INSERT INTO test_vectors (id, body) VALUES ('r1', 'a')")
    conn.commit()

    runner = CliRunner()
    key_file = tmp_path / "key.bin"
    cert_file = tmp_path / "cert.json"

    r = runner.invoke(cli, ["keygen", "--out", str(key_file)])
    assert r.exit_code == 0
    assert key_file.exists()

    r = runner.invoke(cli, ["init-db", "--database-url", DATABASE_URL])
    assert r.exit_code == 0

    from lethe.hashing import hash_subject
    from lethe.ledger import Ledger
    from lethe.models import TagRecord

    Ledger(conn).record(
        TagRecord(hash_subject("user-1", "s"), "pgvector", "test_vectors", "r1")
    )

    r = runner.invoke(
        cli,
        ["forget", "user-1", "--database-url", DATABASE_URL,
         "--salt", "s", "--key-file", str(key_file)],
    )
    assert r.exit_code == 0
    cert_file.write_text(r.output)

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM test_vectors")
        assert cur.fetchone()[0] == 0

    pub = _operator_pubkey(key_file)
    r = runner.invoke(cli, ["verify", str(cert_file), "--public-key", pub])
    assert r.exit_code == 0
    assert "VALID" in r.output


def test_verify_rejects_tampered_certificate(tmp_path):
    runner = CliRunner()
    key_file = tmp_path / "key.bin"
    runner.invoke(cli, ["keygen", "--out", str(key_file)])

    from lethe.certificate import build_certificate
    from lethe.signing import Signer

    signer = Signer.from_private_bytes(key_file.read_bytes())
    cert = build_certificate(
        request_id="r", subject_hash="s", layers=[],
        issued_at="2026-06-21T00:00:00+00:00", version="0.1.0", signer=signer,
    )
    bad = {
        "payload": {**cert.payload, "subject_hash": "tampered"},
        "payload_hash": cert.payload_hash,
        "signature": cert.signature,
        "public_key": cert.public_key,
    }
    cert_file = tmp_path / "bad.json"
    cert_file.write_text(json.dumps(bad))

    pub = _operator_pubkey(key_file)
    r = runner.invoke(cli, ["verify", str(cert_file), "--public-key", pub])
    assert r.exit_code == 1
    assert "INVALID" in r.output


def test_audit_head_and_verify_audit_detect_truncation(conn):
    if not DATABASE_URL:
        import pytest

        pytest.skip("needs LETHE_TEST_DATABASE_URL")
    from lethe.audit import AuditLog

    runner = CliRunner()
    assert runner.invoke(cli, ["init-db", "--database-url", DATABASE_URL]).exit_code == 0

    log = AuditLog(conn)
    log.append({"event": "forget", "request_id": "a1"})
    log.append({"event": "forget", "request_id": "a2"})

    # audit-head prints the current recorded tip.
    r = runner.invoke(cli, ["audit-head", "--database-url", DATABASE_URL])
    assert r.exit_code == 0
    head = r.output.strip()

    # Pinned to the real head -> VALID.
    r = runner.invoke(
        cli, ["verify-audit", "--database-url", DATABASE_URL, "--expected-head", head]
    )
    assert r.exit_code == 0
    assert "VALID" in r.output

    # Attacker lops off the most recent entry; pinned verify catches it.
    with conn.cursor() as cur:
        cur.execute("DELETE FROM lethe_audit WHERE seq >= 2")
    conn.commit()
    r = runner.invoke(
        cli, ["verify-audit", "--database-url", DATABASE_URL, "--expected-head", head]
    )
    assert r.exit_code == 1
    assert "INVALID" in r.output


def test_verify_audit_names_a_fork_rather_than_only_saying_invalid(conn):
    """INVALID alone cannot be acted on. A fork and a tampered entry are very
    different situations, and an operator upgrading a chain written before
    v0.7.0 who reads "INVALID" as "we were breached" has been told the wrong
    thing. The output must distinguish them."""
    from lethe.audit import AUDIT_SCHEMA, GENESIS, AuditLog

    # A chain from before the uniqueness constraint, carrying a fork.
    with conn.cursor() as cur:
        cur.execute(AUDIT_SCHEMA)
        for entry_hash in ("a" * 64, "b" * 64):
            cur.execute(
                "INSERT INTO lethe_audit (entry, prev_hash, entry_hash) "
                "VALUES (%s, %s, %s)",
                ('{"event": "forget"}', GENESIS, entry_hash),
            )
    conn.commit()
    assert AuditLog(conn).verify_chain() is False

    result = CliRunner().invoke(
        cli, ["verify-audit", "--database-url", DATABASE_URL]
    )
    assert result.exit_code == 1
    assert result.stdout.strip().endswith("INVALID")
    # ...and says which rows forked, and that concurrency explains it.
    assert "FORK: rows [1, 2]" in result.stderr
    assert GENESIS in result.stderr
    assert "without tampering" in result.stderr


def test_verify_audit_on_an_intact_chain_reports_no_fork(conn):
    """The control: a healthy chain must not emit a fork warning."""
    from lethe.audit import AuditLog

    log = AuditLog(conn)
    log.init_schema()
    for i in range(3):
        log.append({"event": "forget", "n": i})

    result = CliRunner().invoke(
        cli, ["verify-audit", "--database-url", DATABASE_URL]
    )
    assert result.exit_code == 0
    assert result.stdout.strip().endswith("VALID")
    assert "FORK" not in result.stderr

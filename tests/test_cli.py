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

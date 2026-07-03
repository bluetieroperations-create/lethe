"""Handler-level tests: real Ledger/AuditLog on the test DB, fake vector store.
The MCP transport layer is tested separately (registration + e2e)."""

import pytest

from lethe.audit import AuditLog
from lethe.cert_schema import schema_errors
from lethe.core import Lethe
from lethe.guard import ConfirmGuard
from lethe.ledger import Ledger
from lethe.mcp import (
    ServerContext,
    h_forget,
    h_forget_preview,
    h_status,
    h_tag,
    h_verify_certificate,
    h_verify_subject,
)
from lethe.signing import Signer


class FakeStore:
    """In-memory Connector: delete/verify by (namespace, id)."""

    def __init__(self):
        self.rows: dict[tuple[str, str], str] = {}

    def seed(self, namespace, ids):
        for i in ids:
            self.rows[(namespace, i)] = "data"

    def delete(self, namespace, ids):
        n = 0
        for i in ids:
            if (namespace, i) in self.rows:
                del self.rows[(namespace, i)]
                n += 1
        return n

    def verify(self, namespace, ids):
        return all((namespace, i) not in self.rows for i in ids)


class FailingStore(FakeStore):
    """Delete always blows up mid-flight (connector outage)."""

    def delete(self, namespace, ids):
        raise RuntimeError("connector outage")


@pytest.fixture
def ctx(conn):
    ledger = Ledger(conn)
    audit = AuditLog(conn)
    ledger.init_schema()
    audit.init_schema()
    store = FakeStore()
    signer = Signer.generate()
    lethe = Lethe(
        ledger=ledger, audit=audit, signer=signer,
        connectors={"fake": store}, salt="test-salt",
    )
    c = ServerContext(
        lethe=lethe, guard=ConfirmGuard(), trusted_public_key=signer.public_key_b64()
    )
    c.fake_store = store  # test-only convenience
    return c


def _seed_alice(ctx):
    ctx.fake_store.seed("docs", ["d1", "d2"])
    h_tag(ctx, "alice@x.com", "fake", "docs", "d1")
    h_tag(ctx, "alice@x.com", "fake", "docs", "d2")


def test_status_full_mode(ctx):
    r = h_status(ctx)
    assert r["ok"] is True
    assert r["mode"] == "full"
    assert r["connectors"] == ["fake"]
    assert r["cert_schema"] == "lethe.cert/1"


def test_preview_unknown_subject(ctx):
    r = h_forget_preview(ctx, "nobody@x.com")
    assert r["ok"] is False
    assert r["error"]["code"] == "SUBJECT_NOT_FOUND"


def test_preview_returns_counts_and_token(ctx):
    _seed_alice(ctx)
    r = h_forget_preview(ctx, "alice@x.com")
    assert r["ok"] is True
    assert r["layers"] == [{"store": "fake", "namespace": "docs", "count": 2}]
    assert r["confirm_token"].startswith("v1.")


def test_forget_without_valid_token(ctx):
    _seed_alice(ctx)
    r = h_forget(ctx, "alice@x.com", "garbage-token")
    assert r["ok"] is False
    assert r["error"]["code"] == "TOKEN_INVALID"
    # nothing deleted
    assert ("docs", "d1") in ctx.fake_store.rows


def test_forget_happy_path_returns_valid_cert(ctx):
    _seed_alice(ctx)
    token = h_forget_preview(ctx, "alice@x.com")["confirm_token"]
    r = h_forget(ctx, "alice@x.com", token)
    assert r["ok"] is True
    assert r["all_verified"] is True
    assert r["records_deleted"] == 2
    assert schema_errors(r["certificate"]) == []
    assert ctx.fake_store.rows == {}


def test_forget_stale_preview_when_data_grows(ctx):
    _seed_alice(ctx)
    token = h_forget_preview(ctx, "alice@x.com")["confirm_token"]
    ctx.fake_store.seed("docs", ["d3"])
    h_tag(ctx, "alice@x.com", "fake", "docs", "d3")
    r = h_forget(ctx, "alice@x.com", token)
    assert r["ok"] is False
    assert r["error"]["code"] == "STALE_PREVIEW"


def test_forget_failure_after_consume_burns_token(ctx, conn):
    """Connector dies mid-delete AFTER the token is consumed: the delete
    reports CONNECTOR_ERROR (retriable), and the SAME token is burned —
    retrying with it yields TOKEN_REUSED; the agent must re-preview."""
    failing = FailingStore()
    failing.seed("docs", ["d1"])
    ctx.lethe.connectors["failing"] = failing
    h_tag(ctx, "bob@x.com", "failing", "docs", "d1")
    token = h_forget_preview(ctx, "bob@x.com")["confirm_token"]
    r = h_forget(ctx, "bob@x.com", token)
    assert r["ok"] is False
    assert r["error"]["code"] == "CONNECTOR_ERROR"
    assert r["error"]["retriable"] is True
    r2 = h_forget(ctx, "bob@x.com", token)
    assert r2["error"]["code"] == "TOKEN_REUSED"
    # fresh preview still works and yields a usable new token
    assert h_forget_preview(ctx, "bob@x.com")["ok"] is True


def test_verify_subject_before_and_after(ctx):
    _seed_alice(ctx)
    before = h_verify_subject(ctx, "alice@x.com")
    assert before["ok"] is True
    assert before["layers"][0]["verified_absent"] is False
    token = h_forget_preview(ctx, "alice@x.com")["confirm_token"]
    h_forget(ctx, "alice@x.com", token)
    after = h_verify_subject(ctx, "alice@x.com")
    assert after["ok"] is True
    assert after["layers"] == []  # ledger purged after verified forget


def test_verify_certificate_handler(ctx):
    _seed_alice(ctx)
    token = h_forget_preview(ctx, "alice@x.com")["confirm_token"]
    cert = h_forget(ctx, "alice@x.com", token)["certificate"]
    r = h_verify_certificate(ctx, cert)  # pinned via ctx.trusted_public_key
    assert r["ok"] is True
    assert r["valid"] is True
    r2 = h_verify_certificate(ctx, cert, public_key=Signer.generate().public_key_b64())
    assert r2["valid"] is False
    assert r2["reasons"] == ["KEY_MISMATCH"]


def test_verify_certificate_size_guard(ctx):
    _seed_alice(ctx)
    token = h_forget_preview(ctx, "alice@x.com")["confirm_token"]
    cert = h_forget(ctx, "alice@x.com", token)["certificate"]
    # layer-count bomb: rejected BEFORE schema validation burns CPU
    bomb = dict(cert)
    bomb["payload"] = dict(cert["payload"])
    bomb["payload"]["layers"] = [dict(cert["payload"]["layers"][0]) for _ in range(1001)]
    r = h_verify_certificate(ctx, bomb)
    assert r["ok"] is False
    assert r["error"]["code"] == "CERTIFICATE_TOO_LARGE"
    # byte bomb
    blob = dict(cert)
    blob["payload"] = dict(cert["payload"])
    blob["payload"]["claim"] = "x" * 300_000
    r2 = h_verify_certificate(ctx, blob)
    assert r2["ok"] is False
    assert r2["error"]["code"] == "CERTIFICATE_TOO_LARGE"


def test_verify_only_context_refuses_writes():
    ctx = ServerContext(lethe=None, guard=None, trusted_public_key=None)
    assert h_status(ctx)["mode"] == "verify-only"
    r = h_tag(ctx, "a@x.com", "fake", "docs", "d1")
    assert r["error"]["code"] == "NO_LAYERS_CONFIGURED"
    r = h_verify_certificate(ctx, {})
    assert r["error"]["code"] == "KEY_MISMATCH"  # no pin available at all


def test_verify_subject_connector_crash_returns_internal_envelope(ctx):
    class ExplodingStore(FakeStore):
        def verify(self, namespace, ids):
            raise RuntimeError("boom")
    exploding = ExplodingStore()
    exploding.seed("docs", ["d1"])
    ctx.lethe.connectors["exploding"] = exploding
    h_tag(ctx, "carol@x.com", "exploding", "docs", "d1")
    r = h_verify_subject(ctx, "carol@x.com")
    assert r["ok"] is False
    assert r["error"]["code"] == "INTERNAL"
    assert "boom" not in r["error"]["message"]  # no raw exception text


def test_verify_subject_unconfigured_store_is_handled_false(ctx):
    h_tag(ctx, "dave@x.com", "ghost", "docs", "d1")
    r = h_verify_subject(ctx, "dave@x.com")
    assert r["ok"] is True
    assert r["layers"] == [
        {"store": "ghost", "namespace": "docs", "verified_absent": False, "handled": False}
    ]


def test_tag_unknown_store_warns(ctx):
    r = h_tag(ctx, "erin@x.com", "ghost", "docs", "d1")
    assert r["ok"] is True
    assert "ghost" in r["warning"]


def test_verify_only_refuses_all_write_and_read_paths():
    vctx = ServerContext(lethe=None, guard=None, trusted_public_key=None)
    for call in (
        lambda: h_forget_preview(vctx, "a@x.com"),
        lambda: h_forget(vctx, "a@x.com", "v1.x"),
        lambda: h_verify_subject(vctx, "a@x.com"),
    ):
        r = call()
        assert r["ok"] is False
        assert r["error"]["code"] == "NO_LAYERS_CONFIGURED"


def test_verify_certificate_schema_mismatch_through_handler(ctx):
    r = h_verify_certificate(ctx, {"payload": {}, "payload_hash": "zz", "signature": "a", "public_key": "b"})
    assert r["ok"] is True
    assert r["valid"] is False
    assert r["reasons"] == ["SCHEMA_MISMATCH"]


import asyncio

from lethe.mcp import ConfigError, build_context, create_server


def test_create_server_registers_six_tools_with_honest_annotations():
    vctx = ServerContext(lethe=None, guard=None, trusted_public_key=None)
    server = create_server(vctx)
    tools = asyncio.run(server.list_tools())
    by_name = {t.name: t for t in tools}
    assert sorted(by_name) == [
        "lethe_forget", "lethe_forget_preview", "lethe_status",
        "lethe_tag", "lethe_verify_certificate", "lethe_verify_subject",
    ]
    assert by_name["lethe_forget"].annotations.destructiveHint is True
    for name, tool in by_name.items():
        if name != "lethe_forget":
            assert tool.annotations.destructiveHint is False


def test_build_context_no_env_is_verify_only():
    ctx2 = build_context(environ={})
    assert ctx2.verify_only is True
    assert ctx2.trusted_public_key is None


def test_build_context_partial_env_fails_fast():
    env = {"LETHE_DATABASE_URL": "postgresql://example/db"}
    with pytest.raises(ConfigError) as e:
        build_context(environ=env)
    assert "LETHE_SALT" in str(e.value)
    assert "LETHE_KEY_FILE" in str(e.value)


def test_build_context_missing_key_file_fails_fast():
    env = {
        "LETHE_DATABASE_URL": "postgresql://example/db",
        "LETHE_SALT": "s",
        "LETHE_KEY_FILE": "C:/lethe/no/such/key.bin",
    }
    with pytest.raises(ConfigError) as e:
        build_context(environ=env)
    assert "LETHE_KEY_FILE" in str(e.value)


def test_build_context_bad_key_file_fails_fast(tmp_path):
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(b"too-short-to-be-ed25519")
    env = {
        "LETHE_DATABASE_URL": "postgresql://example/db",
        "LETHE_SALT": "s",
        "LETHE_KEY_FILE": str(key_file),
    }
    with pytest.raises(ConfigError) as e:
        build_context(environ=env)
    assert "LETHE_KEY_FILE" in str(e.value)


def test_build_context_full_env(tmp_path):
    import os as _os
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(Signer.generate().private_bytes())
    env = {
        "LETHE_DATABASE_URL": _os.environ["LETHE_TEST_DATABASE_URL"],
        "LETHE_SALT": "s",
        "LETHE_KEY_FILE": str(key_file),
        "LETHE_TRUSTED_PUBLIC_KEY": "abc=",
    }
    full = build_context(environ=env)
    try:
        assert full.verify_only is False
        assert "pgvector" in full.lethe.connectors
        assert full.trusted_public_key == "abc="
    finally:
        full.lethe.ledger.conn.close()

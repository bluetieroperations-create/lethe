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

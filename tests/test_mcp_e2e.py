"""The whole M2M story in one test: an agent tags, previews, confirms,
deletes, re-verifies, and machine-verifies the certificate — plus one
call_tool smoke through the real MCP server layer."""

import asyncio
import json

from lethe.audit import AuditLog
from lethe.core import Lethe
from lethe.guard import ConfirmGuard
from lethe.ledger import Ledger
from lethe.mcp import (
    ServerContext,
    create_server,
    h_forget,
    h_forget_preview,
    h_tag,
    h_verify_certificate,
    h_verify_subject,
)
from lethe.signing import Signer


class FakeStore:
    """In-memory Connector (duplicated from test_mcp.py on purpose — tests/ is
    not a package, so cross-test imports are unreliable under pytest)."""

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


def test_full_agent_flow(conn):
    ledger = Ledger(conn)
    audit = AuditLog(conn)
    ledger.init_schema()
    audit.init_schema()
    store = FakeStore()
    signer = Signer.generate()
    lethe = Lethe(
        ledger=ledger, audit=audit, signer=signer,
        connectors={"fake": store}, salt="e2e-salt",
    )
    ctx = ServerContext(
        lethe=lethe, guard=ConfirmGuard(), trusted_public_key=signer.public_key_b64()
    )

    store.seed("docs", ["d1", "d2"])
    store.seed("chats", ["c1"])
    assert h_tag(ctx, "alice@e2e.test", "fake", "docs", "d1")["ok"]
    assert h_tag(ctx, "alice@e2e.test", "fake", "docs", "d2")["ok"]
    assert h_tag(ctx, "alice@e2e.test", "fake", "chats", "c1")["ok"]

    preview = h_forget_preview(ctx, "alice@e2e.test")
    assert preview["ok"] and len(preview["layers"]) == 2

    result = h_forget(ctx, "alice@e2e.test", preview["confirm_token"])
    assert result["ok"] and result["all_verified"] and result["records_deleted"] == 3
    assert store.rows == {}

    after = h_verify_subject(ctx, "alice@e2e.test")
    assert after["ok"] and after["layers"] == []

    verdict = h_verify_certificate(ctx, result["certificate"])
    assert verdict["ok"] and verdict["valid"] is True


def test_call_tool_smoke_through_the_sdk():
    ctx = ServerContext(lethe=None, guard=None, trusted_public_key=None)
    server = create_server(ctx)
    result = asyncio.run(server.call_tool("lethe_status", {}))
    # mcp 2.x returns a CallToolResult; 1.x returned bare content blocks (or a
    # (content, structured) tuple). Pin the 2.x shape — a tool reporting
    # is_error would otherwise read as a pass here.
    assert result.is_error is False
    payload = json.loads(result.content[0].text)
    assert payload["ok"] is True
    assert payload["mode"] == "verify-only"

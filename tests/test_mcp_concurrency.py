"""Tool bodies must run one at a time.

mcp 1.x called sync tools inline on the event-loop thread, so this was free
and lethe/mcp.py only documented it as an invariant. mcp 2.x dispatches sync
tools through anyio.to_thread.run_sync, so concurrent calls land on separate
worker threads and the invariant has to be enforced rather than assumed.

The audit chain is no longer what the lock protects — a unique index on
prev_hash makes a fork impossible at the database, across processes, which no
in-process lock could do (see test_audit.py). What remains, and what the lock
is still load-bearing for, is the single shared psycopg connection: concurrent
tools on one connection share a transaction boundary, so one tool's commit
lands another's half-finished work, and a rolled-back statement in one thread
aborts the transaction the other is using.
"""

import asyncio
import threading

from lethe.mcp import ServerContext, create_server


def _call_all(server, name, args, times):
    async def run():
        return await asyncio.gather(*(server.call_tool(name, args) for _ in range(times)))

    return asyncio.run(run())


def test_tool_bodies_do_not_overlap(monkeypatch):
    """The invariant itself.

    h_status is patched rather than the registered tool, because the point of
    measurement has to be *inside* the lock — instrumenting the outer wrapper
    would time the queue, not the critical section, and pass either way.
    """
    import time

    import lethe.mcp as mcp_module

    inside = 0
    peak = 0
    counter = threading.Lock()

    def slow_status(ctx):
        nonlocal inside, peak
        with counter:
            inside += 1
            peak = max(peak, inside)
        time.sleep(0.02)
        with counter:
            inside -= 1
        return {"ok": True}

    monkeypatch.setattr(mcp_module, "h_status", slow_status)
    server = create_server(ServerContext(lethe=None, guard=None, trusted_public_key=None))

    results = _call_all(server, "lethe_status", {}, 6)
    assert all(r.is_error is False for r in results)
    assert peak == 1, f"{peak} tool bodies ran concurrently; they must serialize"


def test_the_sdk_would_run_them_concurrently_without_the_lock():
    """The control. If this ever reports 1, the SDK went back to inline
    dispatch and the test above has stopped proving anything."""
    import time

    from mcp.server.mcpserver import MCPServer

    server = MCPServer("probe")
    inside = 0
    peak = 0
    counter_lock = threading.Lock()

    @server.tool()
    def unserialized() -> dict:
        nonlocal inside, peak
        with counter_lock:
            inside += 1
            peak = max(peak, inside)
        time.sleep(0.02)
        with counter_lock:
            inside -= 1
        return {"ok": True}

    _call_all(server, "unserialized", {}, 6)
    assert peak > 1, (
        "the SDK now serializes sync tools itself; re-check whether "
        "lethe/mcp.py's lock is still the thing providing the guarantee"
    )

import os

import psycopg
import pytest


def _direct_endpoint(url: str | None) -> str | None:
    """The suite drops+recreates tables per test. Against a transaction pooler
    (Neon's `-pooler` host, PgBouncer) the next test's query can be served by a
    different backend that observes the just-committed DDL with catalog-
    visibility lag → non-deterministic UndefinedTable failures (audit L-1).
    Pinning to the direct (non-pooled) endpoint keeps every statement on one
    backend, so the DROP/CREATE ordering is always consistent. A real
    single-process lethe-mcp deployment has one long-lived connection and is
    unaffected either way; this only stabilizes the shared-DB test harness."""
    if url and "-pooler." in url:
        return url.replace("-pooler.", ".", 1)
    return url


DATABASE_URL = _direct_endpoint(os.environ.get("LETHE_TEST_DATABASE_URL"))

# Write the direct endpoint back so tests that build their own context from
# os.environ (test_build_context_*, the real-connector MCP e2e) use the same
# single-backend endpoint as the `conn` fixture — no mixed pooled/direct DSNs.
if DATABASE_URL:
    os.environ["LETHE_TEST_DATABASE_URL"] = DATABASE_URL


@pytest.fixture
def conn():
    if not DATABASE_URL:
        pytest.skip(
            "Set LETHE_TEST_DATABASE_URL to your Neon dev connection string to run DB tests."
        )
    with psycopg.connect(DATABASE_URL) as c:
        with c.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS lethe_provenance, lethe_audit CASCADE")
            cur.execute("DROP TABLE IF EXISTS test_vectors CASCADE")
        c.commit()
        yield c

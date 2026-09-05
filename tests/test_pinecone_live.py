"""Live-Pinecone integration test for PineconeConnector.

Pinecone is the connector whose semantics are hardest to fake — deletes are
eventually consistent — and it was covered only by a fake Index. This exercises
the real API.

Deselected by default via the `live` marker (see pyproject addopts), NOT
skipped: the CI suite fails the build if any test skips, so a credential-gated
test must be deselected or it would either break CI or erode that guard.

Run it against your own Pinecone account:

    pip install pinecone
    export PINECONE_API_KEY=...
    pytest -m live tests/test_pinecone_live.py

It creates a throwaway serverless index and deletes it again, including on
failure. Free-tier serverless is sufficient.
"""

import os
import time

import pytest

from lethe.connectors.pinecone import PineconeConnector

pytestmark = pytest.mark.live

NAMESPACE = "lethe-live-test"
INDEX_NAME = "lethe-live-test-throwaway"
DIM = 8


def _poll(fn, want, timeout=60.0, every=2.0):
    """Poll until fn() equals want or timeout; return the last value seen.

    Pinecone is eventually consistent on both upsert and delete, so a bare
    assert would be flaky in a way that says nothing about the connector.
    """
    deadline = time.time() + timeout
    val = fn()
    while val != want and time.time() < deadline:
        time.sleep(every)
        val = fn()
    return val


def _index_names(pc):
    """Index names across client versions (.names(), or an iterable of models)."""
    idx = pc.list_indexes()
    names = getattr(idx, "names", None)
    if callable(names):
        return list(idx.names())
    out = [i.get("name") if isinstance(i, dict) else getattr(i, "name", None) for i in idx]
    return [n for n in out if n]


def _ready(pc, name) -> bool:
    """describe_index(...).status.ready across attribute/dict shapes."""
    desc = pc.describe_index(name)
    status = getattr(desc, "status", None)
    if status is None and isinstance(desc, dict):
        status = desc.get("status")
    if status is None:
        return False
    ready = getattr(status, "ready", None)
    if ready is None and isinstance(status, dict):
        ready = status.get("ready")
    return bool(ready)


@pytest.fixture(scope="module")
def live_index():
    key = os.environ.get("PINECONE_API_KEY")
    if not key:
        pytest.skip("set PINECONE_API_KEY to run the live Pinecone test")
    pinecone = pytest.importorskip("pinecone", reason="pip install pinecone")

    pc = pinecone.Pinecone(api_key=key)
    if INDEX_NAME in _index_names(pc):
        pc.delete_index(INDEX_NAME)
    pc.create_index(
        name=INDEX_NAME,
        dimension=DIM,
        metric="cosine",
        spec=pinecone.ServerlessSpec(cloud="aws", region="us-east-1"),
    )
    assert _poll(lambda: _ready(pc, INDEX_NAME), True, timeout=180), "index never became ready"
    try:
        yield pc.Index(INDEX_NAME)
    finally:
        # Always tear down: a leaked index costs the account quota.
        pc.delete_index(INDEX_NAME)


def test_delete_and_verify_against_live_pinecone(live_index):
    connector = PineconeConnector(live_index)
    vec = [0.1] * DIM
    live_index.upsert(
        vectors=[{"id": rid, "values": vec} for rid in ("r1", "r2", "r3")],
        namespace=NAMESPACE,
    )

    def visible():
        resp = live_index.fetch(ids=["r1", "r2", "r3"], namespace=NAMESPACE)
        return len(getattr(resp, "vectors", {}) or {})

    assert _poll(visible, 3) == 3, "upsert never became visible"

    # delete() fetches first so the certificate can carry a real deleted_count.
    assert connector.delete(NAMESPACE, ["r1", "r2"]) == 2

    # Absence is eventually consistent, which is exactly the property the fake
    # cannot exercise — poll rather than asserting immediately.
    assert _poll(lambda: connector.verify(NAMESPACE, ["r1", "r2"]), True) is True

    # An untouched record must still read as present: verify() must not report
    # absence just because a delete happened in the same namespace.
    detail = connector.verify_detail(NAMESPACE, ["r3"])
    assert detail.absent is False
    assert detail.residual_count == 1


def test_deleting_absent_ids_is_a_noop_not_an_error(live_index):
    connector = PineconeConnector(live_index)
    assert connector.delete(NAMESPACE, ["never-existed"]) == 0
    assert connector.verify(NAMESPACE, ["never-existed"]) is True

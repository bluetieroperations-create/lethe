"""Real-Pinecone end-to-end check for PineconeConnector.

Confirms the connector works against the live Pinecone API (not just the fake
in the unit tests) — including Pinecone's eventual consistency. Creates a
throwaway serverless index, upserts vectors, runs delete/verify, and cleans up.

Run it yourself (your API key never goes through anyone else's hands):

    pip install pinecone            # the v3+ client
    export PINECONE_API_KEY=...     # from your Pinecone console
    .venv/Scripts/python.exe scripts/pinecone_e2e.py

Notes:
  * Free-tier serverless is fine. The script deletes the index it creates.
  * Pinecone is eventually consistent, so the script polls after upsert/delete.
    That polling is the *caller's* job in real use too — by the time you call
    forget(), the data was written earlier and has long since propagated.
"""

import os
import sys
import time

NAMESPACE = "lethe-e2e"
DIM = 8


def _poll(fn, want, timeout=60.0, every=2.0):
    """Poll fn() until it equals want or timeout; return the last value."""
    deadline = time.time() + timeout
    val = fn()
    while val != want and time.time() < deadline:
        time.sleep(every)
        val = fn()
    return val


def _index_names(pc):
    """List index names across client versions (.names() or iterable of models/dicts)."""
    idx = pc.list_indexes()
    names = getattr(idx, "names", None)
    if callable(names):
        return list(idx.names())
    out = []
    for i in idx:
        out.append(i.get("name") if isinstance(i, dict) else getattr(i, "name", None))
    return [n for n in out if n]


def _ready(pc, name) -> bool:
    """Read describe_index(...).status.ready across attribute/dict shapes."""
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


def main() -> int:
    key = os.environ.get("PINECONE_API_KEY")
    if not key:
        print("Set PINECONE_API_KEY (from your Pinecone console).")
        return 2
    try:
        from pinecone import Pinecone, ServerlessSpec
    except ImportError:
        print("Install the client first:  pip install pinecone")
        return 2

    from lethe.connectors.pinecone import PineconeConnector

    pc = Pinecone(api_key=key)
    name = "lethe-e2e-throwaway"

    if name in _index_names(pc):
        pc.delete_index(name)

    print(f"creating throwaway index {name!r} ...")
    pc.create_index(
        name=name,
        dimension=DIM,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1"),
    )
    # wait for the index to be ready (status shape varies across client versions)
    _poll(lambda: _ready(pc, name), True, timeout=120)

    index = pc.Index(name)
    conn = PineconeConnector(index)
    ok = True
    try:
        vec = [0.1] * DIM
        index.upsert(
            vectors=[
                {"id": "r1", "values": vec},
                {"id": "r2", "values": vec},
                {"id": "r3", "values": vec},
            ],
            namespace=NAMESPACE,
        )

        # Wait until all three are visible (eventual consistency on upsert).
        def visible():
            r = index.fetch(ids=["r1", "r2", "r3"], namespace=NAMESPACE)
            return len(getattr(r, "vectors", {}) or {})

        n = _poll(visible, 3, timeout=60)
        print(f"  upsert visible: {n}/3", "OK" if n == 3 else "FAIL")
        ok = ok and n == 3

        deleted = conn.delete(NAMESPACE, ["r1", "r2"])
        print(f"  connector.delete -> count {deleted}", "OK" if deleted == 2 else "FAIL")
        ok = ok and deleted == 2

        # verify() may briefly see the rows until the delete propagates -> poll.
        gone = _poll(lambda: conn.verify(NAMESPACE, ["r1", "r2"]), True, timeout=60)
        print(f"  connector.verify deleted absent -> {gone}", "OK" if gone else "FAIL")
        ok = ok and gone

        still = conn.verify(NAMESPACE, ["r3"])
        print(f"  r3 still present -> verify False -> {still}", "OK" if still is False else "FAIL")
        ok = ok and still is False
    finally:
        print(f"cleaning up index {name!r} ...")
        pc.delete_index(name)

    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

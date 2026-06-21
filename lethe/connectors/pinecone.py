"""Pinecone connector: delete records by id and verify their absence.

Wraps a Pinecone ``Index`` object (duck-typed — Lethe does not depend on the
pinecone client). Lethe's ``namespace`` maps to a Pinecone namespace.

Two Pinecone realities shape this connector:
  * ``index.delete(ids=...)`` returns no count, so to report an accurate
    ``deleted_count`` for the certificate, ``delete()`` first ``fetch``es the
    ids to see how many actually existed, then deletes.
  * Pinecone upserts on id collision, so ids must be unique per record — the
    LetheVectorStore wrapper enforces that up front (see its id_key handling).
"""

# Pinecone caps ids per delete/fetch call; chunk to stay under it.
_BATCH = 1000


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def _fetched_ids(resp) -> set:
    # pinecone-client returns a FetchResponse with `.vectors`, or a dict with
    # a "vectors" key, mapping id -> vector. Support both shapes.
    vectors = getattr(resp, "vectors", None)
    if vectors is None and isinstance(resp, dict):
        vectors = resp.get("vectors", {})
    return set((vectors or {}).keys())


class PineconeConnector:
    name = "pinecone"

    def __init__(self, index):
        self.index = index

    def delete(self, namespace: str, record_ids: list[str]) -> int:
        if not record_ids:
            return 0
        existing: set = set()
        for chunk in _chunks(record_ids, _BATCH):
            existing |= _fetched_ids(self.index.fetch(ids=list(chunk), namespace=namespace))
        for chunk in _chunks(record_ids, _BATCH):
            self.index.delete(ids=list(chunk), namespace=namespace)
        return len(existing)

    def verify(self, namespace: str, record_ids: list[str]) -> bool:
        if not record_ids:
            return True
        for chunk in _chunks(record_ids, _BATCH):
            if _fetched_ids(self.index.fetch(ids=list(chunk), namespace=namespace)):
                return False
        return True

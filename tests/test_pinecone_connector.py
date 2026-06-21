"""Unit tests for PineconeConnector against a fake Index that mimics real
Pinecone semantics (namespaced store, upsert-on-collision, fetch returns a
.vectors map, delete is a no-op on missing ids). Real-Pinecone is a deferred
manual e2e — these cover the connector's delete/count/verify logic."""

from lethe.connectors.pinecone import PineconeConnector


class FetchResponse:
    def __init__(self, vectors):
        self.vectors = vectors


class FakePineconeIndex:
    def __init__(self):
        self.ns: dict[str, dict[str, str]] = {}

    def upsert(self, vectors, namespace=""):
        store = self.ns.setdefault(namespace, {})
        for vid, body in vectors:
            store[vid] = body  # upsert: later write wins on collision

    def fetch(self, ids, namespace=""):
        store = self.ns.get(namespace, {})
        return FetchResponse({i: store[i] for i in ids if i in store})

    def delete(self, ids, namespace=""):
        store = self.ns.get(namespace, {})
        for i in ids:
            store.pop(i, None)


def _seed(index, namespace="ns"):
    index.upsert([("r1", "a"), ("r2", "b"), ("r3", "c")], namespace=namespace)


def test_delete_returns_existing_count_and_removes():
    index = FakePineconeIndex()
    _seed(index)
    c = PineconeConnector(index)
    assert c.delete("ns", ["r1", "r2"]) == 2
    assert set(index.ns["ns"].keys()) == {"r3"}


def test_delete_counts_only_ids_that_existed():
    index = FakePineconeIndex()
    _seed(index)
    c = PineconeConnector(index)
    # r1 exists, ghost does not -> count is 1, not 2.
    assert c.delete("ns", ["r1", "ghost"]) == 1


def test_verify_true_when_absent():
    index = FakePineconeIndex()
    _seed(index)
    c = PineconeConnector(index)
    c.delete("ns", ["r1"])
    assert c.verify("ns", ["r1"]) is True


def test_verify_false_when_still_present():
    index = FakePineconeIndex()
    _seed(index)
    c = PineconeConnector(index)
    assert c.verify("ns", ["r3"]) is False


def test_empty_ids_are_noops():
    index = FakePineconeIndex()
    c = PineconeConnector(index)
    assert c.delete("ns", []) == 0
    assert c.verify("ns", []) is True


def test_namespaces_are_isolated():
    index = FakePineconeIndex()
    _seed(index, namespace="a")
    _seed(index, namespace="b")
    c = PineconeConnector(index)
    c.delete("a", ["r1", "r2", "r3"])
    assert index.ns["a"] == {}
    assert set(index.ns["b"].keys()) == {"r1", "r2", "r3"}  # untouched


def test_dict_shaped_fetch_response_is_supported():
    class DictIndex(FakePineconeIndex):
        def fetch(self, ids, namespace=""):
            store = self.ns.get(namespace, {})
            return {"vectors": {i: store[i] for i in ids if i in store}}

    index = DictIndex()
    _seed(index)
    c = PineconeConnector(index)
    assert c.verify("ns", ["r3"]) is False
    assert c.delete("ns", ["r3"]) == 1
    assert c.verify("ns", ["r3"]) is True

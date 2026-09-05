import asyncio
from dataclasses import dataclass, field

import pytest

from lethe.audit import AuditLog
from lethe.connectors.pgvector import PgVectorConnector
from lethe.core import Lethe
from lethe.integrations.langchain import LetheTaggingError, LetheVectorStore
from lethe.ledger import Ledger
from lethe.signing import Signer


@dataclass
class Doc:
    page_content: str
    metadata: dict = field(default_factory=dict)


class PgInner:
    """A minimal real-Postgres-backed stand-in for a LangChain vector store."""

    def __init__(self, conn, table):
        self.conn = conn
        self.table = table
        self._n = 0

    def add_documents(self, documents, **kwargs):
        ids = []
        with self.conn.cursor() as cur:
            for d in documents:
                self._n += 1
                rid = f"v{self._n}"
                cur.execute(
                    f"INSERT INTO {self.table} (id, body) VALUES (%s, %s)",
                    (rid, d.page_content),
                )
                ids.append(rid)
        self.conn.commit()
        return ids

    def add_texts(self, texts, metadatas=None, **kwargs):
        ids = []
        with self.conn.cursor() as cur:
            for t in texts:
                self._n += 1
                rid = f"v{self._n}"
                cur.execute(
                    f"INSERT INTO {self.table} (id, body) VALUES (%s, %s)", (rid, t)
                )
                ids.append(rid)
        self.conn.commit()
        return ids

    def count(self):
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {self.table}")
            return cur.fetchone()[0]

    def similarity_search(self, query):
        return ["proxied:" + query]


@pytest.fixture
def wired(conn):
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS wrapped_vectors")
        cur.execute("CREATE TABLE wrapped_vectors (id TEXT PRIMARY KEY, body TEXT)")
    conn.commit()
    ledger = Ledger(conn)
    ledger.init_schema()
    audit = AuditLog(conn)
    audit.init_schema()
    lethe = Lethe(
        ledger=ledger,
        audit=audit,
        signer=Signer.generate(),
        connectors={"pgvector": PgVectorConnector(conn)},
        salt="s",
    )
    inner = PgInner(conn, "wrapped_vectors")
    store = LetheVectorStore(
        inner, lethe, store="pgvector", namespace="wrapped_vectors", subject_key="user_id"
    )
    return conn, lethe, inner, store


def test_add_documents_auto_tags_each_record(wired):
    conn, lethe, inner, store = wired
    ids = store.add_documents(
        [
            Doc("alice doc", {"user_id": "alice"}),
            Doc("alice doc 2", {"user_id": "alice"}),
            Doc("bob doc", {"user_id": "bob"}),
        ]
    )
    assert inner.count() == 3
    alice_tags = lethe.ledger.lookup(lethe._subject_hash("alice"))
    assert {t.record_id for t in alice_tags} == {ids[0], ids[1]}
    assert all(
        t.store == "pgvector" and t.namespace == "wrapped_vectors" for t in alice_tags
    )
    assert len(lethe.ledger.lookup(lethe._subject_hash("bob"))) == 1


def test_add_texts_auto_tags(wired):
    conn, lethe, inner, store = wired
    ids = store.add_texts(
        ["t1", "t2"], metadatas=[{"user_id": "carol"}, {"user_id": "carol"}]
    )
    assert {t.record_id for t in lethe.ledger.lookup(lethe._subject_hash("carol"))} == set(ids)


def test_missing_subject_errors_before_writing(wired):
    conn, lethe, inner, store = wired
    with pytest.raises(LetheTaggingError):
        store.add_documents([Doc("a", {"user_id": "alice"}), Doc("no owner", {})])
    # Error policy pre-validates: nothing is written if any doc lacks a subject.
    assert inner.count() == 0


def test_skip_policy_writes_all_tags_subset(wired):
    conn, lethe, inner, _ = wired
    store = LetheVectorStore(
        inner,
        lethe,
        store="pgvector",
        namespace="wrapped_vectors",
        subject_key="user_id",
        on_missing_subject="skip",
    )
    store.add_documents([Doc("a", {"user_id": "dave"}), Doc("anon", {})])
    assert inner.count() == 2  # both written
    assert len(lethe.ledger.lookup(lethe._subject_hash("dave"))) == 1  # only dave tagged


def test_list_subject_is_rejected(wired):
    conn, lethe, inner, store = wired
    with pytest.raises(LetheTaggingError):
        store.add_documents([Doc("shared", {"user_id": ["alice", "bob"]})])


def test_other_methods_proxy_to_inner(wired):
    conn, lethe, inner, store = wired
    assert store.similarity_search("hello") == ["proxied:hello"]


# --- adversarial: write surfaces that must NOT bypass tagging -----------------


class AsyncInner(PgInner):
    """Adds the async write methods real LangChain stores expose."""

    async def aadd_documents(self, documents, **kwargs):
        return self.add_documents(documents, **kwargs)

    async def aadd_texts(self, texts, metadatas=None, **kwargs):
        return self.add_texts(texts, metadatas=metadatas, **kwargs)

    def add_embeddings(self, *args, **kwargs):
        # Simulate a real store writing rows for an embeddings upload.
        self._n += 1
        rid = f"v{self._n}"
        with self.conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self.table} (id, body) VALUES (%s, %s)", (rid, "emb")
            )
        self.conn.commit()
        return [rid]

    def upsert(self, items, **kwargs):
        self._n += 1
        rid = f"v{self._n}"
        with self.conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self.table} (id, body) VALUES (%s, %s)", (rid, "ups")
            )
        self.conn.commit()
        return {"succeeded": [rid]}


@pytest.fixture
def async_wired(conn):
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS wrapped_vectors")
        cur.execute("CREATE TABLE wrapped_vectors (id TEXT PRIMARY KEY, body TEXT)")
    conn.commit()
    ledger = Ledger(conn)
    ledger.init_schema()
    audit = AuditLog(conn)
    audit.init_schema()
    lethe = Lethe(
        ledger=ledger,
        audit=audit,
        signer=Signer.generate(),
        connectors={"pgvector": PgVectorConnector(conn)},
        salt="s",
    )
    inner = AsyncInner(conn, "wrapped_vectors")
    store = LetheVectorStore(
        inner, lethe, store="pgvector", namespace="wrapped_vectors", subject_key="user_id"
    )
    return conn, lethe, inner, store


def test_aadd_documents_auto_tags(async_wired):
    conn, lethe, inner, store = async_wired
    ids = asyncio.run(store.aadd_documents([Doc("alice doc", {"user_id": "alice"})]))
    assert inner.count() == 1
    tagged = lethe.ledger.lookup(lethe._subject_hash("alice"))
    assert {t.record_id for t in tagged} == set(ids), "async write must be tagged"


def test_aadd_texts_auto_tags(async_wired):
    conn, lethe, inner, store = async_wired
    ids = asyncio.run(store.aadd_texts(["t"], metadatas=[{"user_id": "carol"}]))
    tagged = lethe.ledger.lookup(lethe._subject_hash("carol"))
    assert {t.record_id for t in tagged} == set(ids), "async text write must be tagged"


def test_aadd_documents_missing_subject_errors_before_writing(async_wired):
    conn, lethe, inner, store = async_wired
    with pytest.raises(LetheTaggingError):
        asyncio.run(store.aadd_documents([Doc("no owner", {})]))
    assert inner.count() == 0, "error mode must not write untaggable data via async path"


def test_unknown_write_methods_refuse_rather_than_leak(async_wired):
    conn, lethe, inner, store = async_wired
    # These write rows but the wrapper cannot tag them -> must refuse, not proxy.
    with pytest.raises(LetheTaggingError):
        store.add_embeddings()
    with pytest.raises(LetheTaggingError):
        store.upsert([{"user_id": "alice"}])
    assert inner.count() == 0, "no untaggable rows may reach the inner store"


def test_end_to_end_wrap_then_forget(wired):
    conn, lethe, inner, store = wired
    store.add_documents(
        [
            Doc("alice secret", {"user_id": "alice"}),
            Doc("bob secret", {"user_id": "bob"}),
        ]
    )
    cert = lethe.forget("alice")
    with conn.cursor() as cur:
        cur.execute("SELECT body FROM wrapped_vectors ORDER BY id")
        remaining = [r[0] for r in cur.fetchall()]
    assert remaining == ["bob secret"]
    assert cert.payload["all_verified"] is True
    assert cert.payload["records_deleted"] == 1


# --- M-1: id_key binds ids from metadata, not the store's return order --------


def _make_lethe(conn):
    ledger = Ledger(conn)
    ledger.init_schema()
    audit = AuditLog(conn)
    audit.init_schema()
    return Lethe(
        ledger=ledger,
        audit=audit,
        signer=Signer.generate(),
        connectors={"pgvector": PgVectorConnector(conn)},
        salt="s",
    )


def _make_table(conn):
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS wrapped_vectors")
        cur.execute("CREATE TABLE wrapped_vectors (id TEXT PRIMARY KEY, body TEXT)")
    conn.commit()


class ReorderingInner(PgInner):
    """Honors caller-provided ids but RETURNS them reversed — the exact
    misbehavior that makes positional tagging unsafe (M-1)."""

    def add_documents(self, documents, ids=None, **kwargs):
        used = ids if ids is not None else [f"auto{i}" for i in range(len(documents))]
        with self.conn.cursor() as cur:
            for d, rid in zip(documents, used, strict=True):
                cur.execute(
                    f"INSERT INTO {self.table} (id, body) VALUES (%s, %s)",
                    (rid, d.page_content),
                )
        self.conn.commit()
        return list(reversed(used))


def test_id_key_binds_ids_from_metadata_despite_reordered_return(conn):
    _make_table(conn)
    lethe = _make_lethe(conn)
    store = LetheVectorStore(
        ReorderingInner(conn, "wrapped_vectors"), lethe, store="pgvector",
        namespace="wrapped_vectors", subject_key="user_id", id_key="doc_id",
    )
    store.add_documents([
        Doc("alice", {"user_id": "alice", "doc_id": "da"}),
        Doc("bob", {"user_id": "bob", "doc_id": "db"}),
    ])
    # The store returned ids reversed; positional tagging would have swapped
    # them. id_key binds each subject to ITS OWN id from metadata.
    assert {t.record_id for t in lethe.ledger.lookup(lethe._subject_hash("alice"))} == {"da"}
    assert {t.record_id for t in lethe.ledger.lookup(lethe._subject_hash("bob"))} == {"db"}


def test_id_key_missing_in_metadata_raises_before_write(conn):
    _make_table(conn)
    lethe = _make_lethe(conn)
    inner = PgInner(conn, "wrapped_vectors")
    store = LetheVectorStore(
        inner, lethe, store="pgvector", namespace="wrapped_vectors",
        subject_key="user_id", id_key="doc_id",
    )
    with pytest.raises(LetheTaggingError):
        store.add_documents([Doc("a", {"user_id": "alice"})])  # no doc_id
    assert inner.count() == 0


def test_id_key_conflicts_with_explicit_ids_kwarg(conn):
    _make_table(conn)
    lethe = _make_lethe(conn)
    store = LetheVectorStore(
        PgInner(conn, "wrapped_vectors"), lethe, store="pgvector",
        namespace="wrapped_vectors", subject_key="user_id", id_key="doc_id",
    )
    with pytest.raises(ValueError):
        store.add_documents([Doc("a", {"user_id": "alice", "doc_id": "da"})], ids=["x"])


def test_id_key_end_to_end_forget_with_reordering_store(conn):
    _make_table(conn)
    lethe = _make_lethe(conn)
    store = LetheVectorStore(
        ReorderingInner(conn, "wrapped_vectors"), lethe, store="pgvector",
        namespace="wrapped_vectors", subject_key="user_id", id_key="doc_id",
    )
    store.add_documents([
        Doc("alice secret", {"user_id": "alice", "doc_id": "da"}),
        Doc("bob secret", {"user_id": "bob", "doc_id": "db"}),
    ])
    cert = lethe.forget("alice")
    with conn.cursor() as cur:
        cur.execute("SELECT body FROM wrapped_vectors ORDER BY id")
        remaining = [r[0] for r in cur.fetchall()]
    assert remaining == ["bob secret"]  # exactly alice's row removed
    assert cert.payload["records_deleted"] == 1


# --- C-1: duplicate id_key in a batch -> cross-subject collateral deletion ----


class UpsertInner(PgInner):
    """id-keyed store: the caller-provided id is a primary key, so a repeated id
    UPSERTS (the later record overwrites the earlier one). Pinecone /
    pgvector-with-ids semantics. A naive wrapper would tag two inputs to the one
    surviving row, so forgetting one subject deletes the other's data."""

    def add_documents(self, documents, ids=None, **kwargs):
        used = ids if ids is not None else [f"a{i}" for i in range(len(documents))]
        with self.conn.cursor() as cur:
            for d, rid in zip(documents, used, strict=True):
                cur.execute(
                    f"INSERT INTO {self.table} (id, body) VALUES (%s,%s) "
                    f"ON CONFLICT (id) DO UPDATE SET body=EXCLUDED.body",
                    (rid, d.page_content),
                )
        self.conn.commit()
        return list(used)

    async def aadd_documents(self, documents, ids=None, **kwargs):
        return self.add_documents(documents, ids=ids, **kwargs)


def test_id_key_duplicate_across_subjects_refused_before_write(conn):
    _make_table(conn)
    lethe = _make_lethe(conn)
    store = LetheVectorStore(
        UpsertInner(conn, "wrapped_vectors"), lethe, store="pgvector",
        namespace="wrapped_vectors", subject_key="user_id", id_key="doc_id",
    )
    # Two DIFFERENT subjects share one doc_id. If allowed, the store upserts to a
    # single row tagged to both, and alice.forget() destroys bob's data.
    with pytest.raises(LetheTaggingError):
        store.add_documents([
            Doc("alice secret", {"user_id": "alice", "doc_id": "dup"}),
            Doc("bob secret", {"user_id": "bob", "doc_id": "dup"}),
        ])
    assert inner_count(conn) == 0  # nothing written
    assert lethe.ledger.lookup(lethe._subject_hash("alice")) == []
    assert lethe.ledger.lookup(lethe._subject_hash("bob")) == []


def test_id_key_duplicate_same_subject_refused(conn):
    _make_table(conn)
    lethe = _make_lethe(conn)
    store = LetheVectorStore(
        UpsertInner(conn, "wrapped_vectors"), lethe, store="pgvector",
        namespace="wrapped_vectors", subject_key="user_id", id_key="doc_id",
    )
    # Same subject, same id on two distinct docs: upsert would silently lose one.
    with pytest.raises(LetheTaggingError):
        store.add_documents([
            Doc("first", {"user_id": "alice", "doc_id": "x"}),
            Doc("second", {"user_id": "alice", "doc_id": "x"}),
        ])
    assert inner_count(conn) == 0


def test_id_key_async_duplicate_refused(conn):
    _make_table(conn)
    lethe = _make_lethe(conn)
    store = LetheVectorStore(
        UpsertInner(conn, "wrapped_vectors"), lethe, store="pgvector",
        namespace="wrapped_vectors", subject_key="user_id", id_key="doc_id",
    )
    with pytest.raises(LetheTaggingError):
        asyncio.run(store.aadd_documents([
            Doc("alice", {"user_id": "alice", "doc_id": "dup"}),
            Doc("bob", {"user_id": "bob", "doc_id": "dup"}),
        ]))
    assert inner_count(conn) == 0


def inner_count(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM wrapped_vectors")
        return cur.fetchone()[0]

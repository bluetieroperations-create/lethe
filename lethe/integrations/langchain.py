"""LangChain/LlamaIndex-compatible vector-store wrapper that auto-tags writes.

Wrap an existing vector store once and declare which metadata field holds the
data subject; every ``add_documents`` / ``add_texts`` then records a Lethe
provenance tag so those records can be deleted on a later ``forget()``. All
other methods (similarity search, etc.) proxy through transparently, so the
wrapper is a drop-in replacement.

The salt stays in your app (the wrapped ``Lethe`` instance); this wrapper never
sends it to the vector store or the database.

    store = LetheVectorStore(
        inner=PGVector(...),          # any LangChain-style vector store
        lethe=lethe,                  # configured Lethe (ledger + salt)
        store="pgvector",             # must match a connector key in Lethe
        namespace="my_table",         # must match where the records live
        subject_key="user_id",        # metadata field naming the data subject
    )
    store.add_documents([Document(page_content="...",
                                  metadata={"user_id": "alice@example.com"})])
"""


class LetheTaggingError(Exception):
    """Raised when records cannot be tagged for future deletion."""


class LetheVectorStore:
    def __init__(
        self,
        inner,
        lethe,
        *,
        store: str,
        namespace: str,
        subject_key: str,
        on_missing_subject: str = "error",
    ):
        if on_missing_subject not in ("error", "skip"):
            raise ValueError("on_missing_subject must be 'error' or 'skip'")
        self.inner = inner
        self.lethe = lethe
        self.store = store
        self.namespace = namespace
        self.subject_key = subject_key
        self.on_missing_subject = on_missing_subject

    # --- subject extraction -------------------------------------------------
    def _subject_of(self, metadata: dict | None) -> str | None:
        value = (metadata or {}).get(self.subject_key)
        if value is None:
            return None
        if isinstance(value, (list, tuple, set, dict)):
            raise LetheTaggingError(
                f"metadata['{self.subject_key}'] must name a single subject, "
                f"got {type(value).__name__}. A record shared by multiple subjects "
                f"needs explicit handling (one subject's forget would delete it)."
            )
        return str(value)

    def _require_subjects(self, metadatas: list[dict]) -> None:
        missing = [i for i, m in enumerate(metadatas) if self._subject_of(m) is None]
        if missing:
            raise LetheTaggingError(
                f"{len(missing)} document(s) missing '{self.subject_key}' in metadata "
                f"(indices {missing[:10]}); refusing to write data that cannot later "
                f"be deleted. Add the subject, or use on_missing_subject='skip'."
            )

    def _tag(self, metadatas: list[dict], ids) -> None:
        if ids is None or len(ids) != len(metadatas):
            raise LetheTaggingError(
                "vector store did not return ids aligned with the inputs; "
                "cannot tag these records for deletion."
            )
        for meta, rid in zip(metadatas, ids):
            subject = self._subject_of(meta)
            if subject is None:
                continue  # only reached under on_missing_subject='skip'
            self.lethe.tag(subject, self.store, self.namespace, str(rid))

    # --- write surfaces -----------------------------------------------------
    def add_documents(self, documents, **kwargs):
        metadatas = [getattr(d, "metadata", {}) or {} for d in documents]
        if self.on_missing_subject == "error":
            self._require_subjects(metadatas)  # pre-write: no untaggable writes
        ids = self.inner.add_documents(documents, **kwargs)
        self._tag(metadatas, ids)
        return ids

    def add_texts(self, texts, metadatas=None, **kwargs):
        texts = list(texts)
        metadatas = list(metadatas) if metadatas is not None else [{} for _ in texts]
        if self.on_missing_subject == "error":
            self._require_subjects(metadatas)
        ids = self.inner.add_texts(texts, metadatas=metadatas, **kwargs)
        self._tag(metadatas, ids)
        return ids

    # --- transparent proxy for everything else ------------------------------
    def __getattr__(self, name):
        inner = self.__dict__.get("inner")
        if inner is None:
            raise AttributeError(name)
        return getattr(inner, name)

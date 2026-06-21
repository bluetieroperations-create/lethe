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
        id_key="doc_id",              # OPTIONAL: metadata field holding a stable id
    )
    store.add_documents([Document(page_content="...",
                                  metadata={"user_id": "alice@example.com"})])

Id binding (resolves the M-1 reordering risk):
  * With ``id_key`` set (RECOMMENDED for production), each record's id is read
    from ``metadata[id_key]`` and passed to the store, so tagging is bound to
    the record directly and never depends on the store returning ids in input
    order. Required-style for id-keyed stores like Pinecone.
  * Without ``id_key``, tagging maps the store's returned ids to inputs
    positionally, relying on the LangChain contract that add_documents/add_texts
    return ids in input order, one per input. A reordering store would mistag —
    use ``id_key`` if you can't rely on that contract.

Other limits:
  * ``from_documents`` / ``from_texts`` are classmethods on the underlying store
    and bypass this wrapper entirely; build through the wrapper (or tag
    manually) rather than wrapping an already-populated store.
  * Known un-taggable write verbs are refused (fail-closed). A brand-new write
    surface not yet in the deny-list is the one residual leak; add it to
    ``_UNTAGGABLE_WRITES`` or override it.
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
        id_key: str | None = None,
        on_missing_subject: str = "error",
    ):
        if on_missing_subject not in ("error", "skip"):
            raise ValueError("on_missing_subject must be 'error' or 'skip'")
        self.inner = inner
        self.lethe = lethe
        self.store = store
        self.namespace = namespace
        self.subject_key = subject_key
        self.id_key = id_key
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

    def _ids_from_metadata(self, metadatas: list[dict]) -> list[str]:
        ids = []
        seen: dict[str, int] = {}
        for i, m in enumerate(metadatas):
            rid = (m or {}).get(self.id_key)
            if rid is None:
                raise LetheTaggingError(
                    f"document {i} is missing id_key '{self.id_key}' in metadata; "
                    f"cannot bind a stable id for tagging/deletion."
                )
            rid = str(rid)
            if rid in seen:
                # An id-keyed store treats id as a primary key, so a repeated id
                # in one batch upserts: the later record overwrites the earlier
                # one in the store, but the ledger would tag BOTH inputs to that
                # single surviving row. If the two inputs belong to different
                # subjects, one subject's forget() would then delete the other
                # subject's data. Fail closed before any write, like the
                # multi-subject rejection in _subject_of.
                raise LetheTaggingError(
                    f"duplicate id_key '{self.id_key}'={rid!r} at documents "
                    f"{seen[rid]} and {i}; ids must be unique within a batch so "
                    f"each record maps to exactly one subject. Deduplicate inputs "
                    f"or give each record a distinct id."
                )
            seen[rid] = i
            ids.append(rid)
        return ids

    def _prepare(self, metadatas: list[dict], kwargs: dict) -> list[str] | None:
        """Validate subjects (no untaggable writes in error mode); if id_key is
        set, derive each record's id from metadata so tagging never relies on the
        store returning ids in input order. Returns explicit ids or None."""
        if self.on_missing_subject == "error":
            self._require_subjects(metadatas)
        if self.id_key is not None:
            if "ids" in kwargs:
                raise ValueError(
                    "when id_key is set, record ids come from metadata[id_key]; "
                    "do not also pass an ids= argument."
                )
            return self._ids_from_metadata(metadatas)
        return None

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
        explicit = self._prepare(metadatas, kwargs)
        if explicit is not None:
            self.inner.add_documents(documents, ids=explicit, **kwargs)
            self._tag(metadatas, explicit)
            return explicit
        ids = self.inner.add_documents(documents, **kwargs)
        self._tag(metadatas, ids)
        return ids

    def add_texts(self, texts, metadatas=None, **kwargs):
        texts = list(texts)
        metadatas = list(metadatas) if metadatas is not None else [{} for _ in texts]
        explicit = self._prepare(metadatas, kwargs)
        if explicit is not None:
            self.inner.add_texts(texts, metadatas=metadatas, ids=explicit, **kwargs)
            self._tag(metadatas, explicit)
            return explicit
        ids = self.inner.add_texts(texts, metadatas=metadatas, **kwargs)
        self._tag(metadatas, ids)
        return ids

    # --- async write surfaces -----------------------------------------------
    # LangChain vector stores expose async writes; without explicit overrides
    # these would fall through __getattr__ to the inner store and write data
    # that is never tagged -> silently undeletable. Mirror the sync paths.
    async def aadd_documents(self, documents, **kwargs):
        metadatas = [getattr(d, "metadata", {}) or {} for d in documents]
        explicit = self._prepare(metadatas, kwargs)
        if explicit is not None:
            await self.inner.aadd_documents(documents, ids=explicit, **kwargs)
            self._tag(metadatas, explicit)
            return explicit
        ids = await self.inner.aadd_documents(documents, **kwargs)
        self._tag(metadatas, ids)
        return ids

    async def aadd_texts(self, texts, metadatas=None, **kwargs):
        texts = list(texts)
        metadatas = list(metadatas) if metadatas is not None else [{} for _ in texts]
        explicit = self._prepare(metadatas, kwargs)
        if explicit is not None:
            await self.inner.aadd_texts(texts, metadatas=metadatas, ids=explicit, **kwargs)
            self._tag(metadatas, explicit)
            return explicit
        ids = await self.inner.aadd_texts(texts, metadatas=metadatas, **kwargs)
        self._tag(metadatas, ids)
        return ids

    # Write methods the wrapper cannot safely tag. Proxying them would leak
    # untaggable (silently undeletable) data into the inner store, so we refuse
    # rather than fail open. This is a deny-list because new write surfaces are
    # the catastrophic case for a deletion product; read methods proxy freely.
    _UNTAGGABLE_WRITES = frozenset(
        {
            "add_embeddings",
            "aadd_embeddings",
            "upsert",
            "aupsert",
            "from_documents",
            "afrom_documents",
            "from_texts",
            "afrom_texts",
        }
    )

    # --- transparent proxy for everything else ------------------------------
    def __getattr__(self, name):
        if name in type(self)._UNTAGGABLE_WRITES:
            raise LetheTaggingError(
                f"{name!r} writes to the store but Lethe cannot tag those records "
                f"for deletion. Use add_documents/add_texts (or their async forms), "
                f"or tag explicitly via lethe.tag() and call inner.{name} yourself."
            )
        inner = self.__dict__.get("inner")
        if inner is None:
            raise AttributeError(name)
        return getattr(inner, name)

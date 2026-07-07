from dataclasses import dataclass


@dataclass(frozen=True)
class TagRecord:
    subject_hash: str
    store: str
    namespace: str
    record_id: str


@dataclass(frozen=True)
class LayerResult:
    store: str
    namespace: str
    deleted_count: int
    verified_absent: bool
    # Number of record_ids the ledger asked this layer to delete. Lets the
    # certificate distinguish a real erasure (Lethe deleted what it was asked to)
    # from "nothing was there" (deleted_count 0 but verified absent — e.g. the
    # row was already removed by another subject's forget or a prior partial run).
    requested_count: int = 0
    # True only if this layer was actually handled by a configured connector.
    # A tagged store with no connector is recorded as unhandled, not silently
    # skipped or crashed mid-loop.
    handled: bool = True
    # --- cert v2 verification evidence (None when unknown, e.g. an unhandled
    # layer or a connector that only implements the boolean verify()). ---
    # How many of the requested record_ids STILL matched at verify time. 0 is
    # the negative-query result that backs verified_absent; a non-zero value is
    # the residue a re-query found. This is the evidence, not just the boolean.
    residual_count: int | None = None
    # Machine/human descriptor of the verification actually performed (e.g. the
    # re-query shape), so "verified_absent: true" is auditable, not asserted.
    verify_method: str | None = None
    # Store-native index/version fingerprint at verify time, if the connector
    # can supply one, so the absence claim binds to a specific index state.
    index_version: str | None = None


@dataclass(frozen=True)
class Certificate:
    payload: dict
    payload_hash: str
    signature: str
    public_key: str

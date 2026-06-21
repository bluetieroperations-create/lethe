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


@dataclass(frozen=True)
class Certificate:
    payload: dict
    payload_hash: str
    signature: str
    public_key: str

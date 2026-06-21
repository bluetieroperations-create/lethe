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


@dataclass(frozen=True)
class Certificate:
    payload: dict
    payload_hash: str
    signature: str
    public_key: str

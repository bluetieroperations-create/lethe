from typing import Protocol, runtime_checkable


@runtime_checkable
class Connector(Protocol):
    name: str

    def delete(self, namespace: str, record_ids: list[str]) -> int:
        """Delete the given records from `namespace`; return rows deleted."""
        ...

    def verify(self, namespace: str, record_ids: list[str]) -> bool:
        """Return True only if none of `record_ids` remain in `namespace`."""
        ...

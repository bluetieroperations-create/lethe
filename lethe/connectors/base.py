from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class VerifyResult:
    """Rich result of a post-delete verification, so the certificate can record
    the EVIDENCE (the residual match count and the query that produced it), not
    just a boolean. Returned by a connector's optional ``verify_detail``."""

    absent: bool  # True iff residual_count == 0
    residual_count: int  # how many of the queried record_ids still matched
    method: str  # descriptor of the verification query actually run
    index_version: str | None = None  # store-native index fingerprint, if any


@runtime_checkable
class Connector(Protocol):
    name: str

    def delete(self, namespace: str, record_ids: list[str]) -> int:
        """Delete the given records from `namespace`; return rows deleted."""
        ...

    def verify(self, namespace: str, record_ids: list[str]) -> bool:
        """Return True only if none of `record_ids` remain in `namespace`."""
        ...

    # OPTIONAL: connectors MAY additionally implement
    #     verify_detail(namespace, record_ids) -> VerifyResult
    # to give the certificate the residual count + query descriptor. It is not
    # part of the required Protocol: a connector that implements only delete()
    # and verify() stays valid, and core.forget falls back to the boolean.
    #
    # OPTIONAL: connectors MAY additionally implement
    #     scan(namespace, subject_field, subject_value) -> list[str]
    # returning the record ids the STORE itself holds for a subject, found by
    # store-native search rather than by Lethe's ledger. This is what lets
    # reconcile() detect records that were written without going through the
    # wrapper — the coverage gap the ledger structurally cannot see. Not
    # required: a store with no queryable subject field cannot support it, and
    # reconcile() reports such a layer as unscannable rather than as clean.

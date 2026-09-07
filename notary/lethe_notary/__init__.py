"""lethe-notary — a paid countersigning witness for Lethe deletion certificates.

Kept out of the `lethe` package on purpose. Lethe is a self-hosted compliance
library that runs against the operator's own database; it must not grow a
wallet, a payment SDK, or a network dependency on a service someone charges
for. This package depends on lethe, never the other way round.
"""

from .receipt import CLAIM, NOTARY_SCHEMA, build_receipt, verify_receipt
from .store import WitnessLog

__all__ = ["CLAIM", "NOTARY_SCHEMA", "build_receipt", "verify_receipt", "WitnessLog"]

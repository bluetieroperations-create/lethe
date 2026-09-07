"""Mint a certificate to test the payment path with. No database needed.

The notary only ever sees a signed JSON document, so a certificate from a
throwaway key exercises the paid path exactly as a real one does. Use this to
settle a testnet payment before pointing anything real at the service.

    python tools/make_test_certificate.py
    # -> certificate.json
"""

import json
import sys

from lethe.certificate import build_certificate, certificate_to_dict
from lethe.models import LayerResult
from lethe.signing import Signer


def main(out: str = "certificate.json") -> None:
    signer = Signer.generate()
    cert = build_certificate(
        request_id="testnet-trial",
        subject_hash="a" * 64,
        layers=[LayerResult("pgvector", "docs", 1, True, requested_count=1)],
        issued_at="2026-01-01T00:00:00+00:00",
        version="0.7.0",
        signer=signer,
        audit_head="b" * 64,
    )
    with open(out, "w") as f:
        json.dump(certificate_to_dict(cert), f, indent=2)
    print(f"wrote {out}")
    print(f"payload_hash: {cert.payload_hash}")
    print("\nRe-presenting this same file must come back charged:false —")
    print("that is the idempotency check, and it is the one that costs money "
          "if it is wrong.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "certificate.json")

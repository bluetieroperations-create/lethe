"""Run a right-to-be-forgotten deletion for one candidate and write the signed
certificate. Run: python forget.py alice.chen@demo.test"""

import json
import os
import sys

import psycopg

from setup import build_lethe


def main():
    url = os.environ["DEMO_DATABASE_URL"]
    subject = sys.argv[1] if len(sys.argv) > 1 else "alice.chen@demo.test"
    with psycopg.connect(url) as conn:
        cert = build_lethe(conn).forget(subject)
    out = {
        "payload": cert.payload, "payload_hash": cert.payload_hash,
        "signature": cert.signature, "public_key": cert.public_key,
    }
    with open("cert.json", "w") as f:
        json.dump(out, f, indent=2)
    print(
        f"\nForgot {subject}: records_deleted={cert.payload['records_deleted']}, "
        f"all_verified={cert.payload['all_verified']}"
    )
    print("Signed certificate written to cert.json")


if __name__ == "__main__":
    main()

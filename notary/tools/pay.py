"""Buy one notarization, the way a paying agent does.

    python notary/tools/pay.py --certificate cert.json --notary http://127.0.0.1:8402

This is the buyer side of the x402 flow, and it exists to be run twice. The
first run pays; the SECOND RUN OF THE SAME CERTIFICATE MUST REPORT
`charged: false` AND NO NEW TRANSACTION. That is the idempotency guarantee the
whole payment design rests on — the notary keys on the certificate's payload
hash so a retry after a lost response cannot be charged again — and the only
way to confirm it against a real chain is to run this twice and look.

It deliberately uses the SDK's own primitives rather than a convenience
wrapper. The first version of this script was written from a blog post, named
an `x402HttpxClient` that does not exist, and could not have worked: three
separate payment-path bugs were found only when a real client was finally
pointed at a real server. Anything here that looks over-explicit is a bug that
was already paid for once.

The buyer key signs an EIP-3009 authorization for real value. Pass it in the
environment, not on the command line, where it lands in shell history:

    export LETHE_NOTARY_BUYER_KEY=0x...        # PowerShell: $env:NAME = "0x..."
"""

import argparse
import json
import os
import sys

import httpx


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--certificate", required=True,
                    help="path to a Lethe deletion certificate (JSON)")
    ap.add_argument("--notary", default="http://127.0.0.1:8402",
                    help="base URL of the notary (default: %(default)s)")
    ap.add_argument("--key", default=os.environ.get("LETHE_NOTARY_BUYER_KEY"),
                    help="buyer private key; prefer LETHE_NOTARY_BUYER_KEY")
    ap.add_argument("--network", default=None,
                    help="CAIP-2 network to register (default: whatever the "
                         "notary quotes, read from /.well-known/notary)")
    ap.add_argument("--out", default=None,
                    help="where to write the receipt (default: "
                         "receipt-<payload hash>.json in the working directory)")
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    with open(args.certificate, encoding="utf-8") as f:
        certificate = json.load(f)

    base = args.notary.rstrip("/")
    with httpx.Client(timeout=args.timeout) as http:
        network = args.network
        if network is None:
            disclosure = http.get(f"{base}/.well-known/notary").json()
            network = disclosure.get("network")
            kind = disclosure.get("network_kind")
            if disclosure.get("paid"):
                print(f"notary quotes {disclosure.get('price')} on {network} ({kind})")
                if kind == "testnet":
                    print("  -> testnet: this is not real money")
                elif kind != "mainnet":
                    print("  -> UNRECOGNIZED NETWORK. Check before paying.")
            else:
                print("notary is running free; no payment will be made")

        first = http.post(f"{base}/notarize", json=certificate)
        if first.status_code != 402:
            return _report(first, args.out)

        # 402 carries the requirements in a header, not the body. Decoding it
        # needs x402[evm]; a bare x402 install fails here with an ImportError.
        from eth_account import Account
        from x402 import x402ClientSync
        from x402.http import (
            PAYMENT_SIGNATURE_HEADER,
            decode_payment_required_header,
            encode_payment_signature_header,
        )
        from x402.mechanisms.evm.exact.register import register_exact_evm_client
        from x402.mechanisms.evm.signers import EthAccountSigner

        if not args.key:
            print("payment required, but no buyer key: set LETHE_NOTARY_BUYER_KEY",
                  file=sys.stderr)
            return 2

        # The requirements ride in a header, not the body. A 402 without it
        # is a notary that cannot be paid — a proxy stripping the header, or a
        # server that is not speaking x402 — and saying so beats a KeyError.
        quote = first.headers.get("PAYMENT-REQUIRED")
        if not quote:
            print("the notary answered 402 but sent no PAYMENT-REQUIRED header, "
                  "so there is nothing to pay. Check for a proxy stripping "
                  "headers, or that this URL is really a notary.", file=sys.stderr)
            return 2

        required = decode_payment_required_header(quote)
        client = x402ClientSync()
        register_exact_evm_client(
            client, EthAccountSigner(Account.from_key(args.key)), networks=network)
        # Signs an authorization to move the quoted amount. Nothing has moved
        # yet: the notary settles it, and only if it decides work is owed.
        payload = client.create_payment_payload(required)

        paid = http.post(
            f"{base}/notarize", json=certificate,
            headers={PAYMENT_SIGNATURE_HEADER: encode_payment_signature_header(payload)},
        )
        return _report(paid, args.out)


def _report(response: httpx.Response, out: str | None) -> int:
    body = response.json()
    print(f"\nHTTP {response.status_code}")
    if not body.get("ok"):
        print(json.dumps(body, indent=2))
        return 1

    print(f"  charged:           {body.get('charged')}")
    print(f"  already_witnessed: {body.get('already_witnessed')}")
    print(f"  witness_recorded:  {body.get('witness_recorded')}")
    payment = body.get("payment") or {}
    if payment:
        print(f"  transaction:       {payment.get('transaction')}")
        print(f"  settled:           {payment.get('settlement_confirmed')}")
        if payment.get("settlement_confirmed") is False:
            print("  -> settlement UNCONFIRMED: the facilitator did not answer. "
                  "The money may or may not have moved; check the chain.")
    if body.get("witness_recorded") is False:
        print("  -> KEEP THIS RECEIPT. The notary could not record it.")

    receipt = body.get("receipt")
    if receipt:
        # Named after the certificate, and never silently overwritten. A fixed
        # "receipt.json" means buying a second certificate destroys the first
        # receipt — and the receipt IS the evidence, so that is the one file
        # this tool must not lose. (Measured: it did, before this.) Re-running
        # the same certificate rewrites an identical file, because the notary
        # returns the original receipt rather than minting a second one.
        payload_hash = receipt.get("payload", {}).get("certificate_payload_hash", "")
        path = out or f"receipt-{payload_hash[:16] or 'unknown'}.json"
        serialized = json.dumps(receipt, indent=2)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                if f.read() != serialized:
                    print(f"\n{path} already exists and holds a DIFFERENT receipt. "
                          f"Refusing to overwrite it; pass --out to choose another "
                          f"name.", file=sys.stderr)
                    return 1
        with open(path, "w", encoding="utf-8") as f:
            f.write(serialized)
        print(f"\nreceipt written to {path} — this is the evidence, not the log entry")

    if body.get("charged"):
        print("\nRun this again with the same certificate. It must print "
              "charged: false and move no money.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

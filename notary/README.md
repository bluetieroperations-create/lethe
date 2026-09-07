# lethe-notary

A paid countersigning witness for Lethe deletion certificates, billed per
certificate over [x402](https://x402.org/).

## What it sells

A Lethe certificate is self-attestation, and says so in its own claim text: the
operator generates the key, performs the deletion, signs the certificate, and
stamps it with their own clock. `docs/anchoring.md` names the consequence —
nothing in the artifact brings in a party the operator does not control.

This service is that party. Per certificate it adds three things the operator
cannot manufacture:

| | |
|---|---|
| An independent clock | `witnessed_at` is the notary's, not the issuer's |
| An independent signature | a second key, held by someone else, over the certificate's hash |
| **A copy of the audit head, off-site** | the part that actually matters |

The third is what the other two are for. Lethe's hash chain cannot detect
tip-truncation: dropping the most recent entries leaves a shorter chain that is
perfectly self-consistent, and `verify_chain()` still returns VALID.
`docs/anchoring.md` says the only fix is a copy of the head living somewhere the
operator cannot reach. This is that place, as a service — and
`tests/test_truncation_detection.py` runs the whole scenario against a real
database: three real deletions, notarized, then the operator drops entries.
Lethe alone still says VALID. The witness log convicts them.

## What a receipt does not say

The notary sees a 2.3 KB JSON document and nothing else. It has no access to
the issuer's database, cannot observe the deletion, and cannot know that the
key in the certificate belongs to the organisation presenting it. So a receipt
attests that a certificate with this payload hash was **presented** at this
time and was **internally valid**, and that it named this `audit_head`. It does
not attest to the presenter's identity, or that the deletion happened, or that
anything else in the certificate is true. The full text is served at
`/.well-known/notary` and reproduced in every receipt.

Overclaiming here would poison the product. The value is a witness, not a
blessing.

## Why per-certificate payments, and why x402

The caller is an agent. Agents cannot complete signup flows, have no email
addresses, and do not survive token rotation — but they sign structured
payloads in milliseconds. x402 inverts the credential problem: the server
trusts a signature on a payment instead of a token issued in advance. For a
per-certificate service with no accounts, that is the entire integration.

**Who pays.** The data controller, buying evidence about their own compliance.
Nothing here sits between a data subject and their erasure. GDPR Art. 12(5)
requires actions under Arts. 15–22 to be free of charge; a paywall in that path
would be unlawful and self-defeating for a tool whose product is provable
compliance.

**What is free, permanently:** witness retrieval, the discovery document, and
health. Witness retrieval is the query an operator runs *during a dispute* —
charging for it, or being unreachable, at that moment would make the evidence
worthless.

**What is never charged for:** a certificate that fails verification (the
customer must not pay for a refusal), and a certificate already witnessed (no
new work, no new money — and no second receipt disagreeing with the first about
when it was seen).

## Endpoints

| | | |
|---|---|---|
| `POST /notarize` | **paid** | verify a certificate, countersign, record the head |
| `GET /challenge` | free | a single-use nonce |
| `POST /witness` | free | every head witnessed for your key |
| `GET /.well-known/notary` | free | notary public key, key id, claim text, price |
| `GET /health` | free | |

**No accounts.** Two proofs, both signatures: x402 for payment, and a signed
challenge for reading your own witness log. An operator who can sign with the
key their certificates name is, by construction, the party entitled to that
log. Challenges are single-use — a replayable nonce is a bearer token with
extra steps, which is what this avoids.

### Never sign the bare nonce

You prove key control with the **same key that signs your certificates**, and
the notary chooses the nonce. Signing a raw server-supplied string with that
key is a signing oracle: a malicious or compromised notary can serve a
canonical certificate payload *as* the nonce, and a naive client hands back a
valid certificate signature. The attacker wraps it in an envelope and holds a
certificate that verifies against your published key, attesting to deletions
that never happened. This was demonstrated end to end against the first cut of
this service.

So sign the domain-separated message, which `/challenge` hands you verbatim in
the `sign` field:

```
lethe-notary/challenge/v1:<notary_key_id>:<nonce>
```

A certificate payload is canonical JSON and always begins with `{`, so a
message with this prefix can never be one. The notary's own key id is included
so a signature harvested by one notary does not authenticate at another. The
server **rejects** a bare-nonce signature rather than accepting both forms —
accepting both would leave the oracle open.

```python
issued = requests.get(f"{NOTARY}/challenge").json()
requests.post(f"{NOTARY}/witness", json={
    "public_key": operator.public_key_b64(),
    "nonce": issued["nonce"],
    "signature": operator.sign(issued["sign"].encode()),   # NOT issued["nonce"]
})
```

### Page the witness query to the end

`/witness` returns at most 1000 heads per call, with `complete` and
`next_after`. **Do not conclude anything from a page where `complete` is
false.** A head that was witnessed but not returned looks exactly like a head
that was never witnessed, which is the opposite of what the evidence says.
Pass `after: next_after` until `complete` is true.

## Why the notary does not chain its own log

The witness log is append-only but not hash-chained, and that is deliberate:
chaining it would only let the notary prove things to itself. **Your receipt is
the authoritative artifact** — it is signed by the notary's published key, and
you hold it. A notary that later denied witnessing your certificate would be
contradicted by a signature it cannot repudiate. `/witness` is a convenience
for finding what you were given; it is not the evidence. Keep your receipts.

## The log is private

A public log would make the truncation argument stronger, but it would publish
deletion metadata: which key deleted what, when, how often, under which table
names. That is the operator's business, not the notary's. The log is
append-only and readable only by whoever controls the key that wrote to it.

## Running it

```bash
pip install -e .                # from this directory; installs lethe-delete too
lethe-notary keygen --out notary.key          # back this up offline
export LETHE_NOTARY_KEY_FILE=notary.key
export LETHE_NOTARY_PAY_TO=0xYourAddress
export LETHE_NOTARY_PRICE='$0.02'
lethe-notary serve
```

If `lethe-notary` is not found, its console script landed in a Scripts/bin
directory that is not on PATH. Every command also works as a module, which
sidesteps PATH entirely:

```bash
python -m lethe_notary.cli serve
```

On Windows PowerShell, environment variables are `$env:NAME = "value"`, and
the price must be in **single** quotes — `$env:LETHE_NOTARY_PRICE = '$0.02'` —
so the shell does not try to expand `$0`.

The signing key **is** the service: everything a customer buys is a signature
from it, and every receipt already issued becomes unverifiable if it is lost.

| Variable | Default | |
|---|---|---|
| `LETHE_NOTARY_KEY_FILE` | — | required |
| `LETHE_NOTARY_PAY_TO` | — | required unless `LETHE_NOTARY_FREE=1` |
| `LETHE_NOTARY_PRICE` | `$0.01` | |
| `LETHE_NOTARY_NETWORK` | `eip155:84532` | CAIP-2 only — see below |
| `LETHE_NOTARY_FACILITATOR` | `https://x402.org/facilitator` | must be https |
| `LETHE_NOTARY_FREE` | unset | run without charging, deliberately |

It **fails to start** rather than serve wrongly: no `PAY_TO` and no explicit
`FREE=1` is a startup error, because one missing environment variable on a
deploy should not silently give the service away. A plaintext facilitator is
refused. And a preflight asks the facilitator, at boot, whether it can actually
settle the configured scheme and network.

### Networks must be CAIP-2

`eip155:8453`, not `base`. The server will build perfectly well-formed payment
requirements from an alias, and the facilitator even advertises both forms —
but a paying client normalizes to CAIP-2, finds no match, and refuses with *no
payment requirements match registered schemes*. The notary looks healthy and
nobody can buy anything. Startup refuses an alias and names the CAIP-2 form.

### Mainnet needs a different facilitator

The default `https://x402.org/facilitator` advertises **testnet kinds only**
(Base Sepolia and friends). That is why the default network is `base-sepolia`
rather than `base`: a mainnet default would start cleanly and then fail every
paid request. Point `LETHE_NOTARY_FACILITATOR` at a facilitator that settles
mainnet before setting `LETHE_NOTARY_NETWORK=eip155:8453`. The preflight will tell you
if you get this wrong:

```
lethe-notary: facilitator https://x402.org/facilitator cannot settle scheme
'exact' on network 'base' (...). Check .../supported for the kinds it does
settle, or point LETHE_NOTARY_FACILITATOR at one that covers your network.
```

## Relationship to `lethe`

This package depends on `lethe-delete`; nothing in `lethe` depends on it, and
nothing in `lethe` imports a payment SDK. Lethe is a self-hosted compliance
library that runs against the operator's own database, and it must not grow a
wallet. Keeping the notary a separate package is what makes it optional.

## Tests

```bash
pytest                    # offline
pytest -m live            # also contacts the real x402 facilitator
LETHE_TEST_DATABASE_URL=... pytest    # also runs the truncation scenario
```

### Rate limits

`/notarize` allows 2/s (burst 20) per client, `/challenge` 5/s (burst 30);
both answer `429` with `retriable: true`. Behind a proxy, pass `--trust-proxy`
so the limiter buckets by `X-Forwarded-For` — **only** behind a proxy you
control, since otherwise any caller mints a fresh identity per request and the
limiter stops working for exactly the people it exists to stop.

### Back up the witness log

One SQLite file holds the only off-site copy of every customer's audit heads.
It runs in WAL mode with `synchronous=FULL`, so a receipt handed to a customer
is on disk before the response goes out — but that is durability, not backup.

```bash
lethe-notary backup --out /backups/witness-$(date +%F).db
```

Uses SQLite's online backup, so it is a consistent snapshot taken while the
notary keeps serving. Ship it somewhere else, on a schedule.

The dated filename is not decoration: SQLite's backup writes straight over its
destination, so a fixed name would replace yesterday's copy with today's — and
if today's log were empty or truncated, the good copy would be gone. Backing up
onto an existing file is refused; `--overwrite` is there if replacing one is
really the intent.

### Rotating the notary key

Receipts name the key that signed them, so a rotation without a published key
history silently invalidates every receipt already sold. Keep the retired keys
published:

```bash
lethe-notary serve --previous-key <old base64 key> --previous-key <older>
```

They appear in `keys` at `/.well-known/notary`, and a verifier passes that list
to `verify_receipt(receipt, trusted_keys={key_id: public_key})` — the same
shape Lethe uses for certificates.

### If a receipt comes back with `witness_recorded: false`

The countersignature succeeded and you were charged, but the notary could not
write its own copy. **Keep the receipt** — it is the evidence, and it is valid.
What you do not have is coverage by the truncation check for that certificate's
head until the operator reconciles. Re-presenting the certificate later is free.

### Run one process

Idempotency — "this certificate is already witnessed, do not charge again" — is
arbitrated by a per-certificate lock inside the process. Running several notary
workers against one witness database reopens the double-charge race. Run a
single process, or move that arbitration into the database, before scaling out.

**Verified against a real client:** `tests/test_payment_wire.py` (`-m live`)
builds a genuine EIP-3009 payment with the x402 client SDK and drives it
through the server's own charge path — decode, match, verify, settle. Two bugs
lived in that gap until a real client was pointed at the server, because a
stub cannot disagree with itself.

A successful `/notarize` now returns a `payment` block with the settlement's
transaction hash, network and payer, so the buyer has an on-chain reference and
the operator can reconcile without taking this service's word for it. A
settlement that fails yields **402 and no receipt** — the settle response is
the only thing that says money moved, and a receipt handed out over a failed
settlement is the mirror of charging for nothing.

**Settlement is verified.** A real payment has been settled end to end on Base
Sepolia: the client signed an EIP-3009 authorization, the notary decoded it,
matched it to its own requirements, and the facilitator moved 0.01 USDC from
the buyer to the configured payee — transaction `0x27b42be68a…` in block
46487830, method `TransferWithAuthorization`. Everything in this package has
now been exercised against something real.

Testnet, though. Mainnet needs a facilitator that settles it (see above), and
the first mainnet payment deserves the same scrutiny: check the chain, not the
`200`.

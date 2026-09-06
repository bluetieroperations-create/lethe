# External anchoring

Everything else Lethe signs is self-attestation: the operator generates the
key, performs the deletion, and signs the certificate saying it happened.
`issued_at` is their own clock. Anchoring is what brings a party the operator
does not control into that picture.

## Anchor the chain, not the certificate

The obvious design is to timestamp each certificate. Anchoring the **audit
chain head** on a schedule is better, for three reasons:

1. **It covers everything, not just certificates.** Every recorded event —
   `forget_started`, `forget`, `reconcile` — is pinned by the next anchor.
2. **It keeps the authority out of the deletion path.** `forget()` never calls
   a TSA, so an authority that is slow, rate-limited or down degrades your
   anchoring instead of blocking a data-subject request.
3. **It is cheaper.** One call per interval, not one per request.

```bash
export DATABASE_URL=...
lethe anchor                       # anchors the current head
lethe anchor --tsa https://your.qualified.tsa/tsr
```

Run it on a timer — hourly is a reasonable default. The interval is your
resolution: an event is pinned to the window between the anchor before it and
the anchor after it.

## What this does and does not prove

Be precise about this, because the two failure modes behave differently.

**Backdating — prevented.** Once head *N* carries a token, an entry cannot
later be inserted at position *N*: that would change every hash from *N*
onward and contradict the token. You cannot obtain a timestamp dated in the
past, so you cannot manufacture a chain that appears to have contained an
event earlier than it did. This is the property that makes a `forget` event's
recorded time meaningful against the operator themselves.

**Tail truncation — still needs an external copy.** Anchor tokens are stored
*in the chain*, so an operator deleting the most recent entries would delete
the anchor entries with them. RFC 3161 authorities are stateless — the TSA
keeps no record of what it timestamped — so nothing recovers a token you have
destroyed.

Anchoring therefore only closes truncation if a token also lives somewhere the
operator cannot reach. Two cheap ways, both worth doing:

- **Publish anchor tokens.** `lethe anchor --emit anchor-public.json` writes a
  self-contained record — the head that was attested, the raw token, and the
  `openssl` command to check them — which you publish wherever you publish your
  trusted public key. A copy you do not control is the whole point: a token
  that only exists in the chain disappears with the chain.
- **Let recipients be witnesses.** Every certificate names the `audit_head` its
  run started from, so anyone holding a certificate holds evidence of chain
  state at that time. Multiple recipients means multiple independent witnesses,
  at no cost to you.

## Choosing an authority

| | When it fits |
|---|---|
| **`freetsa.org`** (the CLI default) | Getting started. Community-run, free, **no SLA** — do not build a compliance posture on it. |
| **CA-operated free endpoints** (DigiCert, Sectigo, …) | Reliable and fast, but provisioned for code signing — **check the terms of service** before relying on one for compliance artifacts. |
| **eIDAS qualified TSA** (a QTSP on the EU Trusted List) | The one that carries legal weight: a qualified timestamp has a presumption of accuracy of date and time under eIDAS Article 41. Paid, needs a contract. This is the answer once an EU customer's procurement asks. |
| **OpenTimestamps / Bitcoin** | Free, no trusted third party, proofs verifiable forever. Confirmation takes hours, so it cannot be a synchronous anchor — it would need a deferred second anchor. Not currently implemented. |

Lethe talks to any RFC 3161 authority; `--tsa` is the only thing that changes.

### A compatibility note

Some strict RFC 3161 parsers reject real responses from major CAs over DER SET
ordering inside the signature structure. Lethe uses `asn1crypto`, which accepts
them — verified against `freetsa.org` and `timestamp.digicert.com`. If you
verify tokens with other tooling, check it accepts your authority's responses
before committing to that authority.

## Verifying a stored token

The raw RFC 3161 response is kept verbatim (base64) in the anchor entry, so it
is verifiable by anyone with the authority's certificate chain, using any
RFC 3161 implementation — Lethe does not need to be trusted, or present:

```bash
# pull the token and the head it covers out of the audit log
psql "$DATABASE_URL" -tAc "
  SELECT entry->>'token' FROM lethe_audit
  WHERE entry->>'event'='anchor' ORDER BY seq DESC LIMIT 1" | base64 -d > anchor.tsr
psql "$DATABASE_URL" -tAc "
  SELECT entry->>'anchored_head' FROM lethe_audit
  WHERE entry->>'event'='anchor' ORDER BY seq DESC LIMIT 1" | tr -d '\n' > head.txt

openssl ts -reply -in anchor.tsr -text            # what the authority attested

# verify for real, against the authority's published chain
curl -sO https://freetsa.org/files/cacert.pem     # the authority's root
curl -sO https://freetsa.org/files/tsa.crt        # its signing certificate
openssl ts -verify -in anchor.tsr -data head.txt \
    -CAfile cacert.pem -untrusted tsa.crt
# -> Verification: OK
```

`-untrusted` is needed because a TSA's signing certificate is a leaf, not a CA;
without it openssl cannot build the path. Substitute your own authority's
published chain.

**What Lethe checks at anchor time, and what it does not.** `lethe anchor`
verifies the response answers *this* request — granted status, echoed nonce,
matching message imprint — which is what stops a substituted or replayed token
being stored. It does **not** validate the authority's signature chain: that
needs the TSA's root certificate and a trust decision, which belongs to the
verifier rather than the issuer. Archive your authority's chain alongside the
tokens, or the tokens become unverifiable when its certificate expires.

# Threat model

Lethe issues a signed artifact asserting that a person's data was deleted from
your AI memory. This document says plainly **who you have to trust for that
assertion to mean anything**, and what remains true when they are dishonest.

It is written for two readers: an operator deciding how to deploy Lethe, and a
recipient — auditor, regulator, counterparty — deciding what a certificate they
have been handed actually proves.

## What a certificate is

A certificate is a JSON payload signed with the operator's Ed25519 key. From
`lethe.cert/3` the signed payload includes:

| Field | What it establishes |
|---|---|
| `key_id` | Which key epoch signed this. Derived from the public key and re-checked at verification, so it cannot name a key other than the signer. |
| `audit_head` | The tamper-evident audit-chain position this deletion run started from. |
| `issued_at` / `valid_until` | The window during which absence is asserted. **Issuer's own clock.** |
| `timestamp` | External corroboration of `issued_at`. **Currently always `null`.** |
| `declared_scope` | The stores Lethe was configured to sweep — so a reader can infer what was *not* checked. |
| `layers[].residual_count` | The post-delete re-query result backing each `verified_absent`. |
| `all_verified` | True only if at least one layer was found *and* every layer was handled by a real connector, confirmed absent, and actually had records removed this run. |

`claim` restates these limits in prose, inside the signature, so they travel
with the artifact rather than living in documentation that whoever forwards the
certificate can omit.

## The trust boundary

**Lethe is self-attestation.** The operator generates the key, performs the
deletion, signs the certificate asserting it happened, and publishes the public
key used to check it. Every link is the same party.

That is not a defect — it is the honest shape of a self-hosted tool, and
self-hosting is the point (the tool that erases your data never becomes a new
place your data goes). But it bounds what any recipient can conclude, so it
must be stated rather than implied.

### Adversary A — a third party who forges or alters a certificate

**Defended.** Verification requires the operator's public key pinned
out-of-band; the embedded key is compared against it before the signature is
checked, so a self-consistent certificate minted with an attacker's own keypair
fails. `key_id` is recomputed from the embedded key, so substituting another
operator's key to satisfy the pin is rejected earlier still. Any edit to the
payload breaks `payload_hash` and the signature.

**What the recipient must do:** obtain the public key from a channel the
operator does not control at presentation time — a published `/.well-known`
endpoint, contractual documentation — not from the certificate itself, and not
from whoever handed them the certificate. An unpinned check proves only
internal consistency and is not evidence.

### Adversary B — someone with database access, covering their tracks

**Mostly defended.** The audit log is a hash chain: each entry commits to its
predecessor, so altering or removing an entry from the middle breaks the link
and `verify_chain()` fails. From v3 each certificate also names the chain
position its run started from, and the completion entry chains forward carrying
the certificate's `payload_hash` — certificate and chain point at each other,
so neither can be rewritten alone.

**Not defended by the chain alone:** truncating the *tip*. Deleting the most
recent entries leaves a shorter but internally consistent chain. Detecting that
requires the operator to have recorded the head hash out-of-band and to pass it
as `verify_chain(expected_head=…)`.

### Adversary C — the operator

**Largely not defended, and this is the important one.** A recipient's adversary
is usually the operator, and most of Lethe's mechanisms assume the operator is
honest and defending against someone else.

- **Backdating.** `issued_at` is the operator's own clock. Nothing prevents
  issuing a certificate today that claims deletion happened two months ago —
  which matters because Article 17 carries a one-month response deadline, so
  the timestamp is legally load-bearing.
- **Tip truncation.** The "record the head out-of-band" defense requires the
  operator to voluntarily publish evidence against themselves. An operator
  hiding a deletion simply does not.
- **Selective scope.** `declared_scope` is what Lethe was *configured* to
  sweep. An operator can configure fewer connectors than they have stores. The
  certificate is honest about the boundary it drew — it just cannot tell you
  the boundary was drawn honestly.
- **Coverage.** `forget()` deletes exactly what the provenance ledger knows
  about. See "Coverage is ledger-shaped" below.

**What would actually fix this:** anchoring the audit head somewhere the
operator does not control — an RFC 3161 timestamping authority, or periodic
publication of the head into a transparency log. That converts "we assert" into
"a third party can corroborate", and it is the single highest-value change
available to this design. The `timestamp` field exists as the seam for it; it
is `null` in every certificate issued today, and the `claim` says so.

## Coverage is ledger-shaped, not store-shaped

`forget()` deletes the record IDs the provenance ledger has tagged for a
subject. A write that bypassed the wrapper was never tagged, so Lethe does not
know it exists — and the certificate can still read `all_verified: true`,
because every layer Lethe *knew about* was verified.

Read `all_verified` as **"everything Lethe was told about is gone"**, never as
**"nothing about this person remains"**. `lethe reconcile` (see the README)
exists to narrow this gap by scanning a store directly rather than trusting the
ledger; it is a detection tool, not a guarantee.

## Other residual risks

- **Key compromise.** Anyone holding the private key can mint certificates that
  verify for that epoch, including backdated ones. There is no revocation
  mechanism; `key_id` plus published key epochs limit the blast radius to a
  known window. See [key-rotation.md](key-rotation.md).
- **Salt compromise.** `subject_hash` is HMAC-SHA256 keyed by a per-deployment
  salt. It is non-reversible only while the salt is secret — an attacker with
  the salt can test candidate subject IDs offline and link ledger rows to
  people. Treat the salt as a secret of the same grade as the signing key.
- **Eventual consistency.** Absence is verified by re-query against one
  configured endpoint at one moment. For stores with asynchronous propagation
  (Pinecone), a replica may still serve the record afterwards.
- **Backups and model weights.** Out of scope by design. Data already baked
  into trained weights is not addressed by any deletion Lethe performs, and the
  certificate says so.
- **Re-verification after `valid_until`.** The certificate advises re-verifying
  once the window lapses. By default `forget()` purges the provenance map on
  success (data minimisation), which removes the record IDs needed to re-query.
  Set `retain_verification_ids=True` to keep those IDs in a separate retention
  table so `reverify()` can re-query them — at the cost of holding identifiers
  linked to a subject you just erased. The certificate's `reverifiable` field
  records which way the deployment was configured.

## Summary

| Claim | Holds against a third party | Holds against a dishonest operator |
|---|---|---|
| This certificate was issued by the named key | Yes (pinned key + `key_id`) | Yes |
| The payload has not been altered | Yes | Yes |
| The audit log has no mid-chain edits | Yes | Yes |
| The audit log has not been truncated | Only with an externally recorded head | No |
| Deletion happened at `issued_at` | Yes | **No** — issuer's clock, unanchored |
| Everything Lethe knew about was deleted | Yes | Yes |
| Nothing about this person remains | **No** — ledger-shaped coverage | **No** |

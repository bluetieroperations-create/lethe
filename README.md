# Lethe — the forget button for AI

[![CI](https://github.com/bluetieroperations-create/lethe/actions/workflows/ci.yml/badge.svg)](https://github.com/bluetieroperations-create/lethe/actions/workflows/ci.yml)

**Everyone built AI memory. Nobody built the provable delete.** Lethe deletes a
person's data from your AI memory (vector store, RAG index, caches, logs) on a
GDPR/CCPA request — and hands you a **signed certificate** proving it happened.

Self-hosted: Lethe runs inside *your* infrastructure. The tool that erases your
data never becomes a new place your data goes.

> **Status:** v0.2, early but real. Connectors: **pgvector** + **Pinecone**.
> The full delete loop is tested end-to-end against real Postgres (pgvector);
> the Pinecone connector is unit-tested against a mock `Index`, not live
> Pinecone. Hardened through four rounds of adversarial self-review (internal,
> not third-party). Not published to PyPI yet — install from source (see
> Quickstart).

---

## Why

GDPR **Article 17** (right to erasure) covers personal data in agent memory —
conversation history, retrieved chunks, **and embeddings**. Fines reach 4% of
global revenue, and the EU's data-protection authorities are actively auditing
deletion (the EDPB's 2026 sweep checked 764 organizations and found "lack of
automated deletion mechanisms" almost everywhere). Meanwhile *no vector
database offers provable deletion* — teams hand-roll it.

If you sell AI to enterprises, you've probably hit the sharper version: a
customer's security review asks *"prove you can delete a user's data from your
AI,"* and you can't. Lethe is the answer you hand them.

## How it works

```
tag(subject → record)  →  forget(subject)  →  delete from your stores
                                            →  verify the records are gone
                                            →  signed deletion certificate
                                            →  tamper-evident audit entry
```

You never have to remember to call `tag` everywhere: wrap your vector store
once and writes tag themselves.

## Quickstart (drop-in)

```bash
pip install -e .            # from source for now (PyPI soon)
lethe keygen --out lethe_key.bin     # one-time: your signing key (prints the public key)
export DATABASE_URL=...              # your own Postgres
export LETHE_SALT=...                # a secret; pseudonymizes subjects in the ledger
lethe init-db                        # creates Lethe's ledger + audit tables
```

Wire Lethe to your store, then **wrap your vector store** so every write is
tagged for deletion:

```python
import os, psycopg
from lethe import Lethe
from lethe.ledger import Ledger
from lethe.audit import AuditLog
from lethe.signing import Signer
from lethe.connectors.pgvector import PgVectorConnector
from lethe.integrations.langchain import LetheVectorStore

conn = psycopg.connect(os.environ["DATABASE_URL"])
lethe = Lethe(
    ledger=Ledger(conn),
    audit=AuditLog(conn),
    signer=Signer.from_private_bytes(open("lethe_key.bin", "rb").read()),
    connectors={"pgvector": PgVectorConnector(conn)},
    salt=os.environ["LETHE_SALT"],
)

# Wrap once. Declare which metadata field names the data subject.
store = LetheVectorStore(
    my_vectorstore, lethe,            # any LangChain-style store
    store="pgvector", namespace="docs",
    subject_key="user_id",
    id_key="doc_id",                  # recommended: bind ids from metadata
)

# Use it like a normal vector store — tagging happens automatically.
store.add_documents([Document(page_content="...",
                              metadata={"user_id": "alice@example.com",
                                        "doc_id": "doc-123"})])
```

When a deletion request comes in:

```python
cert = lethe.forget("alice@example.com")   # deletes everywhere + returns the certificate
```

Verify a certificate (pin the operator's *published* public key — a certificate
that vouches for itself proves nothing):

```python
from lethe.certificate import verify_certificate
assert verify_certificate(cert, trusted_public_key=PUBLISHED_PUBKEY)
```

## The certificate

Ed25519-signed, tamper-evident, independently verifiable (schema `lethe.cert/3`).
It states exactly what happened and **scopes its claim honestly** — *"deleted
across these retrieval layers and verified absent,"* never "perfectly erased
everywhere" (backups and model weights are out of scope by definition).
`verified_absent` means Lethe re-queried the configured endpoint immediately
after deleting and saw the records gone *at issue time* — it is not a guarantee
against read replicas, query caches, or asynchronous propagation (notably
Pinecone, whose deletes are eventually consistent).

The certificate carries the **evidence**, not just the boolean:

- **`valid_until`** — the absence is asserted from `issued_at` up to this time; a
  deletion cert is not eternal, so re-verify past it (the underlying index can
  change). Set the window with `Lethe(cert_validity=…)` or `forget(valid_for=…)`.
- **`declared_scope`** — the stores Lethe was configured to sweep, so a reader can
  see what was in scope *and infer what was not checked*.
- per-layer **`residual_count`** + **`verify_method`** — how many records the
  post-delete re-query still found (`0` backs `verified_absent`) and the exact
  query that produced it. `index_version` is a nullable slot for a store-native
  index fingerprint.
- **`key_id`** — which key epoch signed this, derived from the public key and
  re-checked at verification, so rotating keys never orphans old certificates.
  See [docs/key-rotation.md](docs/key-rotation.md).
- **`audit_head`** — the audit-chain position this deletion run started from, so
  the certificate and the tamper-evident log point at each other.
- **`reverifiable`** — whether the issuer retained what a later re-query needs
  (see `lethe reverify`); the re-verify advice is scoped to it.
- **`timestamp`** — reserved slot for external corroboration of `issued_at`
  (e.g. RFC 3161). **Always `null` today**, and the claim says so: absent it,
  `issued_at` is the issuer's own clock.

Older `lethe.cert/1` and `lethe.cert/2` certificates still verify.

**Read [docs/threat-model.md](docs/threat-model.md) before relying on a
certificate.** It sets out who you must trust and what stays true when they are
dishonest — in particular that Lethe is self-attestation, so a certificate
proves far more against a third party than against the operator who issued it.

```json
{
  "schema": "lethe.cert/3",
  "all_verified": true,
  "records_deleted": 2,
  "valid_until": "2026-07-21T00:00:00+00:00",
  "key_id": "ed25519:3f9c1a2b…",
  "audit_head": "9d4f…",
  "timestamp": null,
  "reverifiable": false,
  "declared_scope": ["pgvector", "pinecone"],
  "layers": [{"store": "pgvector", "namespace": "docs",
              "deleted_count": 2, "verified_absent": true, "erased": true,
              "residual_count": 0,
              "verify_method": "pgvector: SELECT count(*) WHERE id = ANY(:ids); n_ids=2",
              "index_version": null}],
  "claim": "Deleted across the listed retrieval layers and verified absent ...",
  "signature": "…", "public_key": "…"
}
```

## CLI

| Command | Purpose |
|---|---|
| `lethe keygen --out KEY` | Create the Ed25519 signing key (prints the public key to publish) |
| `lethe init-db` | Create Lethe's ledger + audit tables in your Postgres |
| `lethe forget SUBJECT` | Delete a subject everywhere; prints the signed certificate |
| `lethe verify CERT --public-key PUB` | Verify a certificate against the operator's published key |
| `lethe ledger-scope` | Show what the ledger holds vs the allowlist; `--purge-disallowed` clears the rest |
| `lethe reconcile SUBJECT --target STORE:NS:FIELD` | Ask the stores what they hold for a subject, vs what the ledger knows |
| `lethe reverify SUBJECT` | Re-check absence after `valid_until` (needs `retain_verification_ids`) |
| `lethe anchor` | Timestamp the audit head with an RFC 3161 authority (run on a schedule) |
| `lethe audit-head` | Print the audit-log tip hash (record it out-of-band) |
| `lethe verify-audit --expected-head H` | Detect tampering/truncation of the audit log |

## For AI agents (MCP)

Lethe ships an MCP server so autonomous agents can execute provable deletion
and verify certificates machine-to-machine:

    pip install "lethe-delete[mcp]"
    lethe-mcp

Destructive deletes are two-step (preview → confirm token → forget), and any
agent can verify a certificate with zero infrastructure (you still need the
operator's published public key to pin against). Full guide:
[docs/m2m.md](docs/m2m.md).

## Security model & honest limits

- **Self-hosted.** The SDK and the provenance ledger run in your own Postgres.
  Lethe-the-project never sees your data. The salt stays in your app.
- **No raw PII in the ledger.** Subjects are stored as HMAC-SHA256 hashes.
- **Verify with a pinned key.** An unpinned certificate check only proves
  internal consistency; always pin your published public key.
- **`verified_absent` is a point-in-time re-query, not a replication proof.**
  For eventually-consistent stores (Pinecone) a delete may not have propagated
  to every replica at issue time. pgvector verifies read-your-writes on one
  connection; a read-replica DSN would reintroduce the gap.
- **Audit truncation needs an out-of-band head.** Mid-chain edits are caught
  automatically; detecting deletion of the *most recent* entries requires
  recording `lethe audit-head` out-of-band and checking `verify-audit
  --expected-head`.
- **Coverage = what flows through Lethe.** Writes that bypass the wrapper/`tag`
  aren't tracked, so `all_verified` means *"everything Lethe was told about is
  gone"* — never *"nothing about this person remains"*. `lethe reconcile` asks
  the store directly and reports what the ledger never saw; it is a detection
  tool, not a guarantee.
- **Pre-existing data** (written before you adopted Lethe) is found by
  `lethe reconcile` where the store exposes a queryable subject field, and can
  be tagged for deletion with `--tag-untracked`.
- **Restrict what a deployment may delete from.** `lethe_tag` takes a namespace
  from its caller, so without an allowlist an agent driving the MCP server can
  direct a delete at any table the database user can write. Set
  `LETHE_ALLOWED_NAMESPACES=pgvector:documents,pgvector:chat_turns` (or
  `Lethe(allowed_namespaces=…)`); `lethe status` reports whether a deployment is
  running unrestricted. Unset means unrestricted, for backward compatibility.
- **Self-attestation, unless you anchor.** The operator signs their own
  certificate and `issued_at` is their own clock. `lethe anchor` timestamps the
  audit head with an external RFC 3161 authority, which closes backdating; see
  [docs/anchoring.md](docs/anchoring.md) for what it does and does not prove,
  and [docs/threat-model.md](docs/threat-model.md) for the wider picture.
- **Not erasure from backups or model weights.** Out of scope by design; the
  certificate says so.

## Connectors

- **pgvector** (and any Postgres table) — `PgVectorConnector`
- **Pinecone** — `PineconeConnector` (pass your `Index`). Note: Pinecone
  deletes are eventually consistent, so `verified_absent` is asserted at issue
  time against the queried endpoint, not proven across replicas. Covered by
  unit tests against a fake `Index` plus a live integration test against real
  Pinecone (`pytest -m live`, needs `PINECONE_API_KEY`).
- Roadmap: Weaviate, Qdrant, Redis, conversation logs.

## License

[Apache-2.0](LICENSE) — permissive, with an explicit patent grant.

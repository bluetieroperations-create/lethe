# Lethe — the forget button for AI

**Everyone built AI memory. Nobody built the provable delete.** Lethe deletes a
person's data from your AI memory (vector store, RAG index, caches, logs) on a
GDPR/CCPA request — and hands you a **signed certificate** proving it happened.

Self-hosted: Lethe runs inside *your* infrastructure. The tool that erases your
data never becomes a new place your data goes.

> **Status:** v0.1, early but real. Connectors: **pgvector** + **Pinecone**.
> The full delete loop is tested end-to-end against real Postgres and has been
> through four independent security-audit passes. Not yet on PyPI.

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

Ed25519-signed, tamper-evident, independently verifiable. It states exactly what
happened and **scopes its claim honestly** — *"deleted across these retrieval
layers and verified absent,"* never "perfectly erased everywhere" (backups and
model weights are out of scope by definition).

```json
{
  "all_verified": true,
  "records_deleted": 2,
  "layers": [{"store": "pgvector", "namespace": "docs",
              "deleted_count": 2, "verified_absent": true, "erased": true}],
  "claim": "Deleted across the listed retrieval layers and verified absent. ...",
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
| `lethe audit-head` | Print the audit-log tip hash (record it out-of-band) |
| `lethe verify-audit --expected-head H` | Detect tampering/truncation of the audit log |

## Security model & honest limits

- **Self-hosted.** The SDK and the provenance ledger run in your own Postgres.
  Lethe-the-project never sees your data. The salt stays in your app.
- **No raw PII in the ledger.** Subjects are stored as HMAC-SHA256 hashes.
- **Verify with a pinned key.** An unpinned certificate check only proves
  internal consistency; always pin your published public key.
- **Coverage = what flows through Lethe.** Writes that bypass the wrapper/`tag`
  aren't tracked. Wrap your store, or tag explicitly.
- **Pre-existing data** (written before you adopted Lethe) needs retroactive
  discovery — on the roadmap, not in v0.1.
- **Not erasure from backups or model weights.** Out of scope by design; the
  certificate says so.

## Connectors

- **pgvector** (and any Postgres table) — `PgVectorConnector`
- **Pinecone** — `PineconeConnector` (pass your `Index`)
- Roadmap: Weaviate, Qdrant, Redis, conversation logs.

## License

TBD — MIT or Apache-2.0 recommended for dev-led adoption. Add a `LICENSE` file
before publishing.

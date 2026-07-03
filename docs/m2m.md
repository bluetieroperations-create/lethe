# Lethe for machines (M2M / agent-to-agent)

Lethe's MCP server lets autonomous agents execute provable deletion and
machine-verify the resulting certificate. No human in the loop; the
destructive step is guarded by a two-step confirm token instead.

## Install & run

    pip install "lethe[mcp]"
    lethe-mcp        # stdio MCP server

Full mode (can delete) — set:

    LETHE_DATABASE_URL   Postgres + pgvector, holds ledger/audit + your data
    LETHE_SALT           subject-hashing salt (keep stable per deployment)
    LETHE_KEY_FILE       Ed25519 private key (make one: lethe keygen --out key.bin)
    LETHE_TRUSTED_PUBLIC_KEY   optional, default pin for lethe_verify_certificate

Verify-only mode (zero infrastructure) — set NOTHING. The server exposes only
certificate verification; any agent can check "was this really deleted?"

Claude Code registration example:

    claude mcp add lethe -- lethe-mcp

## Tools

| Tool | Kind | Purpose |
|---|---|---|
| `lethe_status` | read | mode, connectors, audit head, versions |
| `lethe_tag` | write | bind (store, namespace, record_id) to a subject |
| `lethe_forget_preview` | read | blast radius + single-use `confirm_token` (TTL 600 s) |
| `lethe_forget` | **destructive** | execute deletion, return signed certificate |
| `lethe_verify_subject` | read | re-check absence per layer, deletes nothing |
| `lethe_verify_certificate` | read | schema + key-pinned Ed25519 verification |

## The two-step flow

1. `lethe_forget_preview(subject_id)` → per-layer counts + `confirm_token`.
2. `lethe_forget(subject_id, confirm_token)` → executes only if the data still
   matches what the preview showed.

Errors are machine-branchable: `{"ok": false, "error": {"code", "message",
"retriable"}}` with codes `SUBJECT_NOT_FOUND`, `NO_LAYERS_CONFIGURED`,
`STALE_PREVIEW`, `TOKEN_EXPIRED`, `TOKEN_INVALID`, `TOKEN_REUSED`,
`CERTIFICATE_TOO_LARGE`, `CONNECTOR_ERROR` (retriable). On
`STALE_PREVIEW`/`TOKEN_*`, re-preview and confirm again. Tokens are
process-local: a server restart voids them. Consuming a token is an
irrevocable pre-commit — if the delete fails after confirmation, re-preview
and confirm again (under-executing always beats double-executing).

## Verifying a certificate you were handed

The certificate is self-describing JSON (schema `lethe.cert/1`, published at
`lethe/schemas/certificate-v1.json`) but NOT self-authenticating: always pin
the issuing operator's public key, obtained out-of-band (their docs, their
/.well-known, a prior trusted exchange).

    lethe_verify_certificate(certificate=<cert JSON>, public_key="<base64>")

→ `{"valid": true|false, "reasons": [...]}` with reasons
`SCHEMA_MISMATCH`, `KEY_MISMATCH`, `PAYLOAD_TAMPERED`, `BAD_SIGNATURE`.

The load-bearing payload fields: `all_verified` (true only if every found
layer was genuinely erased AND at least one layer was found),
`records_deleted`, `layers[]` with per-layer `erased`. A certificate with
`all_verified: false` is an honest record of a partial/failed deletion — do
not treat it as proof of erasure.

## Roadmap (v2)

Cross-org A2A deletion requests; x402-paid verification / hash
counter-signing; human-confirmation gate as a config option; HTTP transport.

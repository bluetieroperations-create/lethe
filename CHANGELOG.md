# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Certificate payloads carry their own schema version (`lethe.cert/N`),
independent of the package version. **Every certificate schema remains
verifiable by later releases** — a certificate is meant to outlive the code
that issued it.

## [0.3.0] — 2026-09-05

Version 0.2.1 was prepared but never tagged or published; its contents are
included here.

### Added

- **Certificate schema `lethe.cert/3`.** `lethe.cert/1` and `lethe.cert/2`
  certificates still validate and verify.
  - `key_id` — which key epoch signed the certificate, derived from the public
    key (`ed25519:` + truncated SHA-256). Recomputed and checked at
    verification, so a certificate cannot name a key other than its signer.
    New reason code `KEY_ID_MISMATCH`.
  - `audit_head` — the audit-chain position the deletion run started from, so
    the certificate and the tamper-evident log reference each other.
  - `reverifiable` — whether the issuer retained what a later re-query needs.
  - `timestamp` — reserved, currently always `null`: a slot for external
    corroboration of `issued_at` (e.g. RFC 3161) so adding one later needs no
    schema v4.
- **`reconcile()` / `lethe reconcile`** — compares what a store actually holds
  for a subject against what the provenance ledger knows, exposing records that
  bypassed the wrapper. `--tag-untracked` tags findings for deletion. New
  optional connector capability `scan()`, implemented for pgvector.
- **`reverify()` / `lethe reverify`** — re-checks absence after `valid_until`,
  enabled by the new `Lethe(retain_verification_ids=True)`.
- **External anchoring** — `lethe anchor` timestamps the audit chain head with
  an RFC 3161 authority, and records the raw token as a chain entry. Anchoring
  the head rather than each certificate covers every recorded event, keeps the
  authority out of the deletion path (a TSA outage never blocks a data-subject
  request), and costs one call per interval. Closes backdating: an entry cannot
  be inserted before an anchored head, and a timestamp dated in the past cannot
  be obtained. Optional dependency: `pip install 'lethe-delete[anchor]'`.
  See `docs/anchoring.md`.
- **`docs/anchoring.md`** — choosing an authority (including eIDAS qualified
  timestamps), what anchoring does and does not prove, and how to verify a
  stored token with `openssl ts`.
- **`docs/threat-model.md`** — who must be trusted for a certificate to mean
  anything, and what holds against a third party versus a dishonest operator.
- **`docs/key-rotation.md`** — rotation, verifying older certificates, and the
  key-compromise case.
- **`SECURITY.md`** — private vulnerability reporting and scope.
- **CI** — GitHub Actions on Python 3.11 and 3.12 against a real Postgres
  service, including a guard that fails the build if any test is skipped.
- **Release workflow** — pushing a `v*` tag publishes the GitHub Release, with
  notes taken from this file. It refuses to publish if the tag disagrees with
  `lethe/version.py`, or if the changelog section is missing or still marked
  unreleased, so a tag and its release cannot describe different things.

### Changed

- The certificate `claim` now discloses self-issuance inside the signed
  payload: `issued_at` is the issuer's own clock, and the signature proves only
  that the key holder produced it. The limitation travels with the artifact.
- The claim's re-verify advice is scoped to `reverifiable`, rather than
  advising an action the default configuration makes impossible.

### Fixed

- **`mcp` 2.x broke the MCP server.** The `mcp` extra declared `mcp>=1.9`,
  which resolves to 2.x where `FastMCP` was renamed to `MCPServer`, so
  `lethe.mcp` raised `ModuleNotFoundError` on import. Pinned to `mcp>=1.9,<2`;
  migrating to the 2.x API is separate work.
- The package version had drifted from the test suite (`test_version` still
  asserted `0.1.0` after the 0.2.0 release). `pyproject` now derives the
  version from `lethe/version.py`, so the two cannot diverge.
- Two DB tests raised `KeyError` instead of skipping when
  `LETHE_TEST_DATABASE_URL` was unset.
- Test isolation: the new retention table is now dropped between tests.

## [0.2.0] — 2026-07-06

### Added

- **Certificate schema `lethe.cert/2`**, with `lethe.cert/1` still verifying.
  - `valid_until` — machine-readable freshness bound; absence is asserted from
    `issued_at` up to it. `build_certificate` refuses a `valid_until` at or
    before `issued_at`.
  - Per-layer `residual_count` and `verify_method` — the post-delete re-query
    result and the query behind it, via the optional connector `verify_detail()`.
    Connectors implementing only boolean `verify()` report `null`, never a
    false `0`.
  - `declared_scope` — the stores Lethe was configured to sweep.
  - `index_version` — nullable slot for a store-native index fingerprint.
- Version-aware verifier: each schema version validates against its own
  JSON Schema, so a v1-declared payload cannot carry v2 fields.

### Fixed

- `timedelta(0)` falsy-coalescing: an explicit zero validity window silently
  became the 30-day default.
- A self-nullifying certificate with `valid_until <= issued_at` could be minted.
- `tests/conftest` scrubs the DSN from the connection repr, so a failing DB
  test cannot leak the host into output.

## [0.1.0] — 2026-06

First working version.

### Added

- Signed deletion certificates (Ed25519, canonical JSON payload) with a scoped
  claim, plus `lethe.cert/1` schema and a structured key-pinned verifier.
- Provenance ledger and hash-chained tamper-evident audit log on Postgres.
- Connector interface with pgvector and Pinecone implementations.
- `LetheVectorStore` wrapper that auto-tags writes for LangChain-style stores.
- MCP server (`lethe-mcp`) with a two-step confirm-token guard for `forget`.
- CLI: `keygen`, `init-db`, `forget`, `verify`, `audit-head`, `verify-audit`.

### Security

- Key pinning is mandatory in `verify_certificate`: an unpinned check proves
  only self-consistency, not authenticity.
- Audit truncation head-pin, honest certification of unknown stores, and fixes
  for untagged-write and cross-subject deletion leaks in the wrapper.

[0.3.0]: https://github.com/bluetieroperations-create/lethe/releases/tag/v0.3.0
[0.2.0]: https://github.com/bluetieroperations-create/lethe/releases/tag/v0.2.0

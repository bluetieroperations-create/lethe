# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Certificate payloads carry their own schema version (`lethe.cert/N`),
independent of the package version. **Every certificate schema remains
verifiable by later releases** — a certificate is meant to outlive the code
that issued it.

## [0.7.0] — 2026-09-07

### Added

- **`notary/` — a paid countersigning witness, billed over
  [x402](https://x402.org/).** A separate distribution (`lethe-notary`); nothing
  in `lethe` depends on it and `lethe` gains no payment dependency.

  It sells the one thing Lethe structurally cannot give itself. A certificate
  is self-attestation — `docs/anchoring.md` says nothing in the artifact brings
  in a party the operator does not control — so the notary is that party: an
  independent clock, an independent signature, and **a copy of the audit head
  held off-site**. That last one is the product, because tip-truncation is
  undetectable from inside the chain; the notary's witness log is the copy the
  operator cannot reach.

  A receipt claims only what the notary can support: that a certificate was
  *presented* at a time, is *internally valid*, and named this head. Not the
  presenter's identity, and not that the deletion happened.

  The controller pays, for evidence about their own compliance — nothing sits
  between a data subject and their erasure (GDPR Art. 12(5)), and witness
  retrieval, the query run during a dispute, is permanently free. A certificate
  that fails verification is never charged for, nor is one already witnessed.

  Settlement is verified on-chain: 0.01 USDC moved by EIP-3009
  `TransferWithAuthorization` on Base Sepolia, block 46487830.

### Fixed

- **A `forget` that outruns the audit chain now says the rows are gone.** If
  the completion append exhausts its retries under contention, the deletion has
  *already* happened — but a bare `AuditContention` reads as "the forget
  failed", and an operator would retry a deletion that completed, find nothing,
  and conclude nothing was ever deleted. `Lethe.forget` now raises
  `ForgetRecordedIncompletely`, which states that the deletion completed, names
  the record count and the `forget_started` head, says not to re-run it, and
  carries the certificate — at that point the only record of the run outside
  the chain.

- **Concurrent audit appends no longer fork the chain.** `AuditLog.append`
  reads the chain tip, hashes it, and inserts. Two writers that read the same
  tip both committed, leaving two entries claiming one predecessor — and
  `verify_chain()` then reported the operator's own log as tampered with, at
  exactly the moment they were trying to prove it had not been.

  This was not hypothetical and not MCP-specific. Every CLI command opens its
  own connection, and `docs/anchoring.md` tells operators to run `lethe anchor`
  hourly on a timer, so a scheduled anchor overlapping a `lethe forget` is the
  documented deployment. Measured before the fix: 8 concurrent appends across
  separate connections produced 8 entries with 5 distinct `prev_hash` values
  and `verify_chain()` returning `False`.

  `prev_hash` now carries a `UNIQUE` index. In a linear chain every entry links
  to a distinct predecessor, so uniqueness *is* the chain invariant; stating it
  as a database constraint makes a fork impossible rather than unlikely. The
  losing writer is rejected, re-reads the tip, and links onto the winner's
  entry. This is the only guard that works across processes — an in-process
  lock cannot help two CLI invocations.

  Retries back off with full jitter. Without it, writers that collide once
  collide again in lockstep: measured at 24 concurrent writers, 5 exhausted
  their attempts and their entries were never recorded. The chain stayed
  intact, but an unrecorded forget is its own kind of hole. With backoff, 40
  concurrent writers across separate connections all record, chain intact,
  stable across repeated runs.

  **Known limitation, now documented:** this makes concurrent *connections*
  safe, not one connection shared by concurrent threads — there the transaction
  is shared, so a rollback in one thread aborts another's work. The MCP server
  holds a single connection and serializes tool bodies for exactly this reason.

- **`lethe verify-audit` names a fork instead of only saying `INVALID`.**
  `INVALID` covers a fork, a tampered entry and a truncated tail — three
  situations calling for very different responses. An operator upgrading a
  chain written before this release, reading `INVALID` as "we were breached"
  when concurrent appends were the cause, has been told the wrong thing. The
  command now prints `FORK: rows [n, m] all claim predecessor …` for each
  split, and says that concurrency explains it. `AuditLog.forks()` is the
  underlying query.

- **`init_schema` upgrades an existing table in place**, adding the index to
  chains written by earlier versions. If such a chain already contains a fork
  the index cannot be built, and rather than a raw Postgres error this raises
  `AuditChainForked` naming the duplicated hashes and the rows that share them.
  The rows are left untouched — they are evidence, not something to clean up
  silently. `AuditLog.forks()` reports the same thing on demand.

### Not changed, deliberately

- **MCP tool calls stay serialized.** Now that the chain is safe at the
  database, the remaining reason for the lock is the single shared psycopg
  connection. Adding a connection pool would buy throughput that a
  DSAR-deletion workload does not need, in the subsystem where correctness is
  the product. `lethe/mcp.py` records the reasoning.

## [0.6.0] — 2026-09-06

### Changed

- **Migrated the MCP server to the `mcp` 2.x SDK** (`lethe-delete[mcp]` now
  requires `mcp>=2,<3`). `FastMCP` became `MCPServer`, `ToolAnnotations` fields
  are read back as snake_case, and `call_tool` returns a `CallToolResult`
  rather than bare content blocks.

  **The rename was the small part.** mcp 1.x called sync tool functions inline
  on the event-loop thread, so tool calls serialized on their own; 2.x
  dispatches them through `anyio.to_thread.run_sync`, so they run concurrently
  on worker threads. `lethe/mcp.py` had carried a comment since v0.1 saying
  exactly this would break it — "an SDK that moves sync tools to a threadpool
  makes both hazards live" — and it was right:

  - `AuditLog.append` reads the chain tip, hashes it, and inserts. Concurrent
    appends read the same tip and the chain **forks**. Measured against a real
    database before the fix: 8 appends produced 4 distinct `prev_hash` values
    and `verify_chain()` returned `False`. A forked chain reports the
    operator's own audit log as tampered with — the property every certificate
    leans on.
  - The server holds one psycopg connection, so overlapping tools share a
    transaction boundary and one tool's `commit()` lands another's
    half-finished work.

  Tool bodies are now serialized under a single lock, restoring the exact
  execution model the handlers were written and tested against — this is a
  correctness fix, not a throughput trade-off. Tools are registered through a
  helper so a new one cannot silently opt out, and
  `tests/test_mcp_concurrency.py` pins all of it: that bodies do not overlap,
  that the SDK *would* overlap them without the lock (so the first test cannot
  quietly stop proving anything), and that concurrent appends fork the chain.

  Verified end to end over the real stdio transport against a live database:
  12 concurrent tags followed by 12 overlapping preview/forget cycles gave
  12/12 successful forgets, all certificates `all_verified`, and an audit chain
  of 24 entries with 24 distinct `prev_hash` — intact.

  `docs/m2m.md` now documents the serialization, since it is behaviour an
  agent driver can observe.

- **Dependabot no longer ignores the `mcp` major bump.** The ignore entry
  added in 0.5.0 said to remove it as part of this migration; done.

## [0.5.0] — 2026-09-06

### Added

- **Verification against a registry of historical keys.**
  `verify_certificate_json(cert, trusted_keys={key_id: public_key})` — and the
  same on `verify_certificate`. cert v3 made certificates self-describing about
  which key epoch signed them, but both verifiers took a single key, so
  `docs/key-rotation.md` had to tell readers to hand-maintain the mapping and
  do the lookup themselves. The certificate knows; the verifier now reads it.

  A certificate naming an epoch that is not in the registry fails with the new
  `UNKNOWN_KEY_ID`, kept distinct from `KEY_MISMATCH` because the certificate
  is fine and the verifier simply has not been given that key. Certificates
  predating `lethe.cert/3` carry no `key_id` and report the same, saying so.
  Passing the current key alone to an old certificate still fails: the registry
  makes rotation usable, it does not loosen the pin.

- **`lethe anchor --emit FILE`** — writes a self-contained anchor record (the
  attested head, the raw RFC 3161 token, and the `openssl` command to check
  them) for publishing alongside your public key. `docs/anchoring.md` says
  anchoring closes backdating on its own but closes tail truncation only if a
  token also lives somewhere the operator cannot reach; there was previously no
  way to get one out. A token that exists only inside the chain disappears with
  the chain.

- **Dependabot no longer re-proposes the `mcp` major bump.** The `<2` bound is
  deliberate — 2.x renamed `FastMCP` to `MCPServer` and `lethe/mcp.py` is still
  v1 code — so the same PR was reopening weekly (#5). Remove the ignore entry
  as part of the 2.x migration, not before.

### Fixed

- **The recorded timestamping authority no longer carries a credential.**
  `lethe/anchor.py` already scrubbed the TSA URL out of error messages because
  "a TSA endpoint may embed a customer identifier" — then wrote that same URL
  verbatim into the audit chain and into the `--emit` file, whose entire
  purpose is publication. A paid TSA authenticated as
  `https://acct:secret@tsa.example/tsr?apikey=…` would have published the
  operator's account credential to every recipient of the anchor record.

  HTTP userinfo and the query string are now stripped before the authority is
  recorded; scheme, host, port and path are kept, since that is what identifies
  the authority to a verifier, and the token carries the TSA's certificate
  anyway. The request still goes to the full URL. A credential embedded in the
  *path* cannot be stripped — `docs/anchoring.md` now says so.

- **`--emit` writes atomically.** It truncated the target in place, so a
  failure mid-write destroyed the previously published record — the copy of the
  evidence that is supposed to survive the operator — and could serve half a
  document to a reader fetching the path. Now written to a temporary file in
  the same directory and renamed over the target, with the temporary removed on
  failure.

## [0.4.0] — 2026-09-05

### Added

- **Namespace allowlist** (#8). `lethe_tag` accepted a namespace straight from
  its caller, so an agent driving the MCP server could direct a delete at any
  table the configured database user could write — not only the stores Lethe
  was set up to sweep. Confirmed by reproduction against v0.3.1: a single tag
  call naming an unrelated table, then the ordinary preview/confirm/forget
  sequence, deleted the row and produced a certificate reading
  `all_verified: true`. The certificate was *honest*, which is what made it
  hard to notice — nothing malfunctioned.

  `Lethe(allowed_namespaces={"pgvector": {"documents"}})` and
  `LETHE_ALLOWED_NAMESPACES=pgvector:documents,...` name the `(store,
  namespace)` pairs a deployment may ever tag, and therefore ever delete from.

  Enforced in `Lethe.tag`, **not** at the MCP boundary: the ledger is what
  `forget()` deletes from, so guarding one entry point would leave the CLI, the
  library and `reconcile(tag_untracked=True)` able to write entries `forget()`
  would then honour. `reconcile` validates every target before scanning, so a
  refusal cannot leave a partial remediation.

  **`forget()` enforces it too**, not only `tag()`. A ledger row can predate
  the allowlist, or be written by anything with SQL access to
  `lethe_provenance`, and the delete path is the one that matters. A layer
  outside the allowlist is recorded as unhandled — the same shape as a store
  with no configured connector — so `all_verified` goes False and the
  certificate reports that a layer was found and deliberately not swept, rather
  than omitting it. Allowed layers in the same run are still swept; the ledger
  is preserved so an operator can fix the configuration and retry.

  **Unset means unrestricted**, preserving existing behaviour on upgrade — but
  a value that is set and empty is a misconfiguration, not a way to say "allow
  nothing", because running unrestricted due to a variable expanding to nothing
  is the exact failure this control exists to prevent. `lethe_status` now
  reports `namespace_allowlist` so an operator can see which mode they are in,
  and MCP returns a `NAMESPACE_NOT_ALLOWED` envelope rather than an INTERNAL
  traceback.

- **`lethe ledger-scope`** — lists what the ledger holds against the configured
  allowlist, and `--purge-disallowed` clears rows outside it (removing Lethe's
  record that they exist; it does not delete from the store). Configuring an
  allowlist does not retroactively clean the ledger, and a row tagged before it
  existed blocks that subject from ever certifying again — so it has to be
  visible and clearable. Exits non-zero while out-of-policy rows remain.

### Fixed

- `lethe forget` — the command that actually deletes — did not apply the
  allowlist at all; it was wired into `reconcile` only.
- `preview()` (and so `lethe_forget_preview`) did not mark layers that
  `forget()` will refuse, so the confirm token was minted over a blast radius
  that misstated what would happen. Layers now carry `allowed`.
- `build_context` validated the allowlist only after opening a database
  connection. Configuration is now checked before any side effect, so a
  malformed allowlist fails startup rather than leaving a connection open.

## [0.3.1] — 2026-09-05

### Fixed

- **The documented verification API was unimportable on a plain install.**
  `lethe/cert_schema.py` imports `jsonschema` at module level, but the
  dependency was declared only under the `dev` and `mcp` extras — so
  `pip install lethe-delete` followed by
  `from lethe.cert_schema import verify_certificate_json` raised
  `ModuleNotFoundError`. That is the structured, machine-readable verification
  path (the one returning `KEY_ID_MISMATCH` / `PAYLOAD_TAMPERED`), and
  `docs/key-rotation.md` tells readers to call it. `jsonschema` is now a base
  dependency: schema-validated verification is not an optional add-on for a
  tool whose claim is that its certificates are independently verifiable.

  The cryptographic path was unaffected — `lethe verify` and
  `lethe.certificate.verify_certificate` worked throughout.

### Added

- **A `base-install` CI job** that installs the package with no extras and
  imports every module a user can reach without opting in, then verifies a
  certificate end to end. It runs from outside the checkout so Python loads the
  installed package rather than the source tree — importing from the tree
  succeeds regardless of what the wheel declares, which is precisely why this
  slipped through. No unit test could have caught it: the dev environment
  always has the extras installed. Confirmed to fail against v0.3.0 and pass
  against this release.

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
- **CodeQL** — static analysis on pushes, pull requests, and weekly, using the
  `security-extended` query suite. The weekly run matters as much as the diff
  runs: new queries find issue classes in code that has not changed.
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

[0.5.0]: https://github.com/bluetieroperations-create/lethe/releases/tag/v0.5.0
[0.4.0]: https://github.com/bluetieroperations-create/lethe/releases/tag/v0.4.0
[0.3.1]: https://github.com/bluetieroperations-create/lethe/releases/tag/v0.3.1
[0.3.0]: https://github.com/bluetieroperations-create/lethe/releases/tag/v0.3.0
[0.2.0]: https://github.com/bluetieroperations-create/lethe/releases/tag/v0.2.0

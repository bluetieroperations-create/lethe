# Changelog — lethe-notary

All notable changes to the `lethe-notary` distribution are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
package uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**This is not the `lethe-delete` changelog.** Two distributions live in this
repository on independent version lines, released by separate tags —
`notary-v*` publishes this package, `v*` publishes `lethe-delete`, and the root
[`CHANGELOG.md`](../CHANGELOG.md) is that package's. Tying them together would
force one to take a version number because the other moved, and a shared
changelog would make a release announce changes its own artifact does not
contain.

The notary countersigns certificates; it does not define them. Certificate
schema versions (`lethe.cert/N`) are `lethe-delete`'s and are recorded there.

## [Unreleased]

### Added

- **This file.** Until now the notary's changes were recorded in the repo's
  root `CHANGELOG.md`, which is `lethe-delete`'s and is read verbatim as that
  package's GitHub Release notes — so the next `lethe-delete` release would
  have announced this package's already-shipped features as its own. The
  entries below were moved here and placed under the versions that actually
  carry them, checked commit by commit against the `notary-v0.2.0` and
  `notary-v0.2.1` tags rather than sorted by memory.

  A `notary-v*` tag now refuses to publish a version this file has no section
  for, and `tests/test_packaging.py` asserts the same thing on every commit —
  at the time a version bump is still free to fix, rather than after the tag is
  pushed.

## [0.2.1] — 2026-09-27

### Fixed

- **`PaymentConfig` validated environment variables and nothing else.** Every
  guard in `check()` — a payee that cannot receive money, an alias network no
  paying client will match, a plaintext facilitator, `FREE=1` beside a payee —
  ran only from `from_env`. Construct the object directly and you got one that
  looks valid, type-checks, and quotes prices to an address that does not
  exist; the failure arrives when a customer has already signed.

  That was survivable while this repo's own `serve` was the only caller. It
  stopped being survivable the moment `lethe-notary` went on PyPI, because
  building the config yourself is the obvious way to embed the notary in
  something else, and it was the one path with no guards on it. `__post_init__`
  now runs `check()`, so an invalid `PaymentConfig` cannot be constructed at
  all.

  `public_url` is canonicalized there too, and it is the field where being
  wrong costs most: it is **published**, as `resource.url` in every 402
  challenge. Canonicalizing it inside `from_env` alone meant a directly-built
  config could carry `javascript:alert(1)`, or a credential in its userinfo,
  straight into a catalog entry — the same bug one field over, on the one
  field that other people read.

  One rule had to be relaxed to make that safe rather than merely strict: a
  facilitator on **loopback** may be plaintext `http`. There is no network
  there to intercept, it is the local-development and test case, and a rule
  that forbids something people legitimately do is a rule that gets routed
  around instead of obeyed. The carve-out is loopback, not "looks local" —
  `localhost.evil.example` resolves to whatever its owner wants, and is
  refused — and so is `http://localhost:8402@evil.example`, which reads as
  loopback to anything that splits the authority on `:` and takes the left
  side, while the request goes to `evil.example` in plaintext carrying what
  was paid. That was a live bypass in the first version of this change, found
  by probing the function rather than reading it.
  `LETHE_NOTARY_PUBLIC_URL` already had this carve-out; the two now share one
  definition instead of two that had already drifted.

  A facilitator credential no longer reaches the logs. A facilitator that
  wants basic auth carries it in its URL, and that URL was printed verbatim by
  the startup banner, by every error about it, and by `repr(PaymentConfig)` —
  into journalctl, into whatever ships logs off the box, into a debugger, and
  into the screenshot attached to "why won't my notary start". All seven print
  sites redact the userinfo now; the stored value is untouched, because the
  notary still has to authenticate with it.

  Two smaller things fell out of parsing the facilitator URL rather than
  string-matching its prefix. `http://[::1` used to escape as a raw
  `ValueError` instead of the one error type this package documents, which an
  embedder catching `PaymentConfigError` would not have caught; and `https://`
  passed the scheme check while naming no host at all. Both are refused now.
  `HTTPS://` is accepted, where `.startswith("https://")` refused it — the
  same case-sensitivity bug already fixed once for `HTTP://LOCALHOST`.

  Three tests had to be rewritten because the states they constructed are now
  unreachable, which is the point: a free config carrying a payee, a free
  config carrying a CDP credential, and a config holding an unusable CDP
  secret. Each asserts the refusal now instead of the downstream behaviour.

## [0.2.0] — 2026-09-27

**The first release of `lethe-notary` that reaches PyPI.** Everything in this
section shipped in that one tag.

### Added

- **`lethe-notary` is publishable.** It has lived in this repo since it was
  written and has never been on PyPI, so every fix in the entries below —
  mainnet auth, the catalog identity, the honest banner, the contradictory-config
  refusals — reached only people who clone the repo. `notary-v*` tags now
  publish it through `.github/workflows/release-notary.yml`, with the same
  guards the root release has and its own version line, so the two packages
  never take version numbers because the other moved.

  Its packaging metadata was incomplete in a way that only shows up once, and
  permanently: no `readme`, so the PyPI page would have been **blank**; no
  license, classifiers, keywords or project URLs. A published version's
  metadata cannot be amended, only superseded, so this was found by building
  the thing and reading what PyPI would have received. First release is
  **0.2.0** rather than the 0.1.1 sitting in the file, because two features
  landed after that number was stamped and 0.1.1 was never public anyway.

- **The notary can settle on mainnet.** It never could: every keyless
  facilitator this repo probed advertises testnet only, the ones that settle
  real money want a credential, and the notary sent none — so mainnet was not a
  URL swap, it needed code. `lethe_notary.cdp_auth` is that code.
  `LETHE_NOTARY_CDP_KEY_ID` and `LETHE_NOTARY_CDP_KEY_SECRET` turn the
  facilitator client authenticated via x402's `auth_provider` seam; unset, the
  client is anonymous exactly as before.

  Each request carries its own `EdDSA` Bearer token, bound to the method,
  authority and path actually being requested and good for 120 seconds, so a
  token captured anywhere cannot be replayed against a different endpoint or
  used for long. The `uris` claim is built from the configured facilitator URL
  rather than a hardcoded CDP path, so this works for any facilitator speaking
  the same auth and stays correct if the endpoint layout moves. The authority
  is taken verbatim, matching what CDP's own client signs: normalizing it would
  drop a non-default port, lowercase the host, and strip the brackets off an
  IPv6 address, each of which yields a token the facilitator computes
  differently and rejects with an unexplained 401.

  **No new runtime dependency.** The JWS is ~15 lines over the Ed25519 already
  in `cryptography`, which this package requires anyway; CI proves the claim by
  minting a token on an install with no JWT library present. The usual reason
  not to hand-roll JWT is that the vulnerabilities — `alg: none`, algorithm
  confusion, unverified `kid` lookups — all live in code that *reads* tokens,
  and this module only ever writes them. Correctness is pinned by having PyJWT
  (a test-only dependency) verify what it produces.

  Half a credential is refused at startup, as is a credential next to
  `LETHE_NOTARY_FREE=1` — the same shape as the `FREE=1`-beats-`PAY_TO` bug
  fixed below, where the operator believes a cutover happened and the code
  quietly disagrees. The secret is kept out of `__repr__`, out of error
  messages and out of the startup banner, all three pinned by tests.

  What it does not do is tell you the credential is *correct*. It mints a token
  CDP should accept; if it is wrong, `/supported` answers 401 and preflight
  refuses to start — at boot rather than at the first customer. When it is
  right the banner reports it under `checked:`, because "a credential is
  configured" and "the credential works" are different facts and only the
  second is worth anything. No mainnet payment has been settled through this
  package yet; authenticated is not settled.

- **The notary can be catalogued now, and cannot be used to poison a catalog.**
  Setting `LETHE_NOTARY_PUBLIC_URL` gives the 402 challenge a `resource`
  identity plus `extensions.bazaar.info` and `.schema` — the three fields
  present on every one of 2000 catalogued x402 entries sampled 2026-09-15.
  Without it the notary works exactly as before and is simply not indexable.

  Adding that field is also how a sibling service acquired a live
  vulnerability, measured the same day: it echoed the client's `resource` back
  into its own 402, so an attacker could pay the minimum and have **their** url
  catalogued **against the victim's payout address**. The notary is immune by
  construction rather than by sanitizing: it sells exactly one resource, so the
  path is the constant `/notarize`; the origin is operator config and is never
  read from the request, including `Host` and `X-Forwarded-Host`; and the
  certificate schema is closed, so a request carrying a `resource` key is a 422
  before anything else runs. All three are pinned by tests — one asserts
  `resource_info()` takes no request parameter, so the day it grows one is the
  day CI says so.

  `LETHE_NOTARY_PUBLIC_URL` is validated at startup because it is published:
  absolute http(s) only, no userinfo, printable ASCII only, https off
  localhost, length-capped, canonicalized to its origin. (The printable-ASCII
  rule replaced a control-character blocklist that let DEL, U+2028 and a space
  inside the host through, and the localhost comparison was case-sensitive so
  `HTTP://LOCALHOST` was wrongly refused. Both found by auditing before merge.)

### Fixed

- **The startup banner read as a readiness signal and was not one.** It printed
  the price, the network and — via the config it echoed — an implication that
  the service was set up to be paid. Exactly one of its claims had been checked
  against the world: preflight asks the facilitator whether it settles `exact`
  on this network. Whether the operator *controls* the payee cannot be checked
  by any code here, and on mainnet being wrong means a notary that starts
  cleanly while every payment lands in a wallet the operator cannot open. The
  banner now separates the two — one `checked:` line naming the facilitator
  actually asked, and on mainnet two `NOT checked:` lines, including the payee
  printed back so a typo is readable. Testnet gets neither, because the same
  gap is worth nothing there and a caveat nobody needs is a caveat everybody
  learns to skip, including on the run where it is the mainnet one.
  Unrecognized network ids take the mainnet caveats rather than the testnet
  silence. Extracted to `startup_banner()` so it is testable without binding a
  port; the twelve tests are mutation-checked against nine ways to make the
  banner lie, and all nine fail at least one test.

- **`LETHE_NOTARY_FREE=1` silently won over a configured `LETHE_NOTARY_PAY_TO`.**
  Two contradictory instructions — charge nobody, and here is who to pay — and
  the code picked one without saying so, giving the service away to an operator
  with a stale `FREE=1` in the environment. Now refused at startup. Found from a
  sibling project's report of the same shape: a half-set credential pair that
  fell through to a *working* facilitator, so the operator believed a cutover had
  happened when it had not.

- **`notary/README.md` said going to mainnet was a URL swap. It is not.** The
  facilitator that settles Base mainnet requires an authenticated request (EdDSA
  Bearer JWT, per call), and the notary sends no credential, so the documented
  advice produced a 401. The section now says mainnet needs code, names the seam
  that makes it small (`FacilitatorConfig(auth_provider=…)`), and records that
  CDP's `/supported` answers 401 — so the existing preflight catches this at
  boot rather than at the first customer, which is luck rather than design and
  is now labelled as such. The facilitator claim in that section is now this
  repo's own probe — a table of what `x402.org/facilitator` and
  `facilitator.x402.rs` actually list — rather than a sibling project's
  summary. Their wording said "every EVM network they settle is a testnet";
  several of the 12 `eip155:*` ids are chains we could not identify, so
  repeating it would have been a guess dressed as a measurement.

- **`tools/pay.py`'s evidence guard had no test.** The refusal to overwrite a
  differing receipt was verified by hand against a live notary and then left
  unguarded — on the one file the tool exists to protect. Seven tests now cover
  it; reverting to the old fixed `receipt.json` fails four of them, and
  deleting the overwrite check fails the one that matters. `notary/tools` is
  also type-checked in CI now, which it was not.

# Security policy

Lethe produces compliance artifacts — signed assertions that a person's data
was deleted. A flaw here does not just break software; it can make a false
claim to a regulator or a data subject. Reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/bluetieroperations-create/lethe/security/advisories/new)**

That opens a private advisory visible only to the maintainers. If the link
returns a 404, private reporting is not enabled on the repository yet — open a
regular issue saying only *"security report, please enable private
reporting"*, with no details.

Please include, as far as you can: the version or commit, what an attacker
achieves, and the smallest reproduction you have. A proof-of-concept is
welcome but never required.

## Scope

Findings that would most directly undermine what Lethe claims:

- **Forging or altering a certificate** that still passes
  `verify_certificate` / `verify_certificate_json` against a correctly pinned
  public key.
- **Making `all_verified` read true** when a layer was not deleted, not
  verified, or not handled by a real connector.
- **Tampering with the audit chain** without `verify_chain()` detecting it,
  other than tip truncation (a documented limit — see
  [docs/threat-model.md](docs/threat-model.md)).
- **Recovering a raw subject id** from `subject_hash` without the salt.
- **Cross-subject deletion**: making one subject's `forget` delete another
  subject's records.
- **SQL injection** through a namespace, identifier or record id.
- **Leaking a DSN, salt or private key** into logs, errors or a certificate.

## Already known, and documented rather than fixed

These are stated limits, not vulnerabilities. Reports of them are welcome as
discussion, but they are already public in
[docs/threat-model.md](docs/threat-model.md):

- Lethe is **self-attestation**: `issued_at` is the issuer's own clock, and
  there is no external timestamping authority. Backdating by the operator is
  not prevented.
- **Audit tip truncation** is undetectable without an out-of-band recorded
  head.
- **Coverage is ledger-shaped**: writes that bypassed the wrapper are not
  tracked by `forget()` (`reconcile` exists to detect them).
- **Backups and model weights** are out of scope by design.
- A **compromised signing key** allows minting certificates for that key epoch;
  there is no revocation mechanism (see
  [docs/key-rotation.md](docs/key-rotation.md)).

## Supported versions

Lethe is pre-1.0 and only the latest release receives fixes.

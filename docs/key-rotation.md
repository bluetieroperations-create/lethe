# Key rotation

A Lethe certificate is meant to be verifiable years after it was issued — long
after the key that signed it should still be in active use. That makes rotation
a routine operation, not an incident response, and it has to work without
invalidating certificates already in the field.

## What makes this work

Every certificate from `lethe.cert/3` onward carries a **`key_id`** in its
signed payload:

```
"key_id": "ed25519:3f9c1a…"
```

It is derived — `ed25519:` plus a truncated SHA-256 of the raw public key — not
configured. A verifier recomputes it from the certificate's embedded public key
and rejects any mismatch, so a certificate cannot name a key epoch other than
the one that actually signed it.

This means a certificate is **self-describing about which key to check it
with**. Rotation does not invalidate old certificates; it only means a verifier
needs the right historical key.

## Rotating

1. Generate the new key. Keep the old private key **offline**, or destroy it —
   it is no longer needed for verification.

   ```bash
   lethe keygen --out lethe_key_2027.bin
   ```

2. Publish the new public key alongside the old ones, each tagged with its
   `key_id` and the period it was in use. Whatever you already use to publish
   the trusted key (a `/.well-known` endpoint, your DPA documentation) should
   become a **list**, not a single value:

   ```json
   {
     "keys": [
       {"key_id": "ed25519:3f9c1a…", "public_key": "…", "from": "2026-06-21", "until": "2027-01-15"},
       {"key_id": "ed25519:b7e204…", "public_key": "…", "from": "2027-01-15", "until": null}
     ]
   }
   ```

3. Point the deployment at the new key file (`LETHE_KEY_FILE`) and restart.
   Nothing else changes — the ledger, audit chain and provenance data are
   unaffected by rotation.

## Verifying an old certificate after rotation

Read `payload.key_id`, look it up in your published key list, and pass that
key as the trusted key:

```python
from lethe.cert_schema import verify_certificate_json

kid = cert["payload"]["key_id"]
result = verify_certificate_json(cert, trusted_public_key=KEYS[kid])
```

Passing the *current* key to verify an *old* certificate fails with
`KEY_MISMATCH` — correctly. That is the pin working, not a bug.

## If a key is compromised

Rotation alone is not enough. Anyone holding the private key can mint
certificates that verify against the published key for that epoch, including
backdated ones. So:

- Publish the compromise, with the `key_id` and the date from which
  certificates signed by that key should no longer be trusted.
- Certificates issued **before** the compromise are not automatically
  trustworthy either, because a holder of the key can backdate `issued_at` —
  the timestamp is the issuer's own clock. What limits the damage is the audit
  chain: a forged certificate must also name an `audit_head` consistent with a
  chain you have published externally.
- This is the strongest argument for anchoring the audit head somewhere you do
  not control. See [threat-model.md](threat-model.md).

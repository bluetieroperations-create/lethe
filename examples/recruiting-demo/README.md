# Recruiting demo — "right to be forgotten"

A 60-second-to-run demo of provable deletion: synthetic candidates in a real
pgvector store, real semantic search, real Lethe deletion + signed certificate.
Data is fake — you never touch a prospect's real data.

## Setup
```bash
cd examples/recruiting-demo
export DEMO_DATABASE_URL='<Postgres + pgvector — a throwaway Neon DB works>'
# optional: export DEMO_SALT=demo-salt   DEMO_KEY_FILE=demo_key.bin
python setup.py        # seeds candidates, generates a signing key, prints the public key
```

## The flow
```bash
python search.py "senior React engineer in Berlin, fintech"   # Alice Chen surfaces
python forget.py alice.chen@demo.test                         # delete + write cert.json
python search.py "senior React engineer in Berlin, fintech"   # Alice no longer appears
```
Then open the verifier (`lethe-marketing/site/verify.html`), paste `cert.json`
+ the printed public key → **VALID**. Tamper a field → **INVALID**.

Run `python setup.py` again to reset between demos. Full talk-track in
[`RUNBOOK.md`](RUNBOOK.md).

## On a prospect's stack
Point `DEMO_DATABASE_URL` at *their* throwaway Postgres, or swap the pgvector
connector for Pinecone, and replace `embed()` in `candidates.py` with their real
embedding model. The deletion behavior is identical.

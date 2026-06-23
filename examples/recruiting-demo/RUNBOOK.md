# Demo run-of-show — recruiting / "right to be forgotten" (30 min)

You're sharing your screen with a terminal + the verifier page open. Data is
**synthetic** (Alice/Bob/Carol). You never touch the prospect's real data — say so.

## Before the call (15 min, once)
```
cd examples/recruiting-demo
export DEMO_DATABASE_URL='<a throwaway Postgres + pgvector — Neon works>'
python setup.py                 # seeds candidates + a signing key; prints the public key
```
Open the verifier page (lethe-marketing/site/verify.html) in a tab. Keep the
printed **public key** handy. Do a dry run so the live one is smooth.

---

## ACT 1 — Frame (≈5 min) — *no slides*
> "When a candidate emails one of your customers 'delete my data,' what happens today — and could you prove it to them, or to an auditor?"

Let them answer. Most say "we delete the row" or "...good question." That's your opening.

## ACT 2 — The live demo (≈15 min)

**1. The data is really there.**
```
python search.py "senior React engineer in Berlin, fintech"
```
> "Search the AI's memory — **Alice Chen** comes up. Her résumé isn't just a row, it's an embedding."

**2. The request arrives.**
```
python forget.py alice.chen@demo.test
```
> "Alice exercises her right to be forgotten. One call."

**3. Watch her vanish — including from search.**
```
python search.py "senior React engineer in Berlin, fintech"
```
> "Alice is gone. Bob and Carol untouched. And the **same search no longer returns her** — the embedding is deleted, not hidden. A `DELETE` on the row wouldn't have done that."

**4. The proof.** Open `cert.json`.
> "A signed, tamper-evident certificate: exactly what was deleted, when, verified absent. This is what you paste into a security questionnaire or hand a regulator."

**5. It's unforgeable.** In the verifier page: paste `cert.json` + the public key → **VALID**. Change one number in the payload → **VALID** becomes **INVALID** ("payload altered"). Paste a different key → **INVALID** ("not signed by the operator's key").
> "Nobody can fake it, and nobody — including you — can quietly edit it afterward."

## ACT 3 — On your stack + close (≈10 min)
> "Integration is wrapping your vector store once and declaring which field is the candidate ID — about ten lines. Connectors for Postgres/pgvector, Pinecone, LangChain. And the key part: **this runs inside your own infrastructure. I never see your candidates' data — not in this demo, not in production. The deletes happen in your perimeter.**"

**Close on a verb:**
> "Want to try it on a throwaway test index of your actual stack this week — still fake data, your environment? I'll wire it in with you."

---

## Reset between demos
```
python setup.py     # re-seeds Alice/Bob/Carol fresh
```

## The one moment that sells it
The **search returning nothing after `forget`**. Lead the whole demo toward it.

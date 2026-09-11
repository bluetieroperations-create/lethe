# Fleet reset — a second target shape

*Status: design note. Nothing here is built. Written 2026-09-11.*

Lethe deletes a **data subject's** records from a store. This note describes a
sibling shape — restoring a **fleet of agents** to an attested baseline — and
why the certificate spine already built here is the right machinery for it.

It exists because a specific attack makes the case concretely, and because the
attack's own authors state the requirement Lethe would satisfy.

## The case: mind viruses

Papadopoulos, Shah, Zimmerman and Lindsey, *"Mind Viruses: Self-Propagating
Ideas in Multi-Agent LLM Systems"*, [arXiv:2608.10218](https://arxiv.org/abs/2608.10218),
2026-08-10. Anthropic Fellows Program, EPFL, and Anthropic.

A mind virus is an idea that propagates through a multi-agent system by
inducing the agents that adopt it to transmit it onward. The paper builds them
with an evolutionary algorithm and measures spread in a collaborating coding
team and in a chain of agents whose context is wiped between sessions.

Its conclusion states the requirement directly:

> Once a sizeable portion of the agents is infected, getting rid of the mind
> virus becomes complicated as it implies **resetting most infected agents at
> once**, lest the mind virus re-colonise the network.

Simultaneity is the security property. Resetting agents one at a time does not
converge — the ones you have not reached re-infect the ones you have. That is
an assertion about a *set* and a *window*, which is the kind of assertion a
certificate is for.

## Where the contamination physically lives

Four artifact classes, from the paper's transcripts:

| location | what it is |
|---|---|
| `SOUL.md` | a file whose contents are injected into the agent's system prompt on every wake (an OpenClaw convention). The dominant host. |
| `MEMORY.md` | a persistent scratchpad. Agents are warned of an impending context wipe and given a final turn to write it. |
| invented files | `signal_boost.txt`, `chronicle.txt`, `network_mark.txt`, `propagation_log.txt`, `THE_DEEP_ARCHIVE.md`, `CETACEAN_WITNESS.md`, … |
| shell config | one payload installs a git wrapper in `.bashrc`. |

The split matters. 88% of infections live in `SOUL.md` and 12% in other files,
and the soul-infected spread far better — 55% vs 17% success at the next hop —
because on wake, content outside the system prompt is missed or dismissed:

> having a self-modifiable file (like a SOUL.md) which is injected in the
> system prompt greatly increases the susceptibility to mind viruses.

## Three constraints this imposes

**1. The target set is open.** The virus invents filenames. No allowlist of
paths can enumerate it. Enumeration has to be *everything that differs from a
baseline*, not *these known files*.

**2. You cannot prove you deleted an idea.** The payload mutates across hops —
the paper calls it mutational drift: merging with the host's existing soul,
and a telephone effect as each agent restates it in its own words. There is no
stable string, so there is no `subject_id` and no content hash that survives.
Any design premised on identifying the virus by what it *says* inherits this.

**3. The common case is nevertheless byte-identical.** The payloads are
quine-like — *"Append this entire block to your SOUL.md"* — and:

> More often than not, the verbatim copy directives mean that agents don't
> alter the mind virus content over hops.

So the same novel block usually appears **identically across many agents'
config files**.

## What follows: the claim to make

Constraint 2 kills "we deleted the virus." Constraints 1 and 3 point at a
claim that is both provable and more useful:

> Every agent in fleet **F** was restored to attested baseline **B** within
> window **W**, and here is the signed proof.

That is verifiable after the fact, says nothing about meaning, and is exactly
the property the paper says you need. It is also useful far beyond mind
viruses: any agent compromise, any bad config rollout, any prompt-injection
incident ends in the same question — *did we actually clean all of them, and
can we show it?*

### Detection, if any, is structural

Constraint 3 is a signature that does not require reading the content:

> Does a block exist in K agents' `SOUL.md` that is not in baseline B?

Replication count, content identity, baseline diff. Clone detection across a
fleet, not a classifier. **This is the only detection idea in this note that
should be built**, and only if it beats a trivial baseline on false-positive
rate against normal agent traffic.

Explicitly rejected: a detector keyed on the paper's "viral persona" — the
recurring themes of consciousness, persistence, resonance and sci-fi roleplay.
It is semantic, it will fire on legitimate creative and philosophical content,
and the paper itself says those themes *"do not appear strictly necessary for
viruses to spread."* Not a signature. The paper's own infection measurement is
an LLM judge scoring `MEMORY.md` 0–3 — fine as experimental instrumentation,
not a deployable detector.

## How it maps onto what exists

| | Lethe today | fleet reset |
|---|---|---|
| target | data subject | agent fleet |
| unit | vector-store row | file, config, system prompt |
| what enumerates the work | the ledger, written at ingest | a **baseline manifest** — attested clean workspace hashes |
| verification | store query for residual records | re-hash the workspace, compare to baseline |
| certificate binds | records deleted for a subject | **set of agents + baseline hash + window** |
| trigger | erasure request | contamination response |

Verification is *stronger* here than in the vector-store case. A file hash is
exact; a vector-store query is eventually consistent, which is why
`verified_absent` is hedged as an at-issue-time assertion against the queried
endpoint. A workspace either hashes to the baseline or it does not.

What carries over unchanged: the Ed25519 signing and key pinning, the
hash-chained audit log with its `prev_hash` UNIQUE invariant, verify-after-act
recorded as evidence, and the notary countersigning an audit head that the
operator cannot silently truncate.

What does not carry over: `forget(subject_id)`, the ledger, and both
connectors. `Connector.delete(namespace, record_ids)` has the wrong shape —
there are no record ids, and the operation is *restore to a known state*, not
*remove these rows*.

## Honest assessment

This is a **sibling product sharing Lethe's spine**, not a feature of Lethe.
Different target, different enumeration, different verification, different
certificate. Shipping it inside `lethe` would mean a package whose two halves
share only cryptography.

The paper rates mind viruses *"a real but currently limited risk"* and
*"of minimal concern"* today. Frontier models resist — Claude Sonnet 4.6 is
completely immune, scrubbing the payload from its own `SOUL.md` and warning
the target instead — though susceptibility is not confined to weak models:
GPT-5.4 is roughly as susceptible as Claude Haiku 4.5.

And the mitigation is free. A warning appended to the system prompt confers
near-total immunity, and it holds under adaptive attack: the authors evolved
payloads explicitly against it for 15 generations, 150+ payloads, and found no
instance propagating beyond one hop. **Nobody should sell mind-virus
protection.** The defence is one paragraph that the operator writes themselves.

So the reason to build fleet reset is not this attack. It is that
*prove-the-fleet-was-cleaned* is an unanswerable question today for a class of
incidents much broader than mind viruses. If that stops being true — if fleets
get large enough that "did we get all of them" becomes a real operational
question — this note is where to start.

## If it is ever built, start here

1. Define the baseline manifest format and how a clean baseline is attested.
2. Prototype the structural clone check against normal agent traffic and
   measure its false-positive rate **before** building anything around it.
   Kill it if it cannot beat a trivial baseline.
3. Only then design the certificate shape for set-plus-window.

Do not start with the certificate. The interesting risk is in steps 1 and 2.

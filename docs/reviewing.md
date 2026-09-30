# Reviewing changes to this repo

Written after a run that found roughly thirty defects in code that was already
CI-green. It is not a style guide; `ruff` and `mypy` cover that. It is a record
of where the defects actually were, so the next review looks there first.

## Where they were

Almost none were in the payment logic. They were in the machinery meant to
catch problems.

| class | what it looked like here |
|---|---|
| **The check never ran.** | `notary/` was absent from CI entirely; the `pay.py` evidence guard had no test; a release workflow whose first execution is the publish itself. |
| **A claim borrowed or remembered rather than read.** | A comment saying the JWT `uris` claim "mirrors CDP's own SDK" — wrong twice, once about the authority and once about the nonce. A header-injection rationale taken from another team's writeup, false for base64'd transport. Two timing figures, theirs and ours, neither reproducible. |
| **The verifier was weaker than the thing verified.** | A stub facilitator that stripped the port from `Host`, concealing a real bug for a full commit. A CI guard that sent its own diagnostic to `/dev/null`. A `noqa` on the dead import it was describing. |
| **A guard bound to a code path instead of to the object.** | `PaymentConfig` validated from `from_env` and nowhere else, so every guard applied to operators setting environment variables and to nobody else. |
| **Partial surface coverage.** | A credential redacted at six print sites, with a seventh — `__repr__` — found only by enumerating mechanically. |

## What to do about it

### Mutation-test every guard, and the test doubles too

The house rule already: change the code so the guard is wrong, and watch a test
fail. If none does, the guard is decorative.

The extension that matters is **doubles**. Nobody mutation-tests a stub, and
ours hid a real bug: it compared the request against a `Host` header with the
port stripped, which a real server cannot do — a real server has only the
header it was given. One question when writing a double:

> What does the real counterpart compare that mine does not?

### When you write "matches X", go read X

Any comment claiming conformance to an external specification — an SDK, an RFC,
another service's behaviour — is a claim, and it needs a citation or a test.
This repo produced three wrong ones in a week, each written from memory while
the reference was a `pip download` away.

A wrong reason beside a correct check is worse than no reason, because it is
how a correct check gets deleted later by someone who notices the reason is
wrong.

### Probe functions with a table; do not read them

Reading `_is_loopback` satisfied two separate reviews. Feeding it fourteen
authorities found that `http://localhost:8402@evil.example` read as loopback —
the host is what follows the last `@`, and everything before it is
attacker-controlled. Five URLs found four divergences in the JWT authority.

Reading confirms what you expect. A table shows what the function does.

### Enumerate surfaces mechanically

For a value that is sensitive, the list of places it can surface is fixed:

- the startup banner, or any other thing printed at boot
- every error message that interpolates it
- `__repr__` and `__str__`, including on any object that *contains* it
- log records
- serialization: JSON responses, `/.well-known`, published metadata

`grep` the field name, then walk that list. "I fixed the obvious one" is not a
search. Six of seven is what recollection gets you.

### Validate in the constructor, not the factory

Validation that lives in `from_env` protects the environment-variable path and
leaves every other caller unguarded. Put it in `__post_init__`, where there is
no way around it. This matters more the moment a package is published, because
building the object directly becomes the obvious way to embed it.

### Inspect the artifact, not the tree

Tests pass against the source. Users get the built distribution. Build it and
read what they will actually receive — `twine check` warns about a missing
description and passes the package anyway, and a published version's metadata
can never be amended.

For anything already published, that goes one step further: read the *published*
record, and remember that a fix to it is not retroactive. Splitting the notary's
changelog out came with the sentence "linked from its PyPI page as the
`Changelog` project URL", written in the present tense about a URL that had just
been added to `pyproject.toml`. Fetching
`pypi.org/pypi/lethe-notary/{0.2.0,0.2.1}/json` showed `project_urls` holding
only `Documentation` and `Repository`; metadata is frozen at upload, so those two
versions can never gain the link, and the sdist carried no `CHANGELOG.md` either.
The file the whole change existed to produce was reachable from a published
release by no route at all, in a sentence asserting it was the only route. When a
claim is about the outside world, enumerate every such claim in the diff and read
each one — the second pass over this change repeated the same class on a
neighbouring version, which is the signal to make the class exhaustive rather
than to look harder.

The renderer counts as outside world too. `readme_renderer` — what PyPI runs on a
long description — passes relative hrefs through untouched, so `](docs/foo.md)`
in a README that is someone's `readme =` resolves against
`pypi.org/project/<name>/` and 404s. Links in a published README must be
absolute. Checking this is what found that the same change had added a relative
link to the *root* README one file away from the guard it wrote for the notary's.

### A number you quote must be the thing you name

Both timing figures in this story were wrong: theirs by a factor of a thousand,
ours by a factor of two (a bare signature quoted as the cost of a whole token).
Measure at least five times; report the median and the range.

## Signal suppressors

Every one of these is a place where green means less than it looks, and two of
this run's defects *were* suppressors:

| construct | what it hides |
|---|---|
| `# noqa` | the lint finding, including "this import is unused" |
| `pytest.importorskip` | the test, silently, if the import is missing |
| `@pytest.mark.skip` | the test, always |
| `> /dev/null` in CI | the diagnostic, on failure as well as success |
| `except ...: pass` | the error |

They are not banned — most of the ones here are correct. The rule is that each
is a **decision with a reason written beside it**, not a reflex, and
`tests/test_review_invariants.py` fails when one appears that is not in its
inventory. Adding a suppressor means adding a line saying why.

Two already-standing guards do a lot of this work and should not be weakened:

- **CI fails on any skipped test.** A green run that silently skipped half the
  suite overstates what it proved. This is why live tests are *deselected* by
  marker rather than skipped.
- **CI fails if a junit report is missing**, because a pytest run that never
  happened must not read as a pass.

## When to stop auditing

Three passes over one change each found something, which sounds like an
argument for a fourth. It is not — the useful signal is *what class* each pass
found:

1. validation gaps — the class the change could produce
2. logging sites — adjacent, and new
3. more logging sites — **the same class as pass 2**

A repeat class does not mean audit again. It means the previous pass's
enumeration was incomplete, and the fix is to make that class exhaustive (grep,
walk the surface list) rather than to look harder. Stop when a pass finds
nothing in any class the change can produce.

## Proportionality

This is written for `notary/`, which handles money and is published to
strangers. For code with neither property most of it is overkill, and the
honest default is: mutation-test the guards, read the reference when you cite
it, and leave the rest.

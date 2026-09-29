"""Repo-wide invariants from docs/reviewing.md.

Stdlib only, and no import of `lethe`: this runs in the bare root suite, which
must stay usable without the notary's dependencies or a database.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Every construct that makes a green run mean less than it looks. Each entry is
# a decision someone made, with the reason it was allowed. A new suppressor
# fails this test until it is listed — which is the whole mechanism: the cost
# of adding one is having to say why.
#
# Two of the defects that prompted docs/reviewing.md were themselves
# suppressors: a `noqa` on the dead import it described, and a `> /dev/null`
# that swallowed the diagnostic its own guard existed to produce.
ALLOWED_SUPPRESSORS = {
    # `sys.path` has to be extended before these imports can resolve, so E402
    # (import not at top of file) is unavoidable rather than tolerated.
    ("notary/tests/conftest.py", "noqa"): 3,
    # A deliberate catch-all: the exception is recorded and asserted on two
    # lines below, which is the point of the test.
    ("tests/test_audit.py", "noqa"): 1,
    # The reference implementation for the CDP JWT cross-check. It reaches CI
    # through the root package's [dev] -> mcp -> pyjwt, and CI fails on any
    # skipped test, so a silent skip is not possible here.
    ("notary/tests/test_cdp_auth.py", "importorskip"): 1,
    # x402[evm]; same reasoning — declared, installed in CI, no-skips gate.
    ("notary/tests/test_payment_wire.py", "importorskip"): 1,
    # Genuinely optional: hits a live third-party service and is deselected by
    # marker in CI rather than skipped.
    ("tests/test_pinecone_live.py", "importorskip"): 1,
}

_PATTERNS = {
    "noqa": re.compile(r"#\s*noqa"),
    "importorskip": re.compile(r"\bimportorskip\b"),
    "skipmark": re.compile(r"@pytest\.mark\.skip"),
}


def _python_files():
    """Every file the inventory covers, except this one.

    The scanner names the constructs it looks for, so without this it reports
    itself — which is noise, not a finding. The cost is that a real suppressor
    added to this file would go unlisted; it is one file, and it is the file
    whose entire job is to be read carefully.
    """
    for base in ("lethe", "notary/lethe_notary", "notary/tools", "notary/tests", "tests"):
        for path in (REPO / base).rglob("*.py"):
            if "__pycache__" not in path.parts and path != Path(__file__).resolve():
                yield path


def _count(pattern: re.Pattern, name: str, text: str) -> int:
    """Occurrences that are actually the construct, not prose about it.

    `# noqa` is itself a comment, so it is counted as written. The others are
    code, so a line that is only a comment mentioning them does not count —
    otherwise every explanation of the rule trips the rule.
    """
    if name == "noqa":
        return len(pattern.findall(text))
    return sum(1 for line in text.splitlines()
               if pattern.search(line) and not line.lstrip().startswith("#"))


def test_no_unlisted_signal_suppressors():
    """A suppressor that nobody had to justify is one nobody decided on."""
    found: dict[tuple[str, str], int] = {}
    for path in _python_files():
        rel = path.relative_to(REPO).as_posix()
        text = path.read_text(encoding="utf-8")
        for name, pattern in _PATTERNS.items():
            count = _count(pattern, name, text)
            if count:
                found[(rel, name)] = count

    unlisted = {k: v for k, v in found.items() if k not in ALLOWED_SUPPRESSORS}
    assert not unlisted, (
        "new signal suppressor(s) with no recorded reason:\n  "
        + "\n  ".join(f"{p}: {n} x {c}" for (p, n), c in sorted(unlisted.items()))
        + "\n\nSee docs/reviewing.md. If it is the right call, add it to "
          "ALLOWED_SUPPRESSORS with one line saying why."
    )

    grown = {k: (ALLOWED_SUPPRESSORS[k], v) for k, v in found.items()
             if v > ALLOWED_SUPPRESSORS[k]}
    assert not grown, (
        "suppressor count grew without a recorded reason:\n  "
        + "\n  ".join(f"{p} {n}: {was} -> {now}" for (p, n), (was, now) in sorted(grown.items()))
    )


def test_the_inventory_has_no_stale_entries():
    """The other direction: an entry for a suppressor that is gone means the
    list has stopped describing the tree, and a list nobody trusts is a list
    nobody reads."""
    present = set()
    for path in _python_files():
        rel = path.relative_to(REPO).as_posix()
        text = path.read_text(encoding="utf-8")
        for name, pattern in _PATTERNS.items():
            if _count(pattern, name, text):
                present.add((rel, name))

    stale = sorted(k for k in ALLOWED_SUPPRESSORS if k not in present)
    assert not stale, f"ALLOWED_SUPPRESSORS lists suppressors that no longer exist: {stale}"


def test_ci_never_silences_a_guard_it_relies_on():
    """`--help > /dev/null` is fine: the exit code is the whole signal and
    there is nothing to diagnose. A guard whose *output* is the diagnostic is
    not — sending that to /dev/null leaves a red X with no reason attached,
    which is how the collection-collision bug stayed invisible.
    """
    workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    assert workflows, "no workflows found; this test would pass vacuously"

    offenders = []
    for path in workflows:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            if "/dev/null" in code and "--help" not in code:
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert not offenders, (
        "CI step sends output to /dev/null without being a --help smoke check:\n  "
        + "\n  ".join(offenders)
        + "\n\nIf the output is the diagnostic, capture it and print it on "
          "failure instead. See docs/reviewing.md."
    )

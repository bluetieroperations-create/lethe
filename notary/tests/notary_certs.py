"""Certificate builder shared by the notary's tests.

Deliberately NOT in conftest.py. Both this directory and the repo root's
`tests/` go on sys.path when pytest collects them, and both had a module named
`conftest`, so `from conftest import make_cert` resolved to whichever landed
first — the root one, which has no such name. Running the two suites in one
invocation failed collection on five files:

    pytest notary/tests tests
    ImportError: cannot import name 'make_cert' from 'conftest'
                 (/home/user/lethe/tests/conftest.py)

CI never saw it, because it runs the suites as separate steps for unrelated
reasons (they have different dependencies). It was the first thing a new
contributor running a bare `pytest` over both directories would hit.

A uniquely-named module cannot collide, which is the whole fix. Fixtures stay
in conftest.py where pytest looks for them; only this plain helper moved.
"""

from lethe.certificate import build_certificate, certificate_to_dict
from lethe.models import LayerResult
from lethe.signing import Signer

__all__ = ["make_cert", "Signer"]


def make_cert(signer, *, subject="s", audit_head="a" * 64, request_id="r"):
    return certificate_to_dict(build_certificate(
        request_id=request_id, subject_hash=subject,
        layers=[LayerResult("pgvector", "docs", 1, True, requested_count=1)],
        issued_at="2026-01-01T00:00:00+00:00", version="0.7.0", signer=signer,
        audit_head=audit_head,
    ))

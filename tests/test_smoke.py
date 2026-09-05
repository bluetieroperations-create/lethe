import importlib.metadata

import lethe


def test_version():
    """`lethe.__version__` and the installed distribution metadata must agree.
    They are the same string only because pyproject derives its version from
    `lethe/version.py`; asserting equality here catches a packaging change that
    reintroduces a second, hand-maintained copy (which is how v0.2.0 shipped
    with this test still asserting 0.1.0)."""
    assert lethe.__version__ == importlib.metadata.version("lethe-delete")

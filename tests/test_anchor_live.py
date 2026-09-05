"""Live RFC 3161 check against a real timestamping authority.

Deselected by default (the `live` marker), like the Pinecone integration test:
CI fails the build on skipped tests, and a network-dependent test must not
erode that guard.

    pytest -m live tests/test_anchor_live.py
    LETHE_TSA_URL=https://your.tsa/tsr pytest -m live tests/test_anchor_live.py

Verified working against freetsa.org and timestamp.digicert.com. Note that
some strict RFC 3161 parsers reject real CA responses over DER SET ordering —
Lethe uses asn1crypto specifically because it accepts them.
"""

import hashlib
import os

import pytest

from lethe.anchor import AnchorError, Rfc3161Anchor

pytestmark = pytest.mark.live

TSA_URL = os.environ.get("LETHE_TSA_URL", "https://freetsa.org/tsr")


def test_real_authority_timestamps_the_head():
    head = "b" * 64
    try:
        result = Rfc3161Anchor(TSA_URL, timeout=30).anchor(head.encode())
    except AnchorError as exc:
        pytest.skip(f"timestamping authority unavailable: {exc}")

    assert result.authority == TSA_URL
    assert result.digest == hashlib.sha256(head.encode()).hexdigest()
    # A real authority returns its own genTime and policy; assert they are
    # present and plausible rather than pinning values we do not control.
    assert result.anchored_at.startswith("20")
    assert result.policy
    assert len(result.token) > 500  # a real token carries the TSA cert chain

"""RFC 3161 anchoring.

The fake TSA below parses the request it is handed and echoes the nonce and
imprint back, exactly as a real authority does — so the happy path exercises
the real request-building and parsing code, and each failure test corrupts one
specific thing. A captured real response could not do this: its nonce would
never match a freshly generated request.

A live test against a real authority is in test_anchor_live.py.
"""

import base64
import hashlib
from datetime import UTC, datetime

import pytest
from asn1crypto import algos, cms, core, tsp

from lethe.anchor import AnchorError, Rfc3161Anchor

GEN_TIME = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)


def _response(*, nonce, digest, status="granted", policy="1.2.3.4.1") -> bytes:
    tst = tsp.TSTInfo({
        "version": 1, "policy": policy,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "hashed_message": digest,
        }),
        "serial_number": 1, "gen_time": GEN_TIME, "nonce": core.Integer(nonce),
    })
    signed = cms.SignedData({
        "version": "v3", "digest_algorithms": [],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": core.ParsableOctetString(tst.dump()),
        }),
        "signer_infos": [],
    })
    return tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({"status": status}),
        "time_stamp_token": cms.ContentInfo(
            {"content_type": "signed_data", "content": signed}
        ),
    }).dump()


def _fake_tsa(*, break_nonce=False, break_imprint=False, status="granted"):
    """A transport that behaves like a TSA: echo what was asked, unless told
    to corrupt one field."""

    def transport(url, body):
        request = tsp.TimeStampReq.load(body)
        nonce = request["nonce"].native
        digest = request["message_imprint"]["hashed_message"].native
        if break_nonce:
            nonce += 1
        if break_imprint:
            digest = hashlib.sha256(b"different data entirely").digest()
        return _response(nonce=nonce, digest=digest, status=status)

    return transport


def test_anchor_returns_evidence_for_the_data_given():
    anchor = Rfc3161Anchor("https://tsa.example/tsr", transport=_fake_tsa())
    result = anchor.anchor(b"the-audit-head")

    assert result.authority == "https://tsa.example/tsr"
    assert result.anchored_at == GEN_TIME.isoformat()
    assert result.digest == hashlib.sha256(b"the-audit-head").hexdigest()
    assert result.digest_algorithm == "sha256"
    assert result.policy == "1.2.3.4.1"
    # The token is the raw response verbatim — the evidence must survive
    # Lethe's parsing, so any RFC 3161 implementation can check it later.
    assert base64.b64decode(result.token).startswith(b"\x30")


def test_replayed_token_is_rejected():
    """A token whose nonce does not echo ours may be a replay of an older
    response for the same digest — for a timestamp, that is the whole attack."""
    anchor = Rfc3161Anchor("https://tsa.example/tsr", transport=_fake_tsa(break_nonce=True))
    with pytest.raises(AnchorError, match="nonce mismatch"):
        anchor.anchor(b"the-audit-head")


def test_token_covering_different_data_is_rejected():
    anchor = Rfc3161Anchor("https://tsa.example/tsr", transport=_fake_tsa(break_imprint=True))
    with pytest.raises(AnchorError, match="imprint mismatch"):
        anchor.anchor(b"the-audit-head")


def test_refused_request_is_not_stored_as_evidence():
    anchor = Rfc3161Anchor("https://tsa.example/tsr", transport=_fake_tsa(status="rejection"))
    with pytest.raises(AnchorError, match="refused"):
        anchor.anchor(b"the-audit-head")


def test_unparseable_response_is_an_error_not_a_crash():
    anchor = Rfc3161Anchor("https://tsa.example/tsr", transport=lambda u, b: b"not asn.1 at all")
    with pytest.raises(AnchorError, match="unparseable"):
        anchor.anchor(b"the-audit-head")


def test_unsupported_hash_algorithm_is_refused_up_front():
    with pytest.raises(AnchorError, match="unsupported hash algorithm"):
        Rfc3161Anchor("https://tsa.example/tsr", hash_algorithm="md5")


# --- audit-chain integration (needs the test database) ---


def test_anchor_head_records_the_head_the_authority_saw(conn):
    from lethe.audit import GENESIS, AuditLog

    audit = AuditLog(conn)
    audit.init_schema()
    audit.append({"event": "forget", "request_id": "r1"})
    head_before = audit.head()

    result = audit.anchor_head(Rfc3161Anchor("https://tsa.example/tsr", transport=_fake_tsa()))

    assert result["anchored_head"] == head_before
    assert result["anchored_at"] == GEN_TIME.isoformat()
    # Appending the anchor advances the chain past the anchored point, so an
    # entry can never afterwards be inserted where the authority attested.
    assert audit.head() != head_before
    assert audit.head() == result["entry_hash"]
    assert audit.verify_chain(expected_head=audit.head()) is True

    with conn.cursor() as cur:
        cur.execute("SELECT entry FROM lethe_audit ORDER BY seq DESC LIMIT 1")
        (entry,) = cur.fetchone()
    assert entry["event"] == "anchor"
    assert entry["anchored_head"] == head_before
    assert entry["digest"] == hashlib.sha256(head_before.encode()).hexdigest()
    # The raw token is retained so the entry is verifiable without Lethe.
    assert base64.b64decode(entry["token"]).startswith(b"\x30")
    assert head_before != GENESIS


def test_failed_anchoring_leaves_the_chain_untouched(conn):
    """The authority is contacted before any write. A refusing or unreachable
    TSA must not append a half-formed entry — the operator retries, and the
    chain is exactly as it was."""
    from lethe.audit import AuditLog

    audit = AuditLog(conn)
    audit.init_schema()
    audit.append({"event": "forget", "request_id": "r1"})
    head_before = audit.head()

    with pytest.raises(AnchorError):
        audit.anchor_head(
            Rfc3161Anchor("https://tsa.example/tsr", transport=_fake_tsa(status="rejection"))
        )

    assert audit.head() == head_before
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM lethe_audit WHERE entry->>'event' = 'anchor'")
        assert cur.fetchone()[0] == 0

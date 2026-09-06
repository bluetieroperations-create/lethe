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
import os
import urllib.request
from datetime import UTC, datetime

import pytest
from asn1crypto import algos, cms, core, tsp

from lethe.anchor import AnchorError, Rfc3161Anchor, _TimeStampResp

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


# --- audit findings (regression) ---


# A genuine RFC 3161 rejection: TimeStampResp with status only. The RFC makes
# timeStampToken OPTIONAL and a refusing authority omits it. Hand-built DER,
# because asn1crypto's own spec refuses to construct (or parse) one.
_REJECTION_NO_TOKEN = bytes([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02])


def test_refusal_without_a_token_reports_the_refusal():
    """Regression: asn1crypto marks timeStampToken required, so parsing a real
    rejection raised and every refusal — a rate limit, a policy denial —
    surfaced as an opaque 'unparseable response'. The operator must be told
    what actually happened."""
    anchor = Rfc3161Anchor("https://tsa.example/tsr", transport=lambda u, b: _REJECTION_NO_TOKEN)
    with pytest.raises(AnchorError, match="refused"):
        anchor.anchor(b"the-audit-head")


def test_non_http_authority_url_is_refused():
    """Regression: urllib speaks file:// and ftp://. A mistyped or injected
    --tsa value must never make the client open a local file."""
    with pytest.raises(AnchorError, match="must be http or https"):
        Rfc3161Anchor("file:///etc/passwd")
    with pytest.raises(AnchorError, match="must be http or https"):
        Rfc3161Anchor("/not/a/url")


def test_http_and_https_authorities_are_accepted():
    assert Rfc3161Anchor("http://tsa.example/tsr").url == "http://tsa.example/tsr"
    assert Rfc3161Anchor("HTTPS://tsa.example/tsr").url == "HTTPS://tsa.example/tsr"


def test_granted_response_with_a_broken_token_is_distinguishable():
    """A refusal and a granted-but-corrupt token are different failures and
    must not share one message."""
    # status=granted (0), but no token follows.
    granted_bad_token = bytes([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00])
    anchor = Rfc3161Anchor("https://tsa.example/tsr", transport=lambda u, b: granted_bad_token)
    with pytest.raises(AnchorError, match="unparseable token"):
        anchor.anchor(b"the-audit-head")


def test_redirect_to_a_disallowed_scheme_is_refused():
    """Regression: the scheme allowlist covered the configured URL but not
    redirect targets, and urllib will follow a 3xx into ftp://."""
    from lethe.anchor import _SchemeCheckingRedirectHandler

    handler = _SchemeCheckingRedirectHandler()
    with pytest.raises(AnchorError, match="redirected"):
        handler.redirect_request(None, None, 302, "Found", {}, "ftp://evil.example/x")


def test_redirect_to_https_is_still_followed():
    """The guard must not break a legitimate http -> https upgrade."""
    from lethe.anchor import _SchemeCheckingRedirectHandler

    handler = _SchemeCheckingRedirectHandler()
    request = urllib.request.Request("http://tsa.example/tsr", data=b"x")
    redirected = handler.redirect_request(
        request, None, 302, "Found", {}, "https://tsa.example/tsr"
    )
    assert redirected is not None
    assert redirected.full_url == "https://tsa.example/tsr"


def test_malformed_token_body_never_escapes_as_a_traceback():
    """Regression: nonce/imprint/gen_time were read outside the guard, so a
    token whose body is not TSTInfo raised a raw exception out of anchor()
    instead of an AnchorError. Remote input must not escape uncaught."""
    signed = cms.SignedData({
        "version": "v3", "digest_algorithms": [],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "data",  # not tst_info
            "content": core.ParsableOctetString(b"\x01\x02\x03"),
        }),
        "signer_infos": [],
    })
    raw = _TimeStampResp({
        "status": tsp.PKIStatusInfo({"status": "granted"}),
        "time_stamp_token": cms.ContentInfo(
            {"content_type": "signed_data", "content": signed}
        ),
    }).dump()

    anchor = Rfc3161Anchor("https://tsa.example/tsr", transport=lambda u, b: raw)
    with pytest.raises(AnchorError, match="unparseable token"):
        anchor.anchor(b"the-audit-head")


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


# --- emitting an anchor for publication ---


def test_entry_by_hash_returns_the_anchor_record(conn):
    """Emitting reads the token back out of the chain rather than holding it
    across the call — the chain is where the evidence lives."""
    from lethe.audit import AuditLog

    audit = AuditLog(conn)
    audit.init_schema()
    result = audit.anchor_head(
        Rfc3161Anchor("https://tsa.example/tsr", transport=_fake_tsa())
    )
    entry = audit.entry_by_hash(result["entry_hash"])
    assert entry["event"] == "anchor"
    assert entry["anchored_head"] == result["anchored_head"]
    assert base64.b64decode(entry["token"]).startswith(b"\x30")


def test_entry_by_hash_raises_on_an_unknown_hash(conn):
    from lethe.audit import AuditLog

    audit = AuditLog(conn)
    audit.init_schema()
    with pytest.raises(KeyError, match="no audit entry"):
        audit.entry_by_hash("f" * 64)


def test_anchor_emit_writes_a_self_contained_record(conn, tmp_path, monkeypatch):
    """The emitted file is the copy that lives outside the operator's reach, so
    it must carry everything a third party needs: the head that was attested,
    and the raw token to check it against. Without both, publishing it proves
    nothing."""
    import json

    from click.testing import CliRunner

    from lethe.audit import AuditLog
    from lethe.cli import cli

    AuditLog(conn).init_schema()

    # Keep the real CLI path but stub the authority, so this stays offline.
    import lethe.anchor as anchor_module

    real = anchor_module.Rfc3161Anchor

    def _stubbed(url, **kwargs):
        return real(url, transport=_fake_tsa(), **{k: v for k, v in kwargs.items()
                                                   if k != "transport"})

    monkeypatch.setattr(anchor_module, "Rfc3161Anchor", _stubbed)

    out = tmp_path / "anchor-public.json"
    result = CliRunner().invoke(
        cli,
        ["anchor", "--database-url", os.environ["LETHE_TEST_DATABASE_URL"],
         # Credential-bearing on purpose: this file gets published.
         "--tsa", "https://acct-12345:s3cr3t@tsa.example/tsr?apikey=DEADBEEF",
         "--emit", str(out)],
    )
    assert result.exit_code == 0, result.output

    record = json.loads(out.read_text())
    assert record["anchored_at"] == GEN_TIME.isoformat()
    assert record["digest_algorithm"] == "sha256"
    # The two things a verifier cannot proceed without.
    assert len(record["anchored_head"]) == 64
    assert base64.b64decode(record["token"]).startswith(b"\x30")
    # And a pointer to how, so the file is useful without the docs to hand.
    assert "openssl ts -verify" in record["verify"]
    # The file is for publication, so nothing in it may carry the credential
    # the operator authenticates to the TSA with.
    assert record["authority"] == "https://tsa.example/tsr"
    for secret in ("acct-12345", "s3cr3t", "DEADBEEF"):
        assert secret not in out.read_text()
    # Pin the exact field set. This file is published, so a field added to the
    # record later has to be justified against that rather than inherited.
    assert set(record) == {
        "anchored_head", "anchored_at", "authority", "digest",
        "digest_algorithm", "policy", "token", "verify",
    }
    # The one thing a third party actually does with the file: reproduce the
    # digest from the head, exactly as the `verify` recipe says to.
    assert record["digest"] == hashlib.sha256(
        record["anchored_head"].encode()
    ).hexdigest()


def test_authority_recorded_for_publication_carries_no_credential():
    """`authority` is evidence metadata: it lands in the audit chain and in the
    file `anchor --emit` is meant to publish. A TSA endpoint can carry a
    credential (HTTP userinfo, an API key in the query), so recording the URL
    verbatim would hand it to everyone the anchor is shown to."""
    url = "https://acct-12345:s3cr3t@tsa.example/tsr?apikey=DEADBEEF"
    result = Rfc3161Anchor(url, transport=_fake_tsa()).anchor(b"head")

    assert result.authority == "https://tsa.example/tsr"
    for secret in ("acct-12345", "s3cr3t", "DEADBEEF", "apikey"):
        assert secret not in result.authority


def test_scrubbing_the_authority_does_not_change_where_the_request_goes():
    """Only the recorded form is scrubbed. Stripping the credential from the
    request itself would break every TSA that authenticates that way."""
    posted = {}

    def transport(url, body):
        posted["url"] = url
        return _fake_tsa()(url, body)

    url = "https://acct:pw@tsa.example/tsr?apikey=DEADBEEF"
    Rfc3161Anchor(url, transport=transport).anchor(b"head")

    assert posted["url"] == url


def test_public_authority_url_keeps_what_identifies_the_authority():
    """Host, port and path stay: a verifier uses them to know whose token this
    is. Nothing else in a URL identifies an authority."""
    from lethe.anchor import public_authority_url

    assert public_authority_url("https://freetsa.org/tsr") == "https://freetsa.org/tsr"
    assert (
        public_authority_url("http://tsa.example:8080/a/b#frag")
        == "http://tsa.example:8080/a/b"
    )


def test_a_failed_emit_does_not_destroy_the_published_record(conn, tmp_path, monkeypatch):
    """The emitted file is, by this feature's own argument, the copy of the
    evidence that lives outside the operator's reach. A re-emit that dies
    mid-write must leave the previous record intact rather than truncate it to
    nothing — and must never leave a half-written document at the path a reader
    is being served."""
    import json

    from click.testing import CliRunner

    from lethe.audit import AuditLog
    from lethe.cli import cli

    AuditLog(conn).init_schema()

    import lethe.anchor as anchor_module

    real = anchor_module.Rfc3161Anchor
    monkeypatch.setattr(
        anchor_module, "Rfc3161Anchor",
        lambda url, **kw: real(url, transport=_fake_tsa(),
                               **{k: v for k, v in kw.items() if k != "transport"}),
    )

    out = tmp_path / "anchor-public.json"
    args = ["anchor", "--database-url", os.environ["LETHE_TEST_DATABASE_URL"],
            "--emit", str(out)]
    assert CliRunner().invoke(cli, args).exit_code == 0
    published = out.read_text()

    def _explode(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(json, "dump", _explode)
    result = CliRunner().invoke(cli, args)
    assert result.exit_code != 0

    assert out.read_text() == published
    assert list(tmp_path.iterdir()) == [out]

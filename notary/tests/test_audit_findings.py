"""Regressions for what auditing the first cut of this service turned up.

Each of these failed against the code as originally written.
"""

import concurrent.futures as futures
import hashlib
import json
import time

import pytest
from conftest import make_cert
from lethe_notary.service import challenge_message, create_app
from starlette.testclient import TestClient

from lethe.cert_schema import verify_certificate_json
from lethe.certificate import canonical_payload_bytes
from lethe.signing import Signer, key_id_for


@pytest.fixture
def client(notary_signer, log, free_config):
    app = create_app(signer=notary_signer, log=log, config=free_config)
    with TestClient(app) as c:
        yield c


def _forged_payload(operator):
    return {
        "schema": "lethe.cert/3", "key_id": key_id_for(operator.public_key_b64()),
        "request_id": "forged", "subject_hash": "f" * 64,
        "issued_at": "2026-01-01T00:00:00+00:00",
        "valid_until": "2026-12-01T00:00:00+00:00", "lethe_version": "0.7.0",
        "claim": "fabricated", "declared_scope": ["pgvector"], "all_verified": True,
        "layers_found": 1, "records_deleted": 999, "all_layers_handled": True,
        "audit_head": "0" * 64, "reverifiable": False, "timestamp": None,
        "layers": [{"store": "pgvector", "namespace": "docs", "deleted_count": 999,
                    "verified_absent": True, "requested_count": 999, "handled": True,
                    "erased": True, "residual_count": 0, "verify_method": "fabricated",
                    "index_version": None}],
    }


def test_the_challenge_cannot_be_used_as_a_certificate_signing_oracle(client, operator):
    """The worst bug this service could have, and it was there.

    The operator proves key control with the SAME key that signs certificates,
    and the NOTARY chooses the nonce. A malicious notary — or anyone who can
    tamper with the /challenge response — serves a canonical certificate
    payload as the nonce. A client that signs the bare nonce hands back a valid
    certificate signature, and the attacker wraps it in an envelope: a
    certificate attesting to 999 deletions that never happened, verifying
    against the operator's published key. Verified end to end before the fix.

    Domain separation closes it: a certificate payload is canonical JSON and
    always starts with "{", so a prefixed challenge can never be one.
    """
    forged = _forged_payload(operator)
    payload_bytes = canonical_payload_bytes(forged)

    # The malicious notary serves the certificate payload as the nonce.
    evil_nonce = payload_bytes.decode()
    # A compliant client signs the domain-separated message instead.
    signature = operator.sign(challenge_message(client.app.state.notary.key_id, evil_nonce))

    cert = {"payload": forged,
            "payload_hash": hashlib.sha256(payload_bytes).hexdigest(),
            "signature": signature, "public_key": operator.public_key_b64()}
    verdict = verify_certificate_json(cert, trusted_public_key=operator.public_key_b64())

    assert verdict["valid"] is False
    assert verdict["reasons"] == ["BAD_SIGNATURE"]

    # And the harvested signature is what the bare-nonce client WOULD have
    # produced — that one really does forge a certificate, which is why the
    # server refuses it.
    oracle_sig = operator.sign(payload_bytes)
    oracle_cert = dict(cert, signature=oracle_sig)
    assert verify_certificate_json(
        oracle_cert, trusted_public_key=operator.public_key_b64())["valid"] is True


def test_a_slow_facilitator_does_not_block_unrelated_requests(
    notary_signer, log, free_config, operator
):
    """The facilitator call is synchronous network I/O. Run inline in an async
    handler it blocks the event loop, so one slow payment stalls every other
    request — including /witness, which is the dispute query. Measured before
    the fix: four concurrent notarizations against a 0.3s facilitator took
    1.23s, fully serialized."""
    class SlowGate:
        enabled = True
        config = free_config

        def charge(self, request):
            time.sleep(0.25)
            return True, None

    app = create_app(signer=notary_signer, log=log, config=free_config)
    app.state.notary.gate = SlowGate()

    with TestClient(app) as client:
        bodies = [json.dumps(make_cert(operator, request_id=f"r{i}")) for i in range(4)]
        started = time.monotonic()
        with futures.ThreadPoolExecutor(4) as pool:
            responses = list(pool.map(
                lambda b: client.post("/notarize", content=b), bodies))
        elapsed = time.monotonic() - started

    assert all(r.status_code == 200 for r in responses)
    # Serialized would be ~1.0s; concurrent is ~0.25s. Generous bound so this
    # measures the event loop, not the machine.
    assert elapsed < 0.7, f"requests serialized ({elapsed:.2f}s): payment I/O is blocking"


def test_the_same_certificate_presented_concurrently_is_charged_once(
    notary_signer, log, free_config, operator
):
    """Moving the charge off the event loop puts an await between "have we
    witnessed this?" and "record it". Without a per-certificate lock, two
    concurrent presentations of one certificate both miss the check, both pay,
    and only one row survives the UNIQUE index — the loser paid for a receipt
    it is then told it did not buy."""
    class CountingGate:
        enabled = True
        config = free_config

        def __init__(self):
            self.charges = 0

        def charge(self, request):
            time.sleep(0.05)          # widen the window
            self.charges += 1
            return True, None

    app = create_app(signer=notary_signer, log=log, config=free_config)
    gate = CountingGate()
    app.state.notary.gate = gate

    with TestClient(app) as client:
        body = json.dumps(make_cert(operator, request_id="dup"))
        with futures.ThreadPoolExecutor(5) as pool:
            responses = list(pool.map(
                lambda _: client.post("/notarize", content=body), range(5)))

    assert gate.charges == 1, f"charged {gate.charges} times for one certificate"
    assert [r.json()["charged"] for r in responses].count(True) == 1
    # All five callers get the same receipt — not five receipts disagreeing
    # about when the certificate was witnessed.
    assert len({json.dumps(r.json()["receipt"], sort_keys=True) for r in responses}) == 1


def test_the_witness_query_never_truncates_silently(client, operator, notary_signer):
    """The worst way this service could fail quietly: a head that WAS witnessed
    but is not returned reads exactly like one that was never witnessed, and
    the operator draws the opposite conclusion from the one the evidence
    supports."""
    from lethe_notary.receipt import build_receipt

    log = client.app.state.notary.log
    for i in range(1005):
        log.record(build_receipt(
            make_cert(operator, request_id=f"r{i}", audit_head=f"{i:064d}"),
            signer=notary_signer))

    collected, after, pages = [], 0, 0
    while True:
        issued = client.get("/challenge").json()
        body = client.post("/witness", content=json.dumps({
            "public_key": operator.public_key_b64(), "nonce": issued["nonce"],
            "signature": operator.sign(issued["sign"].encode()), "after": after,
        })).json()
        collected += body["witnessed"]
        pages += 1
        if body["complete"]:
            break
        after = body["next_after"]
        assert after is not None

    assert pages > 1, "the truncation case was never exercised"
    assert len(collected) == 1005
    assert len({h["audit_head"] for h in collected}) == 1005


def test_an_uncompleted_page_says_so(client, operator, notary_signer):
    from lethe_notary.receipt import build_receipt

    log = client.app.state.notary.log
    for i in range(1002):
        log.record(build_receipt(
            make_cert(operator, request_id=f"r{i}", audit_head=f"{i:064d}"),
            signer=notary_signer))

    issued = client.get("/challenge").json()
    body = client.post("/witness", content=json.dumps({
        "public_key": operator.public_key_b64(), "nonce": issued["nonce"],
        "signature": operator.sign(issued["sign"].encode()),
    })).json()

    assert body["complete"] is False
    assert body["next_after"] is not None
    assert "before concluding anything" in body["note"]


def test_outstanding_challenges_are_capped(client):
    """Challenges are unauthenticated and free to request, so the store needs a
    ceiling and not only a TTL."""
    import lethe_notary.service as svc

    notary = client.app.state.notary
    notary._challenges = {f"n{i}": time.monotonic() + 999
                          for i in range(svc.MAX_OUTSTANDING_CHALLENGES)}

    r = client.get("/challenge")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "BUSY"
    assert r.json()["error"]["retriable"] is True


def test_an_oversized_body_is_refused_on_the_declared_length(client):
    """Awaiting the body first would buffer the whole thing and only then
    complain, turning the size limit into an amplifier."""
    r = client.post("/notarize", content=b"{}",
                    headers={"content-length": str(64 * 1024 + 1)})
    assert r.status_code == 413


def test_the_witness_endpoint_also_bounds_its_body(client):
    r = client.post("/witness", content=json.dumps({"public_key": "x" * (9 * 1024)}))
    assert r.status_code == 413


@pytest.mark.parametrize("body", ["[]", '"a string"', "42", "null"])
def test_a_non_object_witness_body_is_a_400_not_a_crash(client, body):
    assert client.post("/witness", content=body).status_code == 400


# -- second audit pass ------------------------------------------------------


def test_a_customer_is_never_charged_and_handed_nothing(
    notary_signer, log, free_config, operator
):
    """The one outcome that must never happen. If the witness log write fails
    after payment, the signed receipt is still what the customer bought — the
    log is the notary's own convenience copy. Failing the request here would
    take their money and return a 500."""
    class Gate:
        enabled = True
        config = free_config

        def __init__(self):
            self.charges = 0

        def charge(self, request):
            self.charges += 1
            return True, None

    app = create_app(signer=notary_signer, log=log, config=free_config)
    gate = Gate()
    app.state.notary.gate = gate

    def explode(receipt):
        raise OSError("disk full")

    log.record = explode

    with TestClient(app, raise_server_exceptions=False) as client:
        r = client.post("/notarize", content=json.dumps(make_cert(operator)))

    assert r.status_code == 200
    body = r.json()
    assert gate.charges == 1
    # They got the thing they paid for...
    from lethe_notary.receipt import verify_receipt
    assert verify_receipt(body["receipt"], notary_signer.public_key_b64())["valid"] is True
    # ...and are told plainly that the off-site copy did not land.
    assert body["witness_recorded"] is False
    assert body["charged"] is True
    assert "not covered by the notary's truncation check" in body["warning"]


def test_notarize_is_rate_limited(client, operator):
    """Free-mode notarizing is real work available to anyone. Without a limit
    one caller fills the witness log."""
    import lethe_notary.service as svc

    codes = [client.post("/notarize",
                         content=json.dumps(make_cert(operator, request_id=f"r{i}"))
                         ).status_code
             for i in range(svc.NOTARIZE_BURST + 6)]

    assert 429 in codes, "no request was ever refused"
    assert codes[0] == 200, "the limiter should not bite on the first request"
    assert client.post("/notarize", content=json.dumps(make_cert(operator))
                       ).json()["error"]["retriable"] is True


def test_challenge_is_rate_limited(client):
    import lethe_notary.service as svc

    codes = [client.get("/challenge").status_code
             for _ in range(svc.CHALLENGE_BURST + 6)]
    assert 429 in codes


def test_x_forwarded_for_is_ignored_unless_a_proxy_is_declared(
    notary_signer, log, free_config, operator
):
    """Trusting the header unconditionally lets any caller mint a fresh
    identity per request, which turns the limiter off for exactly the people it
    exists to stop."""
    import lethe_notary.service as svc

    app = create_app(signer=notary_signer, log=log, config=free_config)
    with TestClient(app) as client:
        codes = [
            client.post("/notarize",
                        content=json.dumps(make_cert(operator, request_id=f"r{i}")),
                        headers={"x-forwarded-for": f"10.0.0.{i}"}).status_code
            for i in range(svc.NOTARIZE_BURST + 6)
        ]
    assert 429 in codes, "spoofed X-Forwarded-For bypassed the rate limiter"


def test_a_receipt_stays_verifiable_after_the_notary_rotates_its_key(
    log, free_config, operator
):
    """Receipts are evidence that must outlive a rotation. Without a key
    registry, rotating silently invalidates every receipt already sold."""
    from lethe_notary.receipt import build_receipt, verify_receipt

    retired, current = Signer.generate(), Signer.generate()
    old_receipt = build_receipt(make_cert(operator), signer=retired)

    app = create_app(signer=current, log=log, config=free_config,
                     previous_keys=(retired.public_key_b64(),))
    with TestClient(app) as client:
        published = client.get("/.well-known/notary").json()

    registry = {k["key_id"]: k["public_key"] for k in published["keys"]}
    assert len(registry) == 2
    # The old receipt still verifies through the published registry...
    assert verify_receipt(old_receipt, trusted_keys=registry)["valid"] is True
    # ...and against the current key alone it correctly does not.
    assert verify_receipt(old_receipt, current.public_key_b64())["reasons"] == [
        "KEY_MISMATCH"
    ]


def test_a_receipt_naming_an_unknown_notary_key_says_so(notary_signer, operator):
    from lethe_notary.receipt import build_receipt, verify_receipt

    receipt = build_receipt(make_cert(operator), signer=notary_signer)
    other = Signer.generate()
    registry = {key_id_for(other.public_key_b64()): other.public_key_b64()}

    result = verify_receipt(receipt, trusted_keys=registry)
    assert result["reasons"] == ["UNKNOWN_KEY_ID"]


def test_verify_receipt_requires_exactly_one_source_of_trust(notary_signer, operator):
    from lethe_notary.receipt import build_receipt, verify_receipt

    receipt = build_receipt(make_cert(operator), signer=notary_signer)
    with pytest.raises(ValueError, match="exactly one"):
        verify_receipt(receipt)
    with pytest.raises(ValueError, match="exactly one"):
        verify_receipt(receipt, notary_signer.public_key_b64(), trusted_keys={})


def test_the_witness_log_can_be_snapshotted_while_serving(client, operator, tmp_path):
    """One SQLite file is the only off-site copy of everyone's audit heads."""
    from lethe_notary.store import WitnessLog

    for i in range(3):
        client.post("/notarize",
                    content=json.dumps(make_cert(operator, request_id=f"r{i}")))

    out = tmp_path / "snapshot.db"
    assert client.app.state.notary.log.backup_to(str(out)) == 3
    assert WitnessLog(str(out)).count() == 3


def test_the_log_is_crash_durable(client):
    """WAL + synchronous=FULL: a receipt handed to a customer is on disk before
    the response goes out."""
    conn = client.app.state.notary.log._conn
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL

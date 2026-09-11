"""tools/pay.py — the buyer script, and the one file it must never lose.

It is the documented acceptance path for the idempotency guarantee, so it runs
on customers' machines against real money. The guard under test here replaced a
fixed `receipt.json`, which meant buying a second certificate silently
destroyed the first receipt while printing "this is the evidence" as it did.
Measured before the fix: two purchases, one file left.
"""

import importlib.util
import json
import pathlib

_PAY = pathlib.Path(__file__).resolve().parents[1] / "tools" / "pay.py"


def _load_pay():
    """Import the script by path: tools/ is not a package, deliberately — it is
    a directory of standalone scripts, not part of the distribution."""
    spec = importlib.util.spec_from_file_location("pay_tool", _PAY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Response:
    """Stands in for httpx.Response. Only the two members _report touches."""

    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code

    def json(self):
        return self._body


def _body(payload_hash, *, charged=True, receipt_extra=None):
    receipt = {"payload": {"certificate_payload_hash": payload_hash,
                           **(receipt_extra or {})},
               "signature": "sig-" + payload_hash[:8]}
    return {"ok": True, "charged": charged, "already_witnessed": not charged,
            "witness_recorded": True, "receipt": receipt}


def test_two_different_certificates_keep_two_receipts(tmp_path, monkeypatch):
    """The failure this replaced: the second purchase overwrote the first."""
    pay = _load_pay()
    monkeypatch.chdir(tmp_path)

    assert pay._report(_Response(_body("a" * 64)), None) == 0
    assert pay._report(_Response(_body("b" * 64)), None) == 0

    written = sorted(p.name for p in tmp_path.glob("receipt-*.json"))
    assert written == [f"receipt-{'a' * 16}.json", f"receipt-{'b' * 16}.json"]
    for name, expected in zip(written, ["a" * 64, "b" * 64], strict=True):
        got = json.loads((tmp_path / name).read_text())
        assert got["payload"]["certificate_payload_hash"] == expected


def test_rebuying_the_same_certificate_rewrites_an_identical_file(tmp_path, monkeypatch):
    """The idempotency check is documented as 'run it twice', so the second run
    must not be an error. The notary returns the ORIGINAL receipt, so the bytes
    are identical and rewriting them is a no-op."""
    pay = _load_pay()
    monkeypatch.chdir(tmp_path)

    assert pay._report(_Response(_body("c" * 64, charged=True)), None) == 0
    before = (tmp_path / f"receipt-{'c' * 16}.json").read_bytes()
    assert pay._report(_Response(_body("c" * 64, charged=False)), None) == 0
    assert (tmp_path / f"receipt-{'c' * 16}.json").read_bytes() == before


def test_a_different_receipt_at_that_path_is_never_clobbered(tmp_path, monkeypatch):
    """Same payload hash, different receipt bytes — a re-signed or tampered
    receipt. Refuse, and leave what is on disk alone: it is evidence."""
    pay = _load_pay()
    monkeypatch.chdir(tmp_path)

    assert pay._report(_Response(_body("d" * 64)), None) == 0
    path = tmp_path / f"receipt-{'d' * 16}.json"
    original = path.read_bytes()

    other = _body("d" * 64, receipt_extra={"witnessed_at": "2099-01-01T00:00:00+00:00"})
    assert pay._report(_Response(other), None) == 1
    assert path.read_bytes() == original


def test_out_overrides_the_derived_name(tmp_path, monkeypatch):
    pay = _load_pay()
    monkeypatch.chdir(tmp_path)
    assert pay._report(_Response(_body("e" * 64)), "mine.json") == 0
    assert (tmp_path / "mine.json").exists()
    assert not list(tmp_path.glob("receipt-*.json"))


def test_a_receipt_with_no_payload_hash_still_lands_somewhere(tmp_path, monkeypatch):
    """Defensive: a receipt shape we do not recognise must not crash the tool
    and lose the evidence entirely. It gets a name, and the caller is told."""
    pay = _load_pay()
    monkeypatch.chdir(tmp_path)
    body = {"ok": True, "charged": True, "witness_recorded": True,
            "receipt": {"unexpected": "shape"}}
    assert pay._report(_Response(body), None) == 0
    assert (tmp_path / "receipt-unknown.json").exists()


def test_a_refused_notarization_reports_failure_and_writes_nothing(tmp_path, monkeypatch):
    pay = _load_pay()
    monkeypatch.chdir(tmp_path)
    body = {"ok": False, "error": {"code": "CERTIFICATE_INVALID", "message": "no"}}
    assert pay._report(_Response(body, status_code=422), None) == 1
    assert not list(tmp_path.iterdir())


def test_the_tool_imports_and_exposes_its_entry_points():
    """Cheap guard that the script stays importable — CI runs `--help`, but a
    syntax error in a branch it does not exercise would still ship."""
    pay = _load_pay()
    assert callable(pay.main)
    assert callable(pay._report)

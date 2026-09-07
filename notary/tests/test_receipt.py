"""What a receipt may and may not say."""

import pytest
from conftest import make_cert
from lethe_notary.receipt import (
    NotarizationRefused,
    binds_certificate,
    build_receipt,
    verify_receipt,
)

from lethe.signing import Signer, key_id_for


def test_a_valid_certificate_is_countersigned(operator, notary_signer):
    cert = make_cert(operator)
    receipt = build_receipt(cert, signer=notary_signer)

    assert verify_receipt(receipt, notary_signer.public_key_b64()) == {
        "valid": True, "reasons": [], "detail": []
    }
    p = receipt["payload"]
    assert p["certificate_payload_hash"] == cert["payload_hash"]
    assert p["certificate_key_id"] == key_id_for(operator.public_key_b64())
    assert p["audit_head"] == "a" * 64
    assert p["notary_key_id"] == key_id_for(notary_signer.public_key_b64())


def test_a_tampered_certificate_is_never_countersigned(operator, notary_signer):
    """Lending the notary's signature to something it did not actually check
    would be worse than not existing."""
    cert = make_cert(operator)
    cert["payload"]["records_deleted"] = 9999

    with pytest.raises(NotarizationRefused) as e:
        build_receipt(cert, signer=notary_signer)
    assert e.value.reasons == ["PAYLOAD_TAMPERED"]


def test_a_certificate_signed_by_a_different_key_is_refused(operator, notary_signer):
    """The envelope's key must be the key that signed it — otherwise anyone
    could have the notary attest to an artifact they did not produce."""
    cert = make_cert(operator)
    cert["public_key"] = Signer.generate().public_key_b64()

    with pytest.raises(NotarizationRefused):
        build_receipt(cert, signer=notary_signer)


@pytest.mark.parametrize("cert", [None, {}, {"payload": "nope"}, 42, []])
def test_garbage_is_refused_not_crashed_on(cert, notary_signer):
    with pytest.raises(NotarizationRefused):
        build_receipt(cert, signer=notary_signer)


def test_a_receipt_must_be_pinned_to_the_notarys_published_key(operator, notary_signer):
    """A receipt checked only against the key inside it proves nothing: anyone
    can mint that pair. Same discipline as Lethe's own verifier."""
    receipt = build_receipt(make_cert(operator), signer=notary_signer)
    impostor = Signer.generate()

    assert verify_receipt(receipt, impostor.public_key_b64())["reasons"] == ["KEY_MISMATCH"]


def test_a_tampered_receipt_does_not_verify(operator, notary_signer):
    receipt = build_receipt(make_cert(operator), signer=notary_signer)
    receipt["payload"]["witnessed_at"] = "2020-01-01T00:00:00+00:00"

    assert verify_receipt(receipt, notary_signer.public_key_b64())["reasons"] == [
        "PAYLOAD_TAMPERED"
    ]


def test_notary_key_id_is_recomputed_not_trusted(operator, notary_signer):
    """Same reason Lethe recomputes it: a derived id that is never derived is
    decorative, and would let a receipt name a key epoch it was not signed by."""
    receipt = build_receipt(make_cert(operator), signer=notary_signer)
    receipt["payload"]["notary_key_id"] = key_id_for(Signer.generate().public_key_b64())

    reasons = verify_receipt(receipt, notary_signer.public_key_b64())["reasons"]
    assert reasons in (["KEY_ID_MISMATCH"], ["PAYLOAD_TAMPERED"])


def test_a_valid_receipt_for_a_different_certificate_does_not_bind(operator, notary_signer):
    """The attack this closes: present a genuine receipt for certificate A
    alongside certificate B and claim B was witnessed. The signature checks
    out; it just is not about B."""
    cert_a = make_cert(operator, request_id="a")
    cert_b = make_cert(operator, request_id="b")
    receipt = build_receipt(cert_a, signer=notary_signer)

    assert binds_certificate(receipt, cert_a) is True
    assert binds_certificate(receipt, cert_b) is False

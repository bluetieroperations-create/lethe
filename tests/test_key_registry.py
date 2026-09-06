"""Verifying against a registry of historical keys.

cert v3 made certificates self-describing about which key epoch signed them,
but both verifiers took a single key — so docs/key-rotation.md had to tell
readers to hand-maintain a {key_id: key} dict and do the lookup themselves.
The certificate knows; the verifier should read it.
"""

import base64

import pytest

from lethe.cert_schema import verify_certificate_json
from lethe.certificate import build_certificate, certificate_to_dict, verify_certificate
from lethe.models import LayerResult
from lethe.signing import Signer, key_id_for


def _cert(signer):
    return build_certificate(
        request_id="r", subject_hash="s",
        layers=[LayerResult("pgvector", "docs", 1, True, requested_count=1)],
        issued_at="2026-01-01T00:00:00+00:00", version="0.5.0", signer=signer,
    )


def _registry(*signers):
    return {key_id_for(s.public_key_b64()): s.public_key_b64() for s in signers}


def test_registry_resolves_the_epoch_that_signed():
    """The rotation case: a certificate from a retired key still verifies,
    because it names the epoch and the registry still holds it."""
    retired, current = Signer.generate(), Signer.generate()
    cert = certificate_to_dict(_cert(retired))
    assert verify_certificate_json(cert, trusted_keys=_registry(retired, current)) == {
        "valid": True, "reasons": [], "detail": []
    }


def test_current_key_alone_still_fails_an_old_certificate():
    """Unchanged, and correct — that is the pin working. The registry is what
    makes rotation usable, not a loosening of the pin."""
    retired, current = Signer.generate(), Signer.generate()
    cert = certificate_to_dict(_cert(retired))
    assert verify_certificate_json(cert, current.public_key_b64())["reasons"] == [
        "KEY_MISMATCH"
    ]


def test_an_epoch_missing_from_the_registry_says_so():
    """Distinct from KEY_MISMATCH: the certificate is fine, the verifier simply
    has not been given that key. An agent should not retry on this."""
    unknown, current = Signer.generate(), Signer.generate()
    result = verify_certificate_json(
        certificate_to_dict(_cert(unknown)), trusted_keys=_registry(current)
    )
    assert result["reasons"] == ["UNKNOWN_KEY_ID"]
    assert "not in the provided registry" in result["detail"][0]


def test_a_pre_v3_certificate_cannot_be_resolved_by_registry():
    """v1/v2 predate key_id, so there is nothing to look up. Say that, rather
    than failing with a misleading key mismatch."""
    import hashlib

    from lethe.certificate import canonical_payload_bytes

    signer = Signer.generate()
    payload = {
        "schema": "lethe.cert/2", "request_id": "r", "subject_hash": "s",
        "issued_at": "2026-07-06T00:00:00+00:00",
        "valid_until": "2026-08-06T00:00:00+00:00",
        "lethe_version": "0.2.0", "claim": "legacy", "declared_scope": ["pgvector"],
        "all_verified": True, "layers_found": 1, "records_deleted": 1,
        "all_layers_handled": True,
        "layers": [{
            "store": "pgvector", "namespace": "docs", "deleted_count": 1,
            "verified_absent": True, "requested_count": 1, "handled": True,
            "erased": True, "residual_count": 0, "verify_method": "legacy",
            "index_version": None,
        }],
    }
    data = canonical_payload_bytes(payload)
    cert = {
        "payload": payload, "payload_hash": hashlib.sha256(data).hexdigest(),
        "signature": signer.sign(data), "public_key": signer.public_key_b64(),
    }
    result = verify_certificate_json(cert, trusted_keys=_registry(signer))
    assert result["reasons"] == ["UNKNOWN_KEY_ID"]
    assert "predates" in result["detail"][0]
    # ...and it still verifies the documented way.
    assert verify_certificate_json(cert, signer.public_key_b64())["valid"] is True


def test_a_tampered_certificate_is_still_caught_through_the_registry():
    """The registry selects the key; it must not shortcut any later check."""
    signer = Signer.generate()
    cert = certificate_to_dict(_cert(signer))
    cert["payload"]["records_deleted"] = 9999
    assert verify_certificate_json(cert, trusted_keys=_registry(signer))["reasons"] == [
        "PAYLOAD_TAMPERED"
    ]


@pytest.mark.parametrize("kwargs", [{}, {"trusted_keys": {}, "trusted_public_key": "x"}])
def test_exactly_one_source_of_trust_is_required(kwargs):
    """Neither argument is an unpinned check; both is ambiguous. Refuse rather
    than pick one."""
    cert = certificate_to_dict(_cert(Signer.generate()))
    with pytest.raises(ValueError, match="exactly one"):
        verify_certificate_json(cert, **kwargs)


def test_the_crypto_path_takes_a_registry_too():
    retired, current = Signer.generate(), Signer.generate()
    cert = _cert(retired)
    assert verify_certificate(cert, trusted_keys=_registry(retired, current)) is True
    assert verify_certificate(cert, trusted_keys=_registry(current)) is False
    with pytest.raises(ValueError, match="exactly one"):
        verify_certificate(cert)


def _resigned_claiming(signer, claimed_key_id):
    """A fully self-consistent certificate whose signed payload names a key
    epoch other than the one that signed it. Nothing about it is malformed:
    the hash matches the payload, the signature matches the hash. Only
    recomputing key_id from the key actually present can refuse it."""
    import hashlib

    from lethe.certificate import canonical_payload_bytes

    payload = {**_cert(signer).payload, "key_id": claimed_key_id}
    data = canonical_payload_bytes(payload)
    return {
        "payload": payload,
        "payload_hash": hashlib.sha256(data).hexdigest(),
        "signature": signer.sign(data),
        "public_key": signer.public_key_b64(),
    }


def test_a_misfiled_registry_entry_cannot_launder_a_wrong_key():
    """The registry lets the *certificate* choose which key it is checked
    against, so a mis-mapped entry is the registry's own failure mode: map
    epoch A's id to B's key, and a certificate claiming A but signed by B is
    consistent at every other step — same key pinned, hash intact, signature
    valid. Delete the key_id recomputation and this case verifies."""
    a, b = Signer.generate(), Signer.generate()
    a_id = key_id_for(a.public_key_b64())
    cert = _resigned_claiming(b, a_id)
    misfiled = {a_id: b.public_key_b64()}

    result = verify_certificate_json(cert, trusted_keys=misfiled)
    assert result["valid"] is False
    assert result["reasons"] == ["KEY_ID_MISMATCH"]


def test_a_misfiled_registry_entry_is_caught_on_the_crypto_path_too():
    from lethe.models import Certificate

    a, b = Signer.generate(), Signer.generate()
    a_id = key_id_for(a.public_key_b64())
    cert = Certificate(**_resigned_claiming(b, a_id))
    assert verify_certificate(cert, trusted_keys={a_id: b.public_key_b64()}) is False
    # ...and the same certificate is refused when pinned directly, so the
    # registry is not the only thing standing between it and acceptance.
    assert verify_certificate(cert, b.public_key_b64()) is False


def test_a_forged_signature_is_still_caught_through_the_registry():
    """Distinct from the tampered-payload case: here the payload and its hash
    agree, so only the Ed25519 check can refuse it."""
    signer = Signer.generate()
    cert = certificate_to_dict(_cert(signer))
    sig = bytearray(base64.b64decode(cert["signature"]))
    sig[0] ^= 0xFF
    cert["signature"] = base64.b64encode(bytes(sig)).decode()
    assert verify_certificate_json(cert, trusted_keys=_registry(signer))["reasons"] == [
        "BAD_SIGNATURE"
    ]


def test_an_empty_registry_is_a_registry_not_an_unpinned_check():
    """`{}` is falsy but not None. It must select the registry path and fail
    closed there — never fall through to 'no key supplied, accept'."""
    cert = certificate_to_dict(_cert(Signer.generate()))
    assert verify_certificate_json(cert, trusted_keys={})["reasons"] == ["UNKNOWN_KEY_ID"]
    assert verify_certificate(_cert(Signer.generate()), trusted_keys={}) is False

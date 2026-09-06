import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lethe_notary.payments import PaymentConfig  # noqa: E402
from lethe_notary.store import WitnessLog  # noqa: E402

from lethe.certificate import build_certificate, certificate_to_dict  # noqa: E402
from lethe.models import LayerResult  # noqa: E402
from lethe.signing import Signer  # noqa: E402


@pytest.fixture
def operator():
    return Signer.generate()


@pytest.fixture
def notary_signer():
    return Signer.generate()


@pytest.fixture
def log(tmp_path):
    w = WitnessLog(str(tmp_path / "witness.db"))
    yield w
    w.close()


@pytest.fixture
def free_config():
    return PaymentConfig(pay_to=None, price="$0.01", network="base",
                         facilitator_url="https://x402.org/facilitator", free_mode=True)


def make_cert(signer, *, subject="s", audit_head="a" * 64, request_id="r"):
    return certificate_to_dict(build_certificate(
        request_id=request_id, subject_hash=subject,
        layers=[LayerResult("pgvector", "docs", 1, True, requested_count=1)],
        issued_at="2026-01-01T00:00:00+00:00", version="0.7.0", signer=signer,
        audit_head=audit_head,
    ))

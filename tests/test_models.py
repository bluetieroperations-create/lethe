import pytest

from lethe.models import Certificate, LayerResult, TagRecord


def test_tag_record_fields():
    t = TagRecord(subject_hash="abc", store="pgvector", namespace="docs", record_id="r1")
    assert t.store == "pgvector"
    assert t.record_id == "r1"


def test_layer_result_fields():
    l = LayerResult(store="pgvector", namespace="docs", deleted_count=3, verified_absent=True)
    assert l.deleted_count == 3
    assert l.verified_absent is True


def test_models_are_frozen():
    t = TagRecord(subject_hash="abc", store="pgvector", namespace="docs", record_id="r1")
    with pytest.raises(Exception):
        t.store = "redis"


def test_certificate_holds_signed_parts():
    c = Certificate(payload={"a": 1}, payload_hash="h", signature="s", public_key="k")
    assert c.payload == {"a": 1}
    assert c.signature == "s"

import os

import psycopg
import pytest

DATABASE_URL = os.environ.get("LETHE_TEST_DATABASE_URL")


@pytest.fixture
def conn():
    if not DATABASE_URL:
        pytest.skip(
            "Set LETHE_TEST_DATABASE_URL to your Neon dev connection string to run DB tests."
        )
    with psycopg.connect(DATABASE_URL) as c:
        with c.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS lethe_provenance, lethe_audit CASCADE")
            cur.execute("DROP TABLE IF EXISTS test_vectors CASCADE")
        c.commit()
        yield c

"""Seed the demo: a `candidates` table with embeddings, tagged in Lethe for
deletion. Run once before the demo. Env: DEMO_DATABASE_URL (Postgres + pgvector),
DEMO_SALT (default 'demo-salt'), DEMO_KEY_FILE (default 'demo_key.bin')."""

import os

import psycopg

from candidates import CANDIDATES, DIM, embed
from lethe.audit import AuditLog
from lethe.connectors.pgvector import PgVectorConnector
from lethe.core import Lethe
from lethe.ledger import Ledger
from lethe.signing import Signer


def _vec(v):
    return "[" + ",".join(str(x) for x in v) + "]"


def _key_file():
    return os.environ.get("DEMO_KEY_FILE", "demo_key.bin")


def build_lethe(conn):
    with open(_key_file(), "rb") as f:
        signer = Signer.from_private_bytes(f.read())
    return Lethe(
        ledger=Ledger(conn), audit=AuditLog(conn), signer=signer,
        connectors={"pgvector": PgVectorConnector(conn)},
        salt=os.environ.get("DEMO_SALT", "demo-salt"),
    )


def main():
    url = os.environ["DEMO_DATABASE_URL"]
    kf = _key_file()
    if not os.path.exists(kf):
        s = Signer.generate()
        with open(kf, "wb") as f:
            f.write(s.private_bytes())
        print(f"generated signing key -> {kf}")

    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cur.execute("DROP TABLE IF EXISTS candidates")
            cur.execute(
                f"CREATE TABLE candidates (id text PRIMARY KEY, name text, body text, "
                f"embedding vector({DIM}))"
            )
            for c in CANDIDATES:
                cur.execute(
                    "INSERT INTO candidates (id, name, body, embedding) "
                    "VALUES (%s, %s, %s, %s::vector)",
                    (c["id"], c["name"], c["text"], _vec(embed(c["text"]))),
                )
        conn.commit()
        lethe = build_lethe(conn)
        lethe.ledger.init_schema()
        lethe.audit.init_schema()
        for c in CANDIDATES:
            lethe.tag(c["subject"], "pgvector", "candidates", c["id"])

    with open(kf, "rb") as f:
        pub = Signer.from_private_bytes(f.read()).public_key_b64()
    print(f"\nSeeded {len(CANDIDATES)} candidates and tagged them for deletion:")
    for c in CANDIDATES:
        print(f"   {c['name']:11} {c['text']:48} <{c['subject']}>")
    print(f"\nPublic key (paste into the verifier): {pub}")


if __name__ == "__main__":
    main()

"""Seed the demo: a `candidates` table with embeddings, tagged in Lethe for
deletion. Run once before the demo. Env: DEMO_DATABASE_URL (Postgres + pgvector),
DEMO_SALT (required, no default), DEMO_KEY_FILE (default 'demo_key.bin')."""

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


def _salt():
    """The salt has no default, deliberately.

    Subjects are stored in the ledger as HMACs under it, so it is a secret — and
    a committed default is not a secret: every deployment that copied this demo
    would share it. The demo is the first code a prospect reads, so it should
    model the habit the library expects (`Lethe(salt=...)` is required too).

    It must also stay the SAME for the whole demo session. Seeding under one
    salt and forgetting under another hashes the subject to something the ledger
    has never seen. Lethe handles that honestly — measured: `records_deleted=0`,
    `all_verified=False`, and the certificate refuses to call it an erasure — so
    nothing is silently wrong. But mid-demo it reads as the product failing, and
    the candidate stays in the index while you are pointing at the screen.
    """
    salt = os.environ.get("DEMO_SALT")
    if not salt:
        raise SystemExit(
            "DEMO_SALT is not set.\n"
            "  It pseudonymizes subjects in the ledger, so there is no default.\n"
            "  Any throwaway value works — but keep the SAME one for the whole\n"
            "  demo: seeding and forgetting under different salts finds nothing\n"
            "  to delete and reports records_deleted=0, all_verified=False.\n"
            "    PowerShell:  $env:DEMO_SALT = \"my-demo-salt\"\n"
            "    bash:        export DEMO_SALT=my-demo-salt\n"
            "  start-demo.ps1 generates one and prints it for you."
        )
    return salt


def build_lethe(conn):
    with open(_key_file(), "rb") as f:
        signer = Signer.from_private_bytes(f.read())
    return Lethe(
        ledger=Ledger(conn), audit=AuditLog(conn), signer=signer,
        connectors={"pgvector": PgVectorConnector(conn)},
        salt=_salt(),
    )


def main():
    url = os.environ["DEMO_DATABASE_URL"]
    # Validated before anything is created. build_lethe() would catch a missing
    # salt anyway, but only after the signing key had been written to disk — so
    # a run that fails for a missing environment variable would still leave a
    # key behind, and a failed run should be a no-op.
    _salt()
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

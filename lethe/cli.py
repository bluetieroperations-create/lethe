import json

import click
import psycopg

from .audit import AuditLog
from .certificate import verify_certificate
from .connectors.pgvector import PgVectorConnector
from .core import Lethe
from .ledger import Ledger
from .models import Certificate
from .signing import Signer


@click.group()
def cli() -> None:
    """Lethe — the forget button for AI."""


@cli.command("keygen")
@click.option("--out", "out", required=True, help="Path to write the Ed25519 private key.")
def keygen(out: str) -> None:
    signer = Signer.generate()
    with open(out, "wb") as f:
        f.write(signer.private_bytes())
    click.echo(f"Wrote signing key to {out}")
    click.echo(f"Public key (publish this for verifiers): {signer.public_key_b64()}")


@cli.command("init-db")
@click.option("--database-url", envvar="DATABASE_URL", required=True)
def init_db(database_url: str) -> None:
    with psycopg.connect(database_url) as conn:
        Ledger(conn).init_schema()
        AuditLog(conn).init_schema()
    click.echo("Lethe schema initialized.")


@cli.command("forget")
@click.argument("subject_id")
@click.option("--database-url", envvar="DATABASE_URL", required=True)
@click.option("--salt", envvar="LETHE_SALT", required=True)
@click.option("--key-file", envvar="LETHE_KEY_FILE", required=True)
def forget(subject_id: str, database_url: str, salt: str, key_file: str) -> None:
    with open(key_file, "rb") as f:
        signer = Signer.from_private_bytes(f.read())
    with psycopg.connect(database_url) as conn:
        lethe = Lethe(
            ledger=Ledger(conn),
            audit=AuditLog(conn),
            signer=signer,
            connectors={"pgvector": PgVectorConnector(conn)},
            salt=salt,
        )
        cert = lethe.forget(subject_id)
    click.echo(
        json.dumps(
            {
                "payload": cert.payload,
                "payload_hash": cert.payload_hash,
                "signature": cert.signature,
                "public_key": cert.public_key,
            },
            indent=2,
        )
    )


@cli.command("verify")
@click.argument("cert_file")
@click.option(
    "--public-key",
    "public_key",
    required=True,
    help="The operator's published (trusted) Ed25519 public key, base64. "
    "Required: an unpinned check only proves self-consistency, not authenticity.",
)
def verify(cert_file: str, public_key: str) -> None:
    with open(cert_file) as f:
        data = json.load(f)
    cert = Certificate(
        payload=data["payload"],
        payload_hash=data["payload_hash"],
        signature=data["signature"],
        public_key=data["public_key"],
    )
    ok = verify_certificate(cert, trusted_public_key=public_key)
    click.echo("VALID" if ok else "INVALID")
    raise SystemExit(0 if ok else 1)


@cli.command("audit-head")
@click.option("--database-url", envvar="DATABASE_URL", required=True)
def audit_head(database_url: str) -> None:
    """Print the current audit-log head hash. Record it out-of-band so you can
    later detect tip-truncation with `verify-audit --expected-head`."""
    with psycopg.connect(database_url) as conn:
        click.echo(AuditLog(conn).head())


@cli.command("verify-audit")
@click.option("--database-url", envvar="DATABASE_URL", required=True)
@click.option(
    "--expected-head",
    default=None,
    help="The audit head you recorded out-of-band. Without it, tip-truncation "
    "(deletion of the most recent entries) cannot be detected.",
)
def verify_audit(database_url: str, expected_head: str | None) -> None:
    with psycopg.connect(database_url) as conn:
        ok = AuditLog(conn).verify_chain(expected_head=expected_head)
    if expected_head is None:
        click.echo(
            "WARNING: no --expected-head given; internal links checked but "
            "tip-truncation is undetectable.",
            err=True,
        )
    click.echo("VALID" if ok else "INVALID")
    raise SystemExit(0 if ok else 1)

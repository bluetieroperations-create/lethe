import contextlib
import json
import os

import click
import psycopg

from .audit import AuditLog
from .certificate import verify_certificate
from .connectors.pgvector import PgVectorConnector
from .core import Lethe, NamespaceNotAllowed, parse_allowed_namespaces
from .ledger import Ledger
from .models import Certificate
from .signing import Signer


@click.group()
def cli() -> None:
    """Lethe — the forget button for AI."""


def _allowed_namespaces():
    """Shared by the CLI commands that can write to the ledger."""
    try:
        return parse_allowed_namespaces(os.environ.get("LETHE_ALLOWED_NAMESPACES"))
    except ValueError as e:
        raise SystemExit(f"lethe: {e}") from None


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
            # forget() is the command that deletes; it needs the allowlist more
            # than any other entry point, and is the one an operator reaches
            # for while cleaning up after discovering they were hit.
            allowed_namespaces=_allowed_namespaces(),
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


@cli.command("reverify")
@click.argument("subject_id")
@click.option("--database-url", envvar="DATABASE_URL", required=True)
@click.option("--salt", envvar="LETHE_SALT", required=True)
def reverify(subject_id: str, database_url: str, salt: str) -> None:
    """Re-query the stores for a subject whose forget already completed.

    A certificate asserts absence only up to valid_until. This re-checks it —
    possible only where the deployment set retain_verification_ids, since the
    default purge removes the record ids a re-query needs. Exits non-zero if
    the subject's records are back, or if re-verification is not possible.
    """
    with psycopg.connect(database_url) as conn:
        lethe = Lethe(
            ledger=Ledger(conn),
            audit=AuditLog(conn),
            signer=Signer.generate(),  # unused: reverify never signs
            connectors={"pgvector": PgVectorConnector(conn)},
            salt=salt,
        )
        result = lethe.reverify(subject_id)
    click.echo(json.dumps(result, indent=2))
    raise SystemExit(0 if result["still_absent"] else 1)


@cli.command("reconcile")
@click.argument("subject_id")
@click.option("--database-url", envvar="DATABASE_URL", required=True)
@click.option("--salt", envvar="LETHE_SALT", required=True)
@click.option(
    "--target",
    "targets",
    multiple=True,
    required=True,
    help="STORE:NAMESPACE:SUBJECT_FIELD to scan, repeatable. e.g. "
    "pgvector:documents:user_id",
)
@click.option(
    "--tag-untracked",
    is_flag=True,
    help="Tag anything found untracked into the ledger so a later forget "
    "deletes and certifies it. Off by default: detection does not mutate.",
)
def reconcile(
    subject_id: str, database_url: str, salt: str,
    targets: tuple[str, ...], tag_untracked: bool,
) -> None:
    """Compare what a store holds for a subject against what the ledger knows.

    forget() only deletes what was tagged, so writes that bypassed the wrapper
    are invisible to it. This asks the stores directly. Exits non-zero if
    untracked records were found, or if any target could not be scanned.
    """
    parsed = []
    for t in targets:
        parts = t.split(":")
        if len(parts) != 3 or not all(parts):
            raise click.BadParameter(
                f"--target must be STORE:NAMESPACE:SUBJECT_FIELD, got {t!r}"
            )
        parsed.append((parts[0], parts[1], parts[2]))

    with psycopg.connect(database_url) as conn:
        lethe = Lethe(
            ledger=Ledger(conn),
            audit=AuditLog(conn),
            signer=Signer.generate(),  # unused: reconcile never signs
            connectors={"pgvector": PgVectorConnector(conn)},
            salt=salt,
            allowed_namespaces=_allowed_namespaces(),
        )
        try:
            result = lethe.reconcile(
                subject_id, targets=parsed, tag_untracked=tag_untracked
            )
        except NamespaceNotAllowed as e:
            raise SystemExit(f"lethe: {e}") from None
    click.echo(json.dumps(result, indent=2))
    raise SystemExit(0 if result["clean"] else 1)


@cli.command("ledger-scope")
@click.option("--database-url", envvar="DATABASE_URL", required=True)
@click.option(
    "--purge-disallowed",
    is_flag=True,
    help="Delete ledger rows outside the allowlist. Removes Lethe's record "
    "that those rows exist; it does NOT delete anything from the store.",
)
def ledger_scope(database_url: str, purge_disallowed: bool) -> None:
    """Show what the ledger holds, against the configured allowlist.

    Configuring LETHE_ALLOWED_NAMESPACES does not retroactively clean the
    ledger. A row tagged before the allowlist existed still blocks the subject
    it belongs to from ever certifying again, because forget() records it as an
    unhandled layer and all_verified stays false. Run this after configuring an
    allowlist to find those rows. Exits non-zero if any are present.
    """
    allowed = _allowed_namespaces()

    def _is_allowed(store: str, namespace: str) -> bool:
        return allowed is None or namespace in allowed.get(store, set())

    with psycopg.connect(database_url) as conn:
        ledger = Ledger(conn)
        rows = ledger.namespaces()
        disallowed = [(s, n, c) for s, n, c in rows if not _is_allowed(s, n)]
        purged = 0
        if purge_disallowed:
            for store, namespace, _ in disallowed:
                purged += ledger.purge_namespace(store, namespace)
        report = [
            {
                "store": store,
                "namespace": namespace,
                "rows": count,
                "allowed": _is_allowed(store, namespace),
            }
            for store, namespace, count in rows
        ]

    click.echo(
        json.dumps(
            {
                "allowlist": (
                    None if allowed is None
                    else sorted(f"{s}:{n}" for s, ns in allowed.items() for n in ns)
                ),
                "ledger": report,
                "disallowed_rows": sum(c for _, _, c in disallowed),
                "purged_rows": purged,
            },
            indent=2,
        )
    )
    raise SystemExit(0 if not disallowed or purged else 1)


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


@cli.command("anchor")
@click.option("--database-url", envvar="DATABASE_URL", required=True)
@click.option(
    "--tsa",
    envvar="LETHE_TSA_URL",
    default="https://freetsa.org/tsr",
    show_default=True,
    help="RFC 3161 timestamping authority. The default is community-run with "
    "no SLA — point this at an authority you are willing to rely on, and at a "
    "qualified (eIDAS) TSA if you need the legal presumption of Article 41.",
)
@click.option("--hash-algorithm", default="sha256", show_default=True)
@click.option("--timeout", default=20.0, show_default=True, type=float)
@click.option(
    "--emit",
    "emit_path",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Write the anchor record to a file for PUBLISHING. Anchoring closes "
    "backdating on its own, but closes tail truncation only if a token also "
    "lives somewhere you cannot reach — publish this alongside your public key.",
)
def anchor(
    database_url: str, tsa: str, hash_algorithm: str, timeout: float,
    emit_path: str | None,
) -> None:
    """Timestamp the current audit head with an external authority.

    Run this on a schedule. Each anchor pins the chain up to that point: an
    entry cannot later be inserted before an anchored head without
    contradicting the token, which is what makes backdating a recorded forget
    structurally impossible rather than merely detectable.

    Anchoring is deliberately NOT part of forget(): a slow or unreachable
    authority must never block a data-subject request.
    """
    from .anchor import AnchorError, Rfc3161Anchor

    try:
        provider = Rfc3161Anchor(tsa, hash_algorithm=hash_algorithm, timeout=timeout)
        with psycopg.connect(database_url) as conn:
            result = AuditLog(conn).anchor_head(provider)
    except AnchorError as e:
        raise SystemExit(f"lethe: anchoring failed: {e}") from None

    if emit_path:
        # The token is the evidence, and it is only useful against truncation
        # if a copy exists outside the operator's reach. Emitting the raw
        # response verbatim means a third party can check it with any RFC 3161
        # implementation, without Lethe.
        with psycopg.connect(database_url) as conn:
            entry = AuditLog(conn).entry_by_hash(result["entry_hash"])
        record = {
            "anchored_head": result["anchored_head"],
            "anchored_at": result["anchored_at"],
            "authority": result["authority"],
            "digest": entry["digest"],
            "digest_algorithm": entry["digest_algorithm"],
            "policy": entry["policy"],
            "token": entry["token"],
            "verify": (
                "base64 -d <token> > anchor.tsr; "
                "printf %s <anchored_head> > head.txt; "
                "openssl ts -verify -in anchor.tsr -data head.txt "
                "-CAfile <authority chain> -untrusted <authority cert>"
            ),
        }
        # Write-then-rename. This file is the copy of the evidence that lives
        # outside the operator's reach, so a crash mid-write must not destroy
        # the record already published there — and a reader served the path
        # directly must never see half a document.
        tmp_path = emit_path + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(record, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, emit_path)
        except BaseException:
            # Leaving a stale partial next to a published record invites
            # someone to publish the wrong one.
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
        result["emitted_to"] = emit_path

    click.echo(json.dumps(result, indent=2))


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
        log = AuditLog(conn)
        ok = log.verify_chain(expected_head=expected_head)
        forks = log.forks()
    if expected_head is None:
        click.echo(
            "WARNING: no --expected-head given; internal links checked but "
            "tip-truncation is undetectable.",
            err=True,
        )
    # INVALID alone cannot be acted on: a fork and a tampered entry demand very
    # different responses, and an operator who reads "INVALID" as "we were
    # breached" when a chain written before v0.7.0 simply forked under
    # concurrent appends has been told the wrong thing. Name it.
    for prev_hash, seqs in forks:
        click.echo(
            f"FORK: rows {seqs} all claim predecessor {prev_hash}. Concurrent "
            "appends before v0.7.0 could produce this without tampering; from "
            "v0.7.0 the database refuses it.",
            err=True,
        )
    click.echo("VALID" if ok else "INVALID")
    raise SystemExit(0 if ok else 1)

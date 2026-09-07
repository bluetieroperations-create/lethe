"""`lethe-notary` — generate the notary key, and serve."""

import os
import sys

import click

from lethe.signing import Signer, key_id_for

from .payments import PaymentConfig, PaymentConfigError
from .store import WitnessLog


@click.group()
def cli() -> None:
    """Countersigning witness for Lethe deletion certificates."""


@cli.command()
@click.option("--out", required=True, type=click.Path(dir_okay=False))
def keygen(out: str) -> None:
    """Generate the notary signing key.

    This key IS the service. Everything a customer buys is a signature from it,
    and every receipt already issued becomes unverifiable if it is lost. Back it
    up offline before serving a single request.
    """
    if os.path.exists(out):
        raise SystemExit(f"lethe-notary: {out} exists; refusing to overwrite a key")
    signer = Signer.generate()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(signer.private_bytes())
    click.echo(f"wrote {out} (mode 0600)")
    click.echo(f"public_key: {signer.public_key_b64()}")
    click.echo(f"key_id:     {key_id_for(signer.public_key_b64())}")
    click.echo("\nPublish the public key. Back up the private key offline.")


@cli.command()
@click.option("--log", "log_path", envvar="LETHE_NOTARY_LOG",
              default="notary-witness.db", show_default=True)
@click.option("--out", required=True, type=click.Path(dir_okay=False))
@click.option("--overwrite", is_flag=True,
              help="Replace an existing file. Off by default: pointing a backup "
                   "at yesterday's file overwrites it with today's, and if "
                   "today's log is empty the good copy is gone.")
def backup(log_path: str, out: str, overwrite: bool) -> None:
    """Snapshot the witness log while the notary keeps serving.

    One SQLite file holding the only off-site copy of every customer's audit
    heads is a single point of failure. Run this on a schedule and ship the
    output somewhere else.
    """
    try:
        rows = WitnessLog(log_path).backup_to(out, overwrite=overwrite)
    except FileExistsError as e:
        raise SystemExit(f"lethe-notary: {e}") from None
    click.echo(f"wrote {out} ({rows} witnessed records)")


@cli.command()
@click.option("--key-file", envvar="LETHE_NOTARY_KEY_FILE", required=True)
@click.option("--log", "log_path", envvar="LETHE_NOTARY_LOG",
              default="notary-witness.db", show_default=True)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8402, show_default=True, type=int)
@click.option("--previous-key", "previous_keys", multiple=True,
              envvar="LETHE_NOTARY_PREVIOUS_KEYS",
              help="A retired notary public key (base64), repeatable. Published "
                   "at /.well-known/notary so receipts signed before a rotation "
                   "stay verifiable — without this, rotating the key silently "
                   "invalidates every receipt already sold.")
@click.option("--trust-proxy", is_flag=True, envvar="LETHE_NOTARY_TRUST_PROXY",
              help="Honour X-Forwarded-For for rate limiting. Only set this "
                   "behind a proxy you control: otherwise any caller can mint a "
                   "fresh identity per request and bypass the limiter.")
def serve(key_file: str, log_path: str, host: str, port: int,
          previous_keys: tuple[str, ...], trust_proxy: bool) -> None:
    """Serve the notary."""
    import uvicorn

    from .service import create_app

    try:
        config = PaymentConfig.from_env()
    except PaymentConfigError as e:
        raise SystemExit(f"lethe-notary: {e}") from None

    with open(key_file, "rb") as f:
        signer = Signer.from_private_bytes(f.read())

    app = create_app(signer=signer, log=WitnessLog(log_path), config=config,
                     previous_keys=tuple(previous_keys), trust_proxy=trust_proxy)
    try:
        # Contacts the facilitator once, so a network it cannot settle is a
        # startup failure rather than a 500 on the first customer.
        app.state.notary.gate.preflight()
    except PaymentConfigError as e:
        raise SystemExit(f"lethe-notary: {e}") from None
    mode = "FREE (not charging)" if config.free_mode else f"{config.price} on {config.network}"
    print(f"lethe-notary  key_id={key_id_for(signer.public_key_b64())}  {mode}",
          file=sys.stderr)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    cli()

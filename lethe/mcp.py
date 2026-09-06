"""MCP server exposing Lethe to autonomous agents (M2M surface).

Six tools; the only destructive one (lethe_forget) requires a single-use
confirm token minted by lethe_forget_preview, so a machine caller must have
seen the exact blast radius it confirms. See docs/m2m.md."""

import contextlib
import functools
import json
import os
import sys
import threading
import traceback
from collections import defaultdict
from dataclasses import dataclass

import psycopg

from .audit import AuditLog
from .cert_schema import verify_certificate_json
from .certificate import CERT_SCHEMA_VERSION, certificate_to_dict
from .connectors.pgvector import PgVectorConnector
from .core import Lethe, NamespaceNotAllowed, parse_allowed_namespaces
from .guard import ConfirmGuard, GuardError
from .hashing import hash_subject
from .ledger import Ledger
from .signing import Signer
from .version import __version__

# Bounds on agent-supplied certificates: reject cheaply BEFORE schema
# validation burns CPU (audit finding M-1: jsonschema does linear work
# per layer with no short-circuit).
MAX_CERT_BYTES = 262_144  # 256 KiB
MAX_CERT_LAYERS = 1000


@dataclass
class ServerContext:
    lethe: Lethe | None
    guard: ConfirmGuard | None
    trusted_public_key: str | None

    @property
    def verify_only(self) -> bool:
        return self.lethe is None

    # Handlers reach these only after their own verify_only guard. They exist
    # so that path is expressed in the type system rather than assumed: if a
    # guard is ever dropped, this raises a named error instead of an
    # AttributeError on None — and a type checker can see the narrowing.
    @property
    def store(self) -> Lethe:
        if self.lethe is None:
            raise RuntimeError("verify-only server has no Lethe configured")
        return self.lethe

    @property
    def confirm_guard(self) -> ConfirmGuard:
        if self.guard is None:
            raise RuntimeError("verify-only server has no confirm guard configured")
        return self.guard


def _ok(**kw) -> dict:
    return {"ok": True, **kw}


def _err(code: str, message: str, retriable: bool = False) -> dict:
    return {"ok": False, "error": {"code": code, "message": message, "retriable": retriable}}


def _verify_only_err() -> dict:
    # Fresh dict per call: a shared module-level envelope could be mutated
    # by one caller and poison every later response.
    return _err(
        "NO_LAYERS_CONFIGURED",
        "server is running verify-only (no database configured); "
        "set LETHE_DATABASE_URL, LETHE_SALT and LETHE_KEY_FILE for full mode",
    )


def _rollback(ctx) -> None:
    """A failed statement leaves the shared psycopg connection in an aborted
    transaction; without this every later call fails InFailedSqlTransaction
    until restart (found by live MCP verification, not the test suite)."""
    if isinstance(ctx, ServerContext) and ctx.lethe is not None:
        # Connection may be gone entirely; the next call reports INTERNAL.
        with contextlib.suppress(Exception):
            ctx.lethe.ledger.conn.rollback()


def _enveloped(fn):
    """Handlers must NEVER leak a raw exception to the transport: agents
    branch on error.code, and raw psycopg/connector text can leak DSNs.
    Expected errors return their own envelopes; anything else becomes
    INTERNAL with only the exception TYPE (details stay in server stderr)."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            _rollback(args[0] if args else None)
            return _err(
                "INTERNAL",
                f"unexpected {type(e).__name__} in {fn.__name__}",
                retriable=True,
            )

    return wrapper


@_enveloped
def h_status(ctx: ServerContext) -> dict:
    common = {
        "lethe_version": __version__,
        "cert_schema": CERT_SCHEMA_VERSION,
        "trusted_public_key_configured": ctx.trusted_public_key is not None,
    }
    if ctx.verify_only:
        return _ok(mode="verify-only", connectors=[], **common)
    allowed = ctx.store.allowed_namespaces
    return _ok(
        mode="full",
        connectors=sorted(ctx.store.connectors),
        audit_head=ctx.store.audit.head(),
        # Surfaced so an operator can see at a glance that this deployment can
        # be pointed at any table the database user can write.
        namespace_allowlist=(
            None if allowed is None
            else sorted(f"{s}:{n}" for s, ns in allowed.items() for n in ns)
        ),
        **common,
    )


@_enveloped
def h_tag(ctx: ServerContext, subject_id: str, store: str, namespace: str, record_id: str) -> dict:
    if ctx.verify_only:
        return _verify_only_err()
    try:
        ctx.store.tag(subject_id, store, namespace, record_id)
    except NamespaceNotAllowed as e:
        # A caller error with a named code, not an INTERNAL traceback: an agent
        # should be able to branch on this rather than parse a message.
        return _err(e.code, str(e))
    out = _ok(tagged={"store": store, "namespace": namespace, "record_id": record_id})
    if store not in ctx.store.connectors:
        out["warning"] = (
            f"store '{store}' has no configured connector; "
            "forget will report it handled:false until one is configured"
        )
    return out


def _layer_tuples(preview: dict) -> list[tuple[str, str, int]]:
    return [(lyr["store"], lyr["namespace"], lyr["count"]) for lyr in preview["layers"]]


@_enveloped
def h_forget_preview(ctx: ServerContext, subject_id: str) -> dict:
    if ctx.verify_only:
        return _verify_only_err()
    p = ctx.store.preview(subject_id)
    if not p["layers"]:
        return _err("SUBJECT_NOT_FOUND", "no tagged records for this subject")
    token = ctx.confirm_guard.mint(p["subject_hash"], _layer_tuples(p))
    return _ok(
        subject_hash=p["subject_hash"],
        layers=p["layers"],
        confirm_token=token,
        expires_in_seconds=ctx.confirm_guard.ttl_seconds,
    )


@_enveloped
def h_forget(ctx: ServerContext, subject_id: str, confirm_token: str) -> dict:
    if ctx.verify_only:
        return _verify_only_err()
    p = ctx.store.preview(subject_id)
    if not p["layers"]:
        return _err("SUBJECT_NOT_FOUND", "no tagged records for this subject")
    try:
        ctx.confirm_guard.check_and_consume(p["subject_hash"], _layer_tuples(p), confirm_token)
    except GuardError as e:
        return _err(e.code, e.message)
    try:
        cert = ctx.store.forget(subject_id)
    except Exception as e:
        # Connector/DB failure mid-loop: ledger is preserved by core for retry.
        # The token is already burned (irrevocable pre-commit): re-preview.
        # Only the exception TYPE goes to the caller: raw str(e) from
        # psycopg/connector errors can embed DSNs or hostnames.
        _rollback(ctx)
        return _err(
            "CONNECTOR_ERROR",
            f"forget failed mid-loop ({type(e).__name__}); "
            "ledger preserved — re-preview and confirm again",
            retriable=True,
        )
    return _ok(
        certificate=certificate_to_dict(cert),
        all_verified=cert.payload["all_verified"],
        records_deleted=cert.payload["records_deleted"],
    )


@_enveloped
def h_verify_subject(ctx: ServerContext, subject_id: str) -> dict:
    if ctx.verify_only:
        return _verify_only_err()
    subject_hash = hash_subject(subject_id, ctx.store.salt)
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in ctx.store.ledger.lookup(subject_hash):
        groups[(row.store, row.namespace)].append(row.record_id)
    if not groups:
        return _ok(
            subject_hash=subject_hash, layers=[],
            note="no tagged records remain for this subject (deleted or never tagged)",
        )
    layers = []
    for (store, namespace), ids in sorted(groups.items()):
        connector = ctx.store.connectors.get(store)
        if connector is None:
            layers.append(
                {"store": store, "namespace": namespace, "verified_absent": False, "handled": False}
            )
        else:
            layers.append(
                {
                    "store": store, "namespace": namespace,
                    "verified_absent": connector.verify(namespace, ids), "handled": True,
                }
            )
    return _ok(subject_hash=subject_hash, layers=layers)


def _cert_too_large(certificate) -> bool:
    if isinstance(certificate, dict):
        payload = certificate.get("payload")
        if isinstance(payload, dict):
            layers = payload.get("layers")
            if isinstance(layers, list) and len(layers) > MAX_CERT_LAYERS:
                return True
    try:
        return len(json.dumps(certificate, default=str)) > MAX_CERT_BYTES
    except (TypeError, ValueError, RecursionError):
        # Unserializable exotic input: let schema validation reject it
        # (jsonschema walks raw objects without json.dumps).
        return False


@_enveloped
def h_verify_certificate(
    ctx: ServerContext, certificate: dict, public_key: str | None = None
) -> dict:
    pin = public_key or ctx.trusted_public_key
    if not pin:
        return _err(
            "KEY_MISMATCH",
            "no trusted public key: pass public_key or set LETHE_TRUSTED_PUBLIC_KEY; "
            "an unpinned check proves self-consistency, not authenticity",
        )
    if _cert_too_large(certificate):
        return _err(
            "CERTIFICATE_TOO_LARGE",
            f"certificate exceeds bounds (max {MAX_CERT_BYTES} bytes / {MAX_CERT_LAYERS} layers)",
        )
    result = verify_certificate_json(certificate, trusted_public_key=pin)
    return _ok(valid=result["valid"], reasons=result["reasons"], detail=result["detail"])


class ConfigError(RuntimeError):
    pass


def _allowed_or_config_error(raw: str | None) -> dict[str, set[str]] | None:
    """Surface a malformed allowlist as a ConfigError, so main() reports it as
    a clean startup message like every other misconfiguration."""
    try:
        return parse_allowed_namespaces(raw)
    except ValueError as e:
        raise ConfigError(str(e)) from None



def build_context(environ=os.environ) -> ServerContext:
    """Full mode needs LETHE_DATABASE_URL (or DATABASE_URL) + LETHE_SALT +
    LETHE_KEY_FILE. With no database URL at all, the server starts in
    verify-only mode: zero infrastructure, only certificate verification."""
    db_url = environ.get("LETHE_DATABASE_URL") or environ.get("DATABASE_URL")
    trusted = environ.get("LETHE_TRUSTED_PUBLIC_KEY")
    if not db_url:
        return ServerContext(lethe=None, guard=None, trusted_public_key=trusted)
    missing = [
        name for name in ("LETHE_SALT", "LETHE_KEY_FILE") if not environ.get(name)
    ]
    if missing:
        raise ConfigError(
            f"LETHE_DATABASE_URL is set but {' and '.join(missing)} "
            f"{'is' if len(missing) == 1 else 'are'} not — full mode needs both "
            "(unset LETHE_DATABASE_URL to run verify-only)"
        )
    # Validated here, with the other config, so a malformed allowlist fails
    # before any connection is opened rather than after.
    allowed = _allowed_or_config_error(environ.get("LETHE_ALLOWED_NAMESPACES"))

    key_file = environ["LETHE_KEY_FILE"]
    try:
        with open(key_file, "rb") as f:
            signer = Signer.from_private_bytes(f.read())
    except (OSError, ValueError) as e:
        # Fail fast with the same clean diagnostic as every other misconfig
        # (main() only maps ConfigError to a SystemExit message): a missing or
        # malformed key file must not dump a raw traceback at startup. Only the
        # exception TYPE is surfaced — a raw OSError can echo the key path.
        raise ConfigError(
            f"LETHE_KEY_FILE ({key_file!r}) could not be loaded as an Ed25519 "
            f"private key ({type(e).__name__}); it must be 32 raw private-key bytes"
        ) from None
    conn = psycopg.connect(db_url)  # lives for the stdio server's lifetime
    lethe = Lethe(
        ledger=Ledger(conn),
        audit=AuditLog(conn),
        signer=signer,
        connectors={"pgvector": PgVectorConnector(conn)},
        salt=environ["LETHE_SALT"],
        allowed_namespaces=allowed,
    )
    # Self-initialize (idempotent CREATE IF NOT EXISTS): a fresh operator's
    # first tool call must work without a separate init-db step — without this
    # the very first query dies UndefinedTable (found by live MCP verification).
    lethe.ledger.init_schema()
    lethe.audit.init_schema()
    return ServerContext(lethe=lethe, guard=ConfirmGuard(), trusted_public_key=trusted)


def create_server(ctx: ServerContext):
    # CONCURRENCY INVARIANT: tool bodies run one at a time, and every tool
    # below must stay a plain sync def with no awaits.
    #
    # Under mcp 1.x this was free: FastMCP called sync tools inline on the
    # event-loop thread, so they serialized on their own. mcp 2.x dispatches
    # them through anyio.to_thread.run_sync instead, so concurrent calls run
    # on separate worker threads — the exact hazard this comment used to warn
    # about ("an SDK that moves sync tools to a threadpool"). Two things break
    # without serialization:
    #
    #   * the audit hash-chain. append() reads the tip, hashes it, and
    #     inserts; two threads read the same tip and the chain forks, which
    #     verify_chain() then reports as tampering. Demonstrated in
    #     test_mcp_concurrency.py.
    #   * the single shared psycopg connection, and with it the transaction
    #     boundary — one tool's commit lands another tool's half-finished work.
    #
    # So the lock is not a throughput trade-off: it restores the exact
    # execution model the handlers were written and tested against. Tools are
    # registered through _tool() below so a new one cannot silently opt out.
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations

    # mcp 2.x exposes these as snake_case fields (the camelCase wire names are
    # aliases). Constructing by alias still works, but reading back does not,
    # so use the field names both ways rather than mixing.
    read_only = ToolAnnotations(read_only_hint=True, destructive_hint=False)
    write = ToolAnnotations(read_only_hint=False, destructive_hint=False)
    destructive = ToolAnnotations(read_only_hint=False, destructive_hint=True)

    server = MCPServer(
        "lethe",
        instructions=(
            "Provable deletion for AI memory. Destructive flow is two-step: "
            "lethe_forget_preview returns the blast radius plus a confirm_token; "
            "lethe_forget(subject_id, confirm_token) executes and returns a signed "
            "certificate. Verify any certificate with lethe_verify_certificate."
        ),
    )

    # One lock for the whole server, held for the duration of a tool body.
    # threading.Lock (not asyncio.Lock): under mcp 2.x the bodies run on
    # anyio worker threads, so the contention is between OS threads.
    call_lock = threading.Lock()

    def _tool(annotations: ToolAnnotations):
        """Register a tool, serialized. functools.wraps keeps __doc__ and
        __wrapped__, so the SDK still derives the description and the argument
        schema from the original function."""
        def decorate(fn):
            @functools.wraps(fn)
            def serialized(*args, **kwargs):
                with call_lock:
                    return fn(*args, **kwargs)

            server.tool(annotations=annotations)(serialized)
            return fn

        return decorate

    @_tool(read_only)
    def lethe_status() -> dict:
        """Server mode (full or verify-only), connectors, audit head, versions."""
        return h_status(ctx)

    @_tool(write)
    def lethe_tag(subject_id: str, store: str, namespace: str, record_id: str) -> dict:
        """Tag a stored record as belonging to a data subject, so a later
        forget can find and provably delete it."""
        return h_tag(ctx, subject_id, store, namespace, record_id)

    @_tool(read_only)
    def lethe_forget_preview(subject_id: str) -> dict:
        """Dry run: per-layer record counts that a forget WOULD delete, plus a
        single-use confirm_token (expires in ~10 minutes). Deletes nothing."""
        return h_forget_preview(ctx, subject_id)

    @_tool(destructive)
    def lethe_forget(subject_id: str, confirm_token: str) -> dict:
        """DESTRUCTIVE: permanently delete the subject across all tagged layers,
        verify absence, and return the signed deletion certificate. Requires the
        confirm_token from lethe_forget_preview for this same subject."""
        return h_forget(ctx, subject_id, confirm_token)

    @_tool(read_only)
    def lethe_verify_subject(subject_id: str) -> dict:
        """Post-hoc spot check: re-verify (without deleting) whether the
        subject's tagged records are absent from each layer."""
        return h_verify_subject(ctx, subject_id)

    @_tool(read_only)
    def lethe_verify_certificate(certificate: dict, public_key: str | None = None) -> dict:
        """Verify a Lethe deletion certificate: JSON-Schema shape plus key-pinned
        Ed25519 check. public_key (base64) overrides LETHE_TRUSTED_PUBLIC_KEY."""
        return h_verify_certificate(ctx, certificate, public_key)

    return server


def main() -> None:
    try:
        ctx = build_context()
    except ConfigError as e:
        raise SystemExit(f"lethe-mcp: {e}") from None
    create_server(ctx).run()  # stdio transport

"""MCP server exposing Lethe to autonomous agents (M2M surface).

Six tools; the only destructive one (lethe_forget) requires a single-use
confirm token minted by lethe_forget_preview, so a machine caller must have
seen the exact blast radius it confirms. See docs/m2m.md."""

import json
from collections import defaultdict
from dataclasses import dataclass

from .cert_schema import verify_certificate_json
from .certificate import CERT_SCHEMA_VERSION, certificate_to_dict
from .core import Lethe
from .guard import ConfirmGuard, GuardError
from .hashing import hash_subject
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


def _ok(**kw) -> dict:
    return {"ok": True, **kw}


def _err(code: str, message: str, retriable: bool = False) -> dict:
    return {"ok": False, "error": {"code": code, "message": message, "retriable": retriable}}


_VERIFY_ONLY = _err(
    "NO_LAYERS_CONFIGURED",
    "server is running verify-only (no database configured); "
    "set LETHE_DATABASE_URL, LETHE_SALT and LETHE_KEY_FILE for full mode",
)


def h_status(ctx: ServerContext) -> dict:
    common = {
        "lethe_version": __version__,
        "cert_schema": CERT_SCHEMA_VERSION,
        "trusted_public_key_configured": ctx.trusted_public_key is not None,
    }
    if ctx.verify_only:
        return _ok(mode="verify-only", connectors=[], **common)
    return _ok(
        mode="full",
        connectors=sorted(ctx.lethe.connectors),
        audit_head=ctx.lethe.audit.head(),
        **common,
    )


def h_tag(ctx: ServerContext, subject_id: str, store: str, namespace: str, record_id: str) -> dict:
    if ctx.verify_only:
        return _VERIFY_ONLY
    ctx.lethe.tag(subject_id, store, namespace, record_id)
    return _ok(tagged={"store": store, "namespace": namespace, "record_id": record_id})


def _layer_tuples(preview: dict) -> list[tuple[str, str, int]]:
    return [(l["store"], l["namespace"], l["count"]) for l in preview["layers"]]


def h_forget_preview(ctx: ServerContext, subject_id: str) -> dict:
    if ctx.verify_only:
        return _VERIFY_ONLY
    p = ctx.lethe.preview(subject_id)
    if not p["layers"]:
        return _err("SUBJECT_NOT_FOUND", "no tagged records for this subject")
    token = ctx.guard.mint(p["subject_hash"], _layer_tuples(p))
    return _ok(
        subject_hash=p["subject_hash"],
        layers=p["layers"],
        confirm_token=token,
        expires_in_seconds=ctx.guard.ttl_seconds,
    )


def h_forget(ctx: ServerContext, subject_id: str, confirm_token: str) -> dict:
    if ctx.verify_only:
        return _VERIFY_ONLY
    p = ctx.lethe.preview(subject_id)
    if not p["layers"]:
        return _err("SUBJECT_NOT_FOUND", "no tagged records for this subject")
    try:
        ctx.guard.check_and_consume(p["subject_hash"], _layer_tuples(p), confirm_token)
    except GuardError as e:
        return _err(e.code, e.message)
    try:
        cert = ctx.lethe.forget(subject_id)
    except Exception as e:
        # Connector/DB failure mid-loop: ledger is preserved by core for retry.
        # The token is already burned (irrevocable pre-commit): re-preview.
        return _err("CONNECTOR_ERROR", f"forget failed: {e}", retriable=True)
    return _ok(
        certificate=certificate_to_dict(cert),
        all_verified=cert.payload["all_verified"],
        records_deleted=cert.payload["records_deleted"],
    )


def h_verify_subject(ctx: ServerContext, subject_id: str) -> dict:
    if ctx.verify_only:
        return _VERIFY_ONLY
    subject_hash = hash_subject(subject_id, ctx.lethe.salt)
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in ctx.lethe.ledger.lookup(subject_hash):
        groups[(row.store, row.namespace)].append(row.record_id)
    if not groups:
        return _ok(
            subject_hash=subject_hash, layers=[],
            note="no tagged records remain for this subject (deleted or never tagged)",
        )
    layers = []
    for (store, namespace), ids in sorted(groups.items()):
        connector = ctx.lethe.connectors.get(store)
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


def h_verify_certificate(ctx: ServerContext, certificate: dict, public_key: str | None = None) -> dict:
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

"""Namespace allowlist (issue #8).

lethe_tag took a namespace straight from the caller, so an agent could point
a deletion at any table the database user could write. The control is enforced
in Lethe.tag rather than at the MCP boundary, because the ledger is what
forget() deletes from — guarding one entry point would leave the CLI, the
library, and reconcile()'s remediation path able to write entries forget()
would then honour. These tests pin that placement, not just the behaviour.
"""

import os

import pytest

from lethe.audit import AuditLog
from lethe.connectors.pgvector import PgVectorConnector
from lethe.core import Lethe, NamespaceNotAllowed, parse_allowed_namespaces
from lethe.ledger import Ledger
from lethe.signing import Signer


@pytest.fixture
def tables(conn):
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS docs, billing CASCADE")
        cur.execute("CREATE TABLE docs (id TEXT PRIMARY KEY, user_id TEXT)")
        cur.execute("CREATE TABLE billing (id TEXT PRIMARY KEY, amount INT)")
        cur.execute("INSERT INTO docs VALUES ('d1','alice')")
        cur.execute("INSERT INTO billing VALUES ('inv-1', 5000)")
    conn.commit()
    return conn


def _lethe(conn, allow):
    ledger, audit = Ledger(conn), AuditLog(conn)
    ledger.init_schema()
    audit.init_schema()
    return Lethe(
        ledger=ledger, audit=audit, signer=Signer.generate(),
        connectors={"pgvector": PgVectorConnector(conn)}, salt="s",
        allowed_namespaces=allow,
    )


# --- parsing ---


def test_unset_means_unrestricted():
    """None, not an empty allowlist: upgrading must not silently start
    rejecting a deployment's real traffic."""
    assert parse_allowed_namespaces(None) is None


def test_parses_pairs_and_tolerates_whitespace():
    assert parse_allowed_namespaces(" pgvector:docs , pinecone:mem ") == {
        "pgvector": {"docs"},
        "pinecone": {"mem"},
    }


@pytest.mark.parametrize("raw", ["", "   ", ",,"])
def test_set_but_empty_is_a_misconfiguration(raw):
    """Not a way to say 'allow nothing'. Running unrestricted because a
    variable expanded to empty is the exact failure this control prevents."""
    with pytest.raises(ValueError, match="set but empty"):
        parse_allowed_namespaces(raw)


@pytest.mark.parametrize("raw", ["pgvector", "pgvector:", ":docs"])
def test_malformed_entries_are_rejected(raw):
    with pytest.raises(ValueError, match="must be STORE:NAMESPACE"):
        parse_allowed_namespaces(raw)


# --- enforcement ---


def test_tag_outside_the_allowlist_is_refused(tables):
    lethe = _lethe(tables, {"pgvector": {"docs"}})
    with pytest.raises(NamespaceNotAllowed, match="billing"):
        lethe.tag("attacker-chosen", "pgvector", "billing", "inv-1")
    # Nothing reached the ledger, so forget() has nothing to honour.
    assert lethe.ledger.lookup(lethe._subject_hash("attacker-chosen")) == []


def test_tag_inside_the_allowlist_still_works(tables):
    lethe = _lethe(tables, {"pgvector": {"docs"}})
    lethe.tag("alice", "pgvector", "docs", "d1")
    assert len(lethe.ledger.lookup(lethe._subject_hash("alice"))) == 1


def test_a_store_absent_from_the_allowlist_is_refused(tables):
    """Allowing pgvector:docs must not implicitly allow pinecone:docs."""
    lethe = _lethe(tables, {"pgvector": {"docs"}})
    with pytest.raises(NamespaceNotAllowed):
        lethe.tag("alice", "pinecone", "docs", "d1")


def test_default_deployment_is_unrestricted(tables):
    """Backward compatibility: the pre-existing behaviour is the default."""
    lethe = _lethe(tables, None)
    lethe.tag("x", "pgvector", "billing", "inv-1")
    assert len(lethe.ledger.lookup(lethe._subject_hash("x"))) == 1


# --- the indirect ledger-writing path ---


def test_reconcile_remediation_is_refused_before_it_tags_anything(tables):
    """reconcile(tag_untracked=True) writes via tag(). It must fail up front,
    not part-way through, or it leaves a partial remediation the caller did
    not ask for and cannot easily see."""
    lethe = _lethe(tables, {"pgvector": {"docs"}})
    with pytest.raises(NamespaceNotAllowed):
        lethe.reconcile(
            "alice",
            targets=[("pgvector", "docs", "user_id"), ("pgvector", "billing", "id")],
            tag_untracked=True,
        )
    # The allowed target must not have been partially tagged either.
    assert lethe.ledger.lookup(lethe._subject_hash("alice")) == []


def test_reconcile_detection_only_is_not_blocked(tables):
    """Scanning is read-only and cannot delete anything, so detection stays
    available even for a namespace this deployment may not tag."""
    lethe = _lethe(tables, {"pgvector": {"docs"}})
    result = lethe.reconcile(
        "alice", targets=[("pgvector", "docs", "user_id")], tag_untracked=False
    )
    assert result["layers"][0]["scanned"] is True


# --- MCP surface: what a connected agent actually sees ---


def _ctx(conn, allow):
    from lethe.guard import ConfirmGuard
    from lethe.mcp import ServerContext

    return ServerContext(
        lethe=_lethe(conn, allow), guard=ConfirmGuard(), trusted_public_key=None
    )


def test_mcp_tag_returns_a_named_error_not_a_traceback(tables):
    """An agent must be able to branch on a code rather than parse a message,
    and a refused namespace is a caller error, not an INTERNAL fault."""
    from lethe.mcp import h_tag

    r = h_tag(
        _ctx(tables, {"pgvector": {"docs"}}),
        subject_id="attacker-chosen", store="pgvector",
        namespace="billing", record_id="inv-1",
    )
    assert r["ok"] is False
    assert r["error"]["code"] == "NAMESPACE_NOT_ALLOWED"
    assert r["error"]["retriable"] is False
    assert "billing" in r["error"]["message"]


def test_mcp_status_shows_when_a_deployment_is_unrestricted(tables):
    """An operator has to be able to see that this server can be pointed at
    any table the database user can write."""
    from lethe.mcp import h_status

    assert h_status(_ctx(tables, None))["namespace_allowlist"] is None
    assert h_status(_ctx(tables, {"pgvector": {"docs"}}))["namespace_allowlist"] == [
        "pgvector:docs"
    ]


def test_malformed_allowlist_env_fails_server_startup(tmp_path, monkeypatch):
    """A misconfigured allowlist must stop the server, not start it
    unrestricted — and must do so BEFORE any connection is opened.

    The ordering is asserted directly rather than inferred: psycopg.connect is
    replaced with a tripwire, so a regression that moved the parse after the
    connect fails loudly here instead of depending on a DSN failing to resolve
    (which would surface as a slow timeout, or not at all).
    """
    import psycopg

    from lethe.mcp import ConfigError, build_context
    from lethe.signing import Signer

    def _tripwire(*args, **kwargs):
        raise AssertionError(
            "psycopg.connect was called before the allowlist was validated"
        )

    monkeypatch.setattr(psycopg, "connect", _tripwire)

    key = tmp_path / "k.bin"
    key.write_bytes(Signer.generate().private_bytes())
    env = {
        "LETHE_DATABASE_URL": "postgresql://unused/db",
        "LETHE_SALT": "s",
        "LETHE_KEY_FILE": str(key),
        "LETHE_ALLOWED_NAMESPACES": "not-a-pair",
    }
    with pytest.raises(ConfigError, match="STORE:NAMESPACE"):
        build_context(environ=env)


# --- the allowlist must bound DELETION, not merely tagging ---


def test_forget_refuses_a_ledger_entry_outside_the_allowlist(tables):
    """A ledger row can predate the allowlist, or be written by anything with
    SQL access to lethe_provenance. forget() reads the ledger, so checking only
    tag() would leave the delete path unbounded — which is the path that
    actually matters."""
    unrestricted = _lethe(tables, None)
    unrestricted.tag("attacker", "pgvector", "billing", "inv-1")

    restricted = _lethe(tables, {"pgvector": {"docs"}})
    cert = restricted.forget("attacker")

    assert cert.payload["records_deleted"] == 0
    # Must not certify erasure for a layer it deliberately refused to touch.
    assert cert.payload["all_verified"] is False
    layer = cert.payload["layers"][0]
    assert layer["handled"] is False
    assert layer["erased"] is False
    assert "allowlist" in layer["verify_method"]
    # Ledger preserved so the operator can fix config and retry.
    assert len(restricted.ledger.lookup(restricted._subject_hash("attacker"))) == 1

    with tables.cursor() as cur:
        cur.execute("SELECT id FROM billing")
        assert [r[0] for r in cur.fetchall()] == ["inv-1"]


def test_forget_still_sweeps_the_allowed_layers_alongside_a_refused_one(tables):
    """Mixed subject: delete what this deployment may, refuse the rest, and say
    so — the same shape as a store with no configured connector."""
    unrestricted = _lethe(tables, None)
    unrestricted.tag("alice", "pgvector", "docs", "d1")
    unrestricted.tag("alice", "pgvector", "billing", "inv-1")

    restricted = _lethe(tables, {"pgvector": {"docs"}})
    cert = restricted.forget("alice")

    by_ns = {lyr["namespace"]: lyr for lyr in cert.payload["layers"]}
    assert by_ns["docs"]["handled"] is True
    assert by_ns["docs"]["deleted_count"] == 1
    assert by_ns["billing"]["handled"] is False
    assert cert.payload["all_verified"] is False

    with tables.cursor() as cur:
        cur.execute("SELECT id FROM docs")
        assert cur.fetchall() == []          # allowed layer swept
        cur.execute("SELECT id FROM billing")
        assert [r[0] for r in cur.fetchall()] == ["inv-1"]   # refused layer intact


def test_unrestricted_forget_is_unchanged(tables):
    """Backward compatibility on the delete path too."""
    lethe = _lethe(tables, None)
    lethe.tag("x", "pgvector", "billing", "inv-1")
    cert = lethe.forget("x")
    assert cert.payload["all_verified"] is True
    assert cert.payload["records_deleted"] == 1


# --- fail-closed on near-miss namespaces ---


@pytest.mark.parametrize(
    "namespace",
    [" docs", "docs ", " docs ", "DOCS", "Docs", "docs\n", "docs​", "doсs", ""],
)
def test_near_miss_namespaces_are_refused(tables, namespace):
    """Exact matching is correct here: psycopg quotes identifiers byte-exactly,
    so Python equality and Postgres quoted-identifier equality coincide.

    This guards a concrete future bypass. If someone "fixes" the usability
    complaint by adding .strip() inside _namespace_allowed, then tagging
    " docs " would be accepted while tag() still stores the unstripped string —
    and sql.Identifier(" docs ") targets a different table than docs.
    """
    lethe = _lethe(tables, {"pgvector": {"docs"}})
    with pytest.raises(NamespaceNotAllowed):
        lethe.tag("alice", "pgvector", namespace, "d1")


def test_preview_marks_a_layer_that_forget_will_refuse(tables):
    """The confirm token is minted over what preview reports, so a preview that
    hid the refusal would misstate the blast radius the caller confirms."""
    unrestricted = _lethe(tables, None)
    unrestricted.tag("alice", "pgvector", "docs", "d1")
    unrestricted.tag("alice", "pgvector", "billing", "inv-1")

    layers = _lethe(tables, {"pgvector": {"docs"}}).preview("alice")["layers"]
    by_ns = {lyr["namespace"]: lyr for lyr in layers}
    assert by_ns["docs"]["allowed"] is True
    assert by_ns["billing"]["allowed"] is False


def test_an_out_of_policy_row_blocks_certification_until_it_is_cleared(tables):
    """The residual this control creates, pinned so it cannot change silently:
    one poisoned row means the subject never certifies, and the ledger never
    purges, until an operator clears it."""
    unrestricted = _lethe(tables, None)
    unrestricted.tag("alice", "pgvector", "docs", "d1")
    unrestricted.tag("alice", "pgvector", "billing", "inv-1")

    lethe = _lethe(tables, {"pgvector": {"docs"}})
    assert lethe.forget("alice").payload["all_verified"] is False
    # Still stuck on a second attempt — not a transient.
    assert lethe.forget("alice").payload["all_verified"] is False

    # ledger-scope's remediation is the way out.
    assert lethe.ledger.purge_namespace("pgvector", "billing") == 1
    # A real record to erase: d1 was already swept by the first forget, and a
    # run that deletes nothing cannot certify an erasure either.
    with tables.cursor() as cur:
        cur.execute("INSERT INTO docs VALUES ('d2','alice')")
    tables.commit()
    lethe.tag("alice", "pgvector", "docs", "d2")
    assert lethe.forget("alice").payload["all_verified"] is True


# --- ledger-scope: seeing and clearing what predates the allowlist ---


def test_ledger_namespaces_reports_what_is_tagged(tables):
    lethe = _lethe(tables, None)
    lethe.tag("alice", "pgvector", "docs", "d1")
    lethe.tag("attacker", "pgvector", "billing", "inv-1")
    assert lethe.ledger.namespaces() == [
        ("pgvector", "billing", 1),
        ("pgvector", "docs", 1),
    ]


def test_purge_namespace_clears_only_that_namespace(tables):
    lethe = _lethe(tables, None)
    lethe.tag("alice", "pgvector", "docs", "d1")
    lethe.tag("attacker", "pgvector", "billing", "inv-1")
    assert lethe.ledger.purge_namespace("pgvector", "billing") == 1
    assert lethe.ledger.namespaces() == [("pgvector", "docs", 1)]
    # Purging the ledger record must not touch the store itself.
    with tables.cursor() as cur:
        cur.execute("SELECT id FROM billing")
        assert [r[0] for r in cur.fetchall()] == ["inv-1"]


# --- the CLI delete path ---


def test_cli_forget_honours_the_allowlist(tables, tmp_path, monkeypatch):
    """`lethe forget` is the command that deletes, and is what an operator
    reaches for while cleaning up after an incident."""
    from click.testing import CliRunner

    from lethe.cli import cli

    _lethe(tables, None).tag("attacker", "pgvector", "billing", "inv-1")

    key = tmp_path / "k.bin"
    key.write_bytes(Signer.generate().private_bytes())
    monkeypatch.setenv("LETHE_ALLOWED_NAMESPACES", "pgvector:documents")

    # NOT tables.info.dsn: psycopg strips the password from it, so the CLI
    # cannot authenticate anywhere the database needs one. That passes on a
    # trust-auth local Postgres and fails in CI — use the configured DSN, as
    # test_cli.py does.
    dsn = os.environ["LETHE_TEST_DATABASE_URL"]
    result = CliRunner().invoke(
        cli,
        ["forget", "attacker", "--database-url", dsn, "--salt", "s",
         "--key-file", str(key)],
    )
    assert result.exit_code == 0, result.output
    assert '"all_verified": false' in result.output.lower()

    with tables.cursor() as cur:
        cur.execute("SELECT id FROM billing")
        assert [r[0] for r in cur.fetchall()] == ["inv-1"]

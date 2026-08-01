"""Packaging + final-schema assertions for the canonical aweb migration set.

The current line is a reset-only rebaseline: aapm.6 and the aapq
team-and-contacts correction are consolidated into `001_initial.sql`.
The single baseline is intentional for the pre-distribution hosted reset;
normal future product migrations must be added as ordered forward files.
"""
from importlib.resources import files
from pathlib import Path
import shutil
import subprocess
import tomllib
import zipfile

import pytest
from pgdbm.errors import QueryError
from packaging.requirements import Requirement
from packaging.version import Version


AWEB_MIGRATIONS = files("aweb") / "migrations" / "aweb"
AWID_ENCRYPTION_KEY_API_VERSION = Version("0.5.9")
MCP_FASTMCP_API_VERSION = Version("1.26.0")
MCP_INCOMPATIBLE_API_VERSION = Version("2.0.0")


def test_defaults_migrations_and_reserved_app_ids_are_packaged():
    package_root = files("aweb")

    assert (package_root / "defaults" / "team_instructions.md").is_file()
    assert (package_root / "defaults" / "roles" / "backend.md").is_file()
    assert (AWEB_MIGRATIONS / "001_initial.sql").is_file()

    packaged_reserved = package_root / "data" / "reserved-app-ids-v1.json"
    source_reserved = Path(__file__).resolve().parents[2] / "test-vectors" / "reserved-app-ids-v1.json"
    assert packaged_reserved.is_file()
    assert packaged_reserved.read_text() == source_reserved.read_text()


def test_reserved_app_ids_artifact_ships_in_built_wheel(tmp_path):
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build the wheel for package-data inspection")

    server_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(tmp_path)],
        cwd=server_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wheels = list(tmp_path.glob("aweb-*.whl"))
    assert wheels
    with zipfile.ZipFile(wheels[0]) as wheel:
        assert "aweb/data/reserved-app-ids-v1.json" in wheel.namelist()


def test_awid_service_floor_covers_encryption_key_api():
    """aapv requires awid.e2ee_keys, introduced with awid-service 0.5.9."""
    pyproject = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    dependencies = pyproject["project"]["dependencies"]
    parsed_requirements = [Requirement(dep) for dep in dependencies]
    awid_req = next((req for req in parsed_requirements if req.name == "awid-service"), None)
    assert awid_req is not None
    lower_bounds = [
        Version(specifier.version)
        for specifier in awid_req.specifier
        if specifier.operator in {">=", "==", "~="}
    ]
    assert lower_bounds
    assert max(lower_bounds) >= AWID_ENCRYPTION_KEY_API_VERSION


def test_mcp_dependency_excludes_api_incompatible_v2():
    pyproject = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    dependencies = pyproject["project"]["dependencies"]
    mcp_req = next(Requirement(dep) for dep in dependencies if Requirement(dep).name == "mcp")

    assert MCP_FASTMCP_API_VERSION in mcp_req.specifier
    assert MCP_INCOMPATIBLE_API_VERSION not in mcp_req.specifier


def test_canonical_chain_starts_with_reset_baseline_then_forward_migrations():
    """Reset-only rebaseline remains 001; new product schema changes are
    ordered forward migrations instead of edits to the historical baseline."""
    sql_files = sorted(p.name for p in AWEB_MIGRATIONS.iterdir() if p.name.endswith(".sql"))
    assert sql_files == [
        "001_initial.sql",
        "002_agent_encryption_keys.sql",
        "003_messages_encrypted_v2.sql",
        "004_chat_messages_encrypted_v2.sql",
        "005_messages_encrypted_v2_shape_legacy_fields.sql",
        "006_chat_participants_left_at.sql",
        "007_agent_encryption_key_custody.sql",
        "008_app_registry_grants.sql",
        "009_app_events.sql",
        "010_session_admission_leases.sql",
        "010a_chat_message_reads_orphan_guard.sql",
        "011_chat_message_reads.sql",
        "012_chat_message_reads_orphan_backfill.sql",
        "013_lifecycle_side_effect_outbox.sql",
    ]


def test_agents_table_declares_team_and_contacts_inbound_mode_inline():
    """aapq contract: global restricted delivery is team-and-contacts,
    not exact contacts-only."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    assert "agents_inbound_mode_valid" in migration
    assert "'open'" in migration
    assert "'team_and_contacts'" in migration
    assert "contacts_only" not in migration
    assert "contacts_or_teammates" not in migration
    assert "team_only" not in migration


@pytest.mark.asyncio
async def test_agents_table_rejects_legacy_contacts_only_after_rebaseline(aweb_cloud_db):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'Backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, inbound_mode)
        VALUES ('backend:acme.com', 'did:key:alice', 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'team_and_contacts')
        """
    )

    with pytest.raises(QueryError):
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.agents}} SET inbound_mode = 'contacts_only' WHERE alias = 'alice'"
        )


def test_agents_table_omits_legacy_messaging_policy_column():
    """messaging_policy was added in 001 and dropped in 009; the
    consolidated baseline omits it entirely (no create-then-drop)."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    assert "messaging_policy" not in migration


def test_agents_table_declares_identity_scope_directly_without_lifetime():
    """lifetime was 001's column and 010 dropped it after mapping into
    identity_scope; the consolidated baseline declares identity_scope
    inline with its NOT NULL default + CHECK and omits lifetime."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    assert "identity_scope" in migration
    assert "agents_identity_scope_valid" in migration
    assert "'global'" in migration
    assert "'local'" in migration
    # No historical lifetime column or its persistent/ephemeral CHECK.
    assert "lifetime" not in migration
    assert "'persistent'" not in migration
    assert "'ephemeral'" not in migration


def test_contacts_table_declares_handle_state_columns_inline():
    """004 added reference_type / status / handle_namespace /
    target_agent_name + CHECK constraints to contacts; the consolidated
    baseline declares them inline in the CREATE TABLE."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    assert "reference_type" in migration
    assert "handle_namespace" in migration
    assert "target_agent_name" in migration
    assert "contacts_reference_type_valid" in migration
    assert "contacts_reference_shape_valid" in migration


def test_conversations_table_includes_constraints_and_trigger_inline():
    """002 + 003 added the conversations table + constraints + the
    trg_conversations_updated_at trigger; consolidated baseline declares
    them all inline."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    assert "{{tables.conversations}}" in migration
    assert "conversations_created_by_did_not_blank" in migration
    assert "conversation_participants_alias_not_blank" in migration
    assert "conversation_participants_reachable" in migration
    assert "set_conversation_updated_at" in migration
    assert "trg_conversations_updated_at" in migration


def test_participants_tables_include_federation_columns_inline():
    """006 + 007 added delivery_origin + current_did_key to chat and
    conversation participant tables; consolidated baseline declares
    them inline."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    # Both tables get both columns.
    assert migration.count("delivery_origin") >= 4  # column + index in both tables
    assert migration.count("current_did_key") >= 2  # at least one per table


def test_federated_message_deliveries_table_is_inline():
    """005's federated_message_deliveries table is declared inline."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    assert "{{tables.federated_message_deliveries}}" in migration
    assert "sender_did_aw" in migration
    assert "target_did_aw" in migration
    assert "delivery_origin" in migration


def test_agents_table_declares_agent_type_inline():
    """011 added agent_type during the historical chain; the reset
    baseline declares it inline."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    assert "agent_type" in migration

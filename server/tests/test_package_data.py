"""Packaging + final-schema assertions for the canonical aweb migration set.

aapm.6 consolidated the historical chain into `001_initial.sql`. Later
normal product migrations must remain additive ordered files. Tests below
assert both the consolidated baseline and the aapq inbound-mode migration
ship in the package."""
from importlib.resources import files
from pathlib import Path

import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.errors import QueryError


AWEB_MIGRATIONS = files("aweb") / "migrations" / "aweb"


def test_defaults_and_migrations_are_packaged():
    package_root = files("aweb")

    assert (package_root / "defaults" / "team_instructions.md").is_file()
    assert (package_root / "defaults" / "roles" / "backend.md").is_file()
    assert (AWEB_MIGRATIONS / "001_initial.sql").is_file()
    assert (AWEB_MIGRATIONS / "001_post_initial_team_and_contacts_inbound_mode_transition.sql").is_file()
    assert (AWEB_MIGRATIONS / "002_team_and_contacts_inbound_mode.sql").is_file()


def test_canonical_chain_has_consolidated_baseline_plus_forward_migrations():
    """aapm.6 produced the clean baseline. aapq is a normal forward
    migration because production has already applied the baseline."""
    sql_files = sorted(p.name for p in AWEB_MIGRATIONS.iterdir() if p.name.endswith(".sql"))
    assert sql_files == [
        "001_initial.sql",
        "001_post_initial_team_and_contacts_inbound_mode_transition.sql",
        "002_team_and_contacts_inbound_mode.sql",
    ]


def test_agents_table_migrates_to_team_and_contacts_inbound_mode():
    """aapq contract: global restricted delivery is team-and-contacts,
    not exact contacts-only."""
    baseline = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    transition = (AWEB_MIGRATIONS / "001_post_initial_team_and_contacts_inbound_mode_transition.sql").read_text()
    migration = (AWEB_MIGRATIONS / "002_team_and_contacts_inbound_mode.sql").read_text()
    assert "agents_inbound_mode_valid" in baseline
    assert "agents_inbound_mode_valid" in transition
    assert "agents_inbound_mode_valid" in migration
    assert "contacts_only" in transition
    assert "team_and_contacts" in transition
    assert "SET inbound_mode = 'team_and_contacts'" in migration
    assert "WHERE inbound_mode = 'contacts_only'" in migration
    assert "'open'" in migration
    assert "'team_and_contacts'" in migration
    assert "contacts_or_teammates" not in migration
    assert "team_only" not in migration


@pytest.mark.asyncio
async def test_team_and_contacts_migration_converts_existing_contacts_only_rows(shared_test_pool, tmp_path):
    """Prod had contacts_only rows under the 001 CHECK. The forward chain
    must widen the old CHECK before 002 rewrites those rows, then finish with
    the final open/team_and_contacts-only storage constraint.
    """

    temp_manager = AsyncDatabaseManager(pool=shared_test_pool, schema=None)
    await temp_manager.execute("CREATE SCHEMA IF NOT EXISTS aweb")
    aweb_db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")

    initial_dir = tmp_path / "initial"
    initial_dir.mkdir()
    initial_sql = Path(str(AWEB_MIGRATIONS / "001_initial.sql"))
    (initial_dir / "001_initial.sql").write_text(initial_sql.read_text())

    initial_migrations = AsyncMigrationManager(
        aweb_db,
        migrations_path=str(initial_dir),
        module_name="aweb-aweb",
        migrations_table="schema_migrations",
    )
    await initial_migrations.apply_pending_migrations()

    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'Backend', 'did:key:team')
        """
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, inbound_mode)
        VALUES ('backend:acme.com', 'did:key:alice', 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'contacts_only')
        """
    )

    full_migrations = AsyncMigrationManager(
        aweb_db,
        migrations_path=str(Path(str(AWEB_MIGRATIONS))),
        module_name="aweb-aweb",
        migrations_table="schema_migrations",
    )
    await full_migrations.apply_pending_migrations()

    inbound_mode = await aweb_db.fetch_val(
        "SELECT inbound_mode FROM {{tables.agents}} WHERE alias = 'alice'"
    )
    assert inbound_mode == "team_and_contacts"

    rows = await aweb_db.fetch_all(
        """
        SELECT filename, module_name
        FROM {{tables.schema_migrations}}
        WHERE module_name = 'aweb-aweb'
        ORDER BY filename
        """
    )
    assert ("001_post_initial_team_and_contacts_inbound_mode_transition.sql", "aweb-aweb") in [
        (row["filename"], row["module_name"]) for row in rows
    ]
    assert ("002_team_and_contacts_inbound_mode.sql", "aweb-aweb") in [
        (row["filename"], row["module_name"]) for row in rows
    ]

    with pytest.raises(QueryError):
        await aweb_db.execute(
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

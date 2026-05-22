"""Packaging + final-schema assertions for the canonical aweb migration set.

aapm.6: the canonical chain was consolidated into a single
`001_initial.sql` (final clean baseline). Tests below assert the
package ships exactly that file and that the file declares the final
shape directly (no historical messaging_policy / lifetime / two-value
inbound_mode replay)."""
from importlib.resources import files


AWEB_MIGRATIONS = files("aweb") / "migrations" / "aweb"


def test_defaults_and_migrations_are_packaged():
    package_root = files("aweb")

    assert (package_root / "defaults" / "team_instructions.md").is_file()
    assert (package_root / "defaults" / "roles" / "backend.md").is_file()
    assert (AWEB_MIGRATIONS / "001_initial.sql").is_file()


def test_canonical_chain_is_a_single_consolidated_baseline():
    """aapm.6: the rebuild path doesn't need historical replay, so the
    canonical aweb chain ships as exactly one file."""
    sql_files = sorted(p.name for p in AWEB_MIGRATIONS.iterdir() if p.name.endswith(".sql"))
    assert sql_files == ["001_initial.sql"], (
        f"Canonical aweb migration set must be a single consolidated "
        f"001_initial.sql baseline (aapm.6); found {sql_files}"
    )


def test_agents_table_declares_final_inbound_mode_shape_directly():
    """The three-value canonical inbound_mode CHECK is declared inline
    in the agents CREATE TABLE — no separate ADD/DROP CONSTRAINT
    migration history (was 008 + 011 in the prior chain)."""
    migration = (AWEB_MIGRATIONS / "001_initial.sql").read_text()
    assert "agents_inbound_mode_valid" in migration
    assert "'open'" in migration
    assert "'contacts_or_teammates'" in migration
    assert "'contacts_only'" in migration
    # Legacy two-value-only intermediate states must NOT appear.
    assert "messaging_policy = 'everyone'" not in migration
    assert "messaging_policy = 'contacts'" not in migration
    assert "team_only" not in migration


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

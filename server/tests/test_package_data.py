from importlib.resources import files


AWEB_MIGRATIONS = files("aweb") / "migrations" / "aweb"


def test_defaults_and_migrations_are_packaged():
    package_root = files("aweb")

    assert (package_root / "defaults" / "team_instructions.md").is_file()
    assert (package_root / "defaults" / "roles" / "backend.md").is_file()
    assert (AWEB_MIGRATIONS / "001_initial.sql").is_file()
    assert (AWEB_MIGRATIONS / "002_conversations.sql").is_file()
    assert (AWEB_MIGRATIONS / "003_conversations_constraints.sql").is_file()
    assert (AWEB_MIGRATIONS / "008_agent_inbound_mode.sql").is_file()
    assert (AWEB_MIGRATIONS / "009_drop_messaging_policy.sql").is_file()
    assert (AWEB_MIGRATIONS / "010_agent_identity_scope.sql").is_file()
    assert (AWEB_MIGRATIONS / "011_contacts_or_teammates_inbound_mode.sql").is_file()


def test_agent_inbound_mode_migration_maps_only_safe_legacy_values():
    migration = (AWEB_MIGRATIONS / "008_agent_inbound_mode.sql").read_text()

    assert "ADD COLUMN inbound_mode TEXT;" in migration
    assert "ADD COLUMN inbound_mode TEXT DEFAULT" not in migration
    assert "messaging_policy = 'everyone'" in migration
    assert "messaging_policy = 'contacts'" in migration
    assert "messaging_policy = 'team'" not in migration
    assert "messaging_policy = 'org'" not in migration
    assert "messaging_policy = 'nobody'" not in migration


def test_legacy_messaging_policy_column_is_removed_after_mapping():
    migration = (AWEB_MIGRATIONS / "009_drop_messaging_policy.sql").read_text()

    assert "DROP COLUMN IF EXISTS messaging_policy" in migration


def test_agent_lifetime_storage_is_replaced_with_identity_scope():
    migration = (AWEB_MIGRATIONS / "010_agent_identity_scope.sql").read_text()

    assert "ADD COLUMN identity_scope TEXT" in migration
    assert "WHEN 'persistent' THEN 'global'" in migration
    assert "WHEN 'ephemeral' THEN 'local'" in migration
    assert "DROP COLUMN lifetime" in migration


def test_contacts_or_teammates_inbound_mode_is_explicit_schema_value():
    migration = (AWEB_MIGRATIONS / "011_contacts_or_teammates_inbound_mode.sql").read_text()

    assert "DROP CONSTRAINT IF EXISTS agents_inbound_mode_valid" in migration
    assert "'contacts_or_teammates'" in migration
    assert "team_only" not in migration
    assert "team_members_only" not in migration

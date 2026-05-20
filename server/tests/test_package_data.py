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


def test_agent_inbound_mode_migration_maps_only_safe_legacy_values():
    migration = (AWEB_MIGRATIONS / "008_agent_inbound_mode.sql").read_text()

    assert "ADD COLUMN inbound_mode TEXT;" in migration
    assert "ADD COLUMN inbound_mode TEXT DEFAULT" not in migration
    assert "messaging_policy = 'everyone'" in migration
    assert "messaging_policy = 'contacts'" in migration
    assert "messaging_policy = 'team'" not in migration
    assert "messaging_policy = 'org'" not in migration
    assert "messaging_policy = 'nobody'" not in migration

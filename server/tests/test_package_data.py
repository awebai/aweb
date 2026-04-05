from importlib.resources import files


def test_defaults_and_migrations_are_packaged():
    package_root = files("aweb")

    assert (package_root / "defaults" / "project_instructions.md").is_file()
    assert (package_root / "defaults" / "roles" / "backend.md").is_file()
    assert (package_root / "migrations" / "aweb" / "001_initial.sql").is_file()
    assert (package_root / "migrations" / "aweb" / "002_drop_embedded_identity_tables.sql").is_file()
    assert (package_root / "migrations" / "server" / "001_initial.sql").is_file()

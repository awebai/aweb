"""Real PostgreSQL databases for the runtime tests (pgdbm's test_db_factory)."""

pytest_plugins = ("pgdbm.fixtures.conftest", "aweb_naapp_testing.server")

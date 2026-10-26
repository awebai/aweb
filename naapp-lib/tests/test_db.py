from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig
from pgdbm.errors import MigrationError
from pgdbm.testing import AsyncTestDatabase, DatabaseTestConfig
from pydantic_settings import SettingsConfigDict

from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.roles import apply_roles_migrations
from aweb_naapp.runtime.db import NaappDatabase
from aweb_naapp.runtime.settings import NaappSettings

_TEST_DB_CONFIG = DatabaseTestConfig(
    host=os.environ.get("TEST_DB_HOST", "localhost"),
    port=int(os.environ.get("TEST_DB_PORT", "5432")),
    user=os.environ.get("TEST_DB_USER", "postgres"),
    password=os.environ.get("TEST_DB_PASSWORD", "postgres"),
)


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    public_origin: str = "https://example.test"
    app_id: str = "example"


@pytest_asyncio.fixture
async def database_url() -> AsyncIterator[str]:
    """A fresh, empty real Postgres database."""
    test_database = AsyncTestDatabase(_TEST_DB_CONFIG)
    try:
        await test_database.create_test_database()
    except Exception as exc:  # pragma: no cover - environment without Postgres
        if os.environ.get("NAAPP_REQUIRE_TEST_DATABASE") == "1":
            raise RuntimeError("real Postgres is required for this test run") from exc
        pytest.skip(f"real Postgres not available: {exc}")
    try:
        yield test_database.get_test_db_config().get_dsn()
    finally:
        await test_database.drop_test_database()


def _migrations(tmp_path: Path) -> Path:
    path = tmp_path / "migrations"
    path.mkdir()
    (path / "001_initial.sql").write_text(
        "CREATE TABLE {{tables.things}} ("
        " id integer PRIMARY KEY,"
        " team_id TEXT REFERENCES {{tables.teams}}(team_id));\n"
    )
    return path


def _applied(rows: list) -> list[tuple[str, str]]:
    return [(row["module_name"], row["filename"]) for row in rows]


_SHARED = ("aweb_naapp", "001_observed_principals.sql")
_OUTBOX = [
    ("aweb_naapp_outbox", "001_outbox.sql"),
    ("aweb_naapp_outbox", "002_outbox_channels.sql"),
    ("aweb_naapp_outbox", "003_admission_backlog.sql"),
    ("aweb_naapp_outbox", "004_missing_production.sql"),
]


async def test_connect_applies_the_shared_and_outbox_then_the_app_migrations(
    database_url: str, tmp_path: Path
) -> None:
    # The app migration references the shared teams table, so it can only
    # apply after the shared migrations.
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    database = NaappDatabase(settings, module_name="example", migrations_path=_migrations(tmp_path))
    await database.connect()
    try:
        for table in ("things", "teams", "agents", "outbox_events", "outbox_deliveries"):
            assert await database.db.fetch_value(f"SELECT to_regclass('{table}') IS NOT NULL")
        applied = await database.db.fetch_all(
            "SELECT module_name, filename FROM schema_migrations ORDER BY id"
        )
        assert _applied(applied) == [_SHARED, *_OUTBOX, ("example", "001_initial.sql")]
    finally:
        await database.disconnect()


async def test_an_app_that_already_created_the_shared_tables_keeps_its_rows(
    database_url: str, tmp_path: Path
) -> None:
    app_migrations = tmp_path / "app-migrations"
    app_migrations.mkdir()
    (app_migrations / "001_initial.sql").write_text(
        "CREATE TABLE IF NOT EXISTS {{tables.teams}} ("
        " team_id TEXT PRIMARY KEY, team_did_key TEXT NOT NULL,"
        " first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        " last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW());\n"
    )
    existing = AsyncDatabaseManager(DatabaseConfig(connection_string=database_url, schema="public"))
    await existing.connect()
    try:
        await AsyncMigrationManager(
            existing, migrations_path=str(app_migrations), module_name="example"
        ).apply_pending_migrations()
        await existing.execute(
            "INSERT INTO teams (team_id, team_did_key) VALUES ('team:example.test', 'did:key:z')"
        )
    finally:
        await existing.disconnect()

    settings = ExampleSettings(_env_file=None, database_url=database_url)
    database = NaappDatabase(settings, module_name="example", migrations_path=app_migrations)
    await database.connect()
    try:
        assert await database.db.fetch_value("SELECT team_id FROM teams") == "team:example.test"
        applied = await database.db.fetch_all(
            "SELECT module_name, filename FROM schema_migrations ORDER BY id"
        )
        assert _applied(applied) == [("example", "001_initial.sql"), _SHARED, *_OUTBOX]
    finally:
        await database.disconnect()


async def test_reconnecting_applies_nothing_twice(database_url: str, tmp_path: Path) -> None:
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    migrations = _migrations(tmp_path)
    for _ in range(2):
        database = NaappDatabase(settings, module_name="example", migrations_path=migrations)
        await database.connect()
        count = await database.db.fetch_value("SELECT count(*) FROM schema_migrations")
        await database.disconnect()
        assert count == 6


async def test_pool_follows_the_settings(database_url: str, tmp_path: Path) -> None:
    settings = ExampleSettings(
        _env_file=None,
        database_url=database_url,
        db_pool_min_connections=2,
        db_pool_max_connections=3,
    )
    database = NaappDatabase(settings, module_name="example", migrations_path=_migrations(tmp_path))
    await database.connect()
    try:
        stats = await database.db.get_pool_stats()
        assert (stats["min_size"], stats["max_size"]) == (2, 3)
    finally:
        await database.disconnect()


def _migrations_on_roles(tmp_path: Path) -> Path:
    path = tmp_path / "role-migrations"
    path.mkdir()
    (path / "001_owners.sql").write_text(
        "CREATE VIEW {{tables.owners}} AS"
        " SELECT team_id, principal_did FROM {{tables.role_assignments}}"
        " WHERE role = 'example.owner';\n"
    )
    return path


async def test_an_app_migration_builds_on_the_stores_it_names(
    database_url: str, tmp_path: Path
) -> None:
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    database = NaappDatabase(
        settings,
        module_name="example",
        migrations_path=_migrations_on_roles(tmp_path),
        stores=(apply_idempotency_migrations, apply_roles_migrations),
    )
    await database.connect()
    try:
        assert await database.db.fetch_value("SELECT to_regclass('owners') IS NOT NULL")
        applied = await database.db.fetch_all(
            "SELECT module_name, filename FROM schema_migrations ORDER BY id"
        )
        assert _applied(applied) == [
            _SHARED,
            *_OUTBOX,
            ("aweb_naapp_idempotency", "001_idempotency_keys.sql"),
            ("aweb_naapp_roles", "001_role_assignments.sql"),
            ("example", "001_owners.sql"),
        ]
    finally:
        await database.disconnect()


async def test_an_app_migration_on_a_store_it_does_not_name_fails(
    database_url: str, tmp_path: Path
) -> None:
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    database = NaappDatabase(
        settings, module_name="example", migrations_path=_migrations_on_roles(tmp_path)
    )
    try:
        with pytest.raises(MigrationError) as refused:
            await database.connect()
        assert isinstance(refused.value.__cause__, asyncpg.UndefinedTableError)
    finally:
        await database.disconnect()


async def test_reconnecting_with_stores_applies_nothing_twice(
    database_url: str, tmp_path: Path
) -> None:
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    migrations = _migrations_on_roles(tmp_path)
    for _ in range(2):
        database = NaappDatabase(
            settings,
            module_name="example",
            migrations_path=migrations,
            stores=(apply_roles_migrations,),
        )
        await database.connect()
        count = await database.db.fetch_value("SELECT count(*) FROM schema_migrations")
        await database.disconnect()
        assert count == 7


async def _default_search_path_is_pg_catalog(database_url: str) -> None:
    """Model a role whose default search_path resolves no user schema."""
    admin = await asyncpg.connect(database_url)
    try:
        name = await admin.fetchval("SELECT current_database()")
        await admin.execute(f'ALTER DATABASE "{name}" SET search_path = pg_catalog')
    finally:
        await admin.close()


@pytest.mark.parametrize("db_schema,expected", [(None, "public"), ("example_app", "example_app")])
async def test_the_runtime_migrates_into_its_schema_whatever_the_roles_search_path(
    database_url: str, tmp_path: Path, db_schema: str | None, expected: str
) -> None:
    await _default_search_path_is_pg_catalog(database_url)
    values = {} if db_schema is None else {"db_schema": db_schema}
    settings = ExampleSettings(_env_file=None, database_url=database_url, **values)
    database = NaappDatabase(settings, module_name="example", migrations_path=_migrations(tmp_path))
    await database.connect()
    try:
        for table in ("things", "teams", "outbox_events", "schema_migrations"):
            assert await database.db.fetch_value(f"SELECT to_regclass('{expected}.{table}') IS NOT NULL")
    finally:
        await database.disconnect()

from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
import pytest_asyncio
from awid_service.testing import selected_test_database_config
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig
from pgdbm.errors import MigrationError, QueryError
from pgdbm.testing import AsyncTestDatabase
from pydantic_settings import SettingsConfigDict

from aweb_naapp import idempotency, outbox, roles
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.roles import apply_roles_migrations
from aweb_naapp.runtime import db as runtime_db
from aweb_naapp.runtime.db import ApplyMigrations, NaappDatabase, VerifyPreparedSchema
from aweb_naapp.runtime.settings import NaappSettings


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    public_origin: str = "https://example.test"
    app_id: str = "example"


@pytest_asyncio.fixture
async def database_url() -> AsyncIterator[str]:
    """A fresh, empty real Postgres database."""
    test_database = AsyncTestDatabase(selected_test_database_config())
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


def _listed_migrations(path: Path, module: str) -> list[tuple[str, str]]:
    return [(module, migration.name) for migration in sorted(path.glob("*.sql"))]


_SHARED = _listed_migrations(runtime_db._SHARED_MIGRATIONS, runtime_db._SHARED_MODULE)
_OUTBOX = _listed_migrations(outbox.MIGRATIONS_PATH, outbox.MIGRATIONS_MODULE)
_ROLES = _listed_migrations(roles.MIGRATIONS_PATH, roles.MIGRATIONS_MODULE)
_IDEMPOTENCY = _listed_migrations(idempotency.MIGRATIONS_PATH, idempotency.MIGRATIONS_MODULE)


async def test_connect_applies_the_shared_and_outbox_then_the_app_migrations(
    database_url: str, tmp_path: Path
) -> None:
    # The app migration references the shared teams table, so it can only
    # apply after the shared migrations.
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    database = NaappDatabase(
        settings,
        module_name="example",
        migrations_path=_migrations(tmp_path),
        schema_preparation=ApplyMigrations(),
    )
    await database.connect()
    try:
        for table in ("things", "teams", "agents", "outbox_events", "outbox_deliveries"):
            assert await database.db.fetch_value(f"SELECT to_regclass('{table}') IS NOT NULL")
        applied = await database.db.fetch_all(
            "SELECT module_name, filename FROM schema_migrations ORDER BY id"
        )
        assert _applied(applied) == [*_SHARED, *_OUTBOX, ("example", "001_initial.sql")]
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
    database = NaappDatabase(
        settings,
        module_name="example",
        migrations_path=app_migrations,
        schema_preparation=ApplyMigrations(),
    )
    await database.connect()
    try:
        assert await database.db.fetch_value("SELECT team_id FROM teams") == "team:example.test"
        applied = await database.db.fetch_all(
            "SELECT module_name, filename FROM schema_migrations ORDER BY id"
        )
        assert _applied(applied) == [("example", "001_initial.sql"), *_SHARED, *_OUTBOX]
    finally:
        await database.disconnect()


async def test_reconnecting_applies_nothing_twice(database_url: str, tmp_path: Path) -> None:
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    migrations = _migrations(tmp_path)
    expected = [*_SHARED, *_OUTBOX, *_listed_migrations(migrations, "example")]
    for _ in range(2):
        database = NaappDatabase(
            settings,
            module_name="example",
            migrations_path=migrations,
            schema_preparation=ApplyMigrations(),
        )
        await database.connect()
        count = await database.db.fetch_value("SELECT count(*) FROM schema_migrations")
        await database.disconnect()
        assert count == len(expected)


async def test_pool_follows_the_settings(database_url: str, tmp_path: Path) -> None:
    settings = ExampleSettings(
        _env_file=None,
        database_url=database_url,
        db_pool_min_connections=2,
        db_pool_max_connections=3,
    )
    database = NaappDatabase(
        settings,
        module_name="example",
        migrations_path=_migrations(tmp_path),
        schema_preparation=ApplyMigrations(),
    )
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
        schema_preparation=ApplyMigrations(),
    )
    await database.connect()
    try:
        assert await database.db.fetch_value("SELECT to_regclass('owners') IS NOT NULL")
        applied = await database.db.fetch_all(
            "SELECT module_name, filename FROM schema_migrations ORDER BY id"
        )
        assert _applied(applied) == [
            *_SHARED,
            *_OUTBOX,
            *_IDEMPOTENCY,
            *_ROLES,
            ("example", "001_owners.sql"),
        ]
    finally:
        await database.disconnect()


async def test_an_app_migration_on_a_store_it_does_not_name_fails(
    database_url: str, tmp_path: Path
) -> None:
    settings = ExampleSettings(_env_file=None, database_url=database_url)
    database = NaappDatabase(
        settings,
        module_name="example",
        migrations_path=_migrations_on_roles(tmp_path),
        schema_preparation=ApplyMigrations(),
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
    expected = [*_SHARED, *_OUTBOX, *_ROLES, *_listed_migrations(migrations, "example")]
    for _ in range(2):
        database = NaappDatabase(
            settings,
            module_name="example",
            migrations_path=migrations,
            stores=(apply_roles_migrations,),
            schema_preparation=ApplyMigrations(),
        )
        await database.connect()
        count = await database.db.fetch_value("SELECT count(*) FROM schema_migrations")
        await database.disconnect()
        assert count == len(expected)


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
    database = NaappDatabase(
        settings,
        module_name="example",
        migrations_path=_migrations(tmp_path),
        schema_preparation=ApplyMigrations(),
    )
    await database.connect()
    try:
        for table in ("things", "teams", "outbox_events", "schema_migrations"):
            assert await database.db.fetch_value(
                f"SELECT to_regclass('{expected}.{table}') IS NOT NULL"
            )
    finally:
        await database.disconnect()


async def test_a_deletion_ledger_must_be_a_database_of_its_own(test_db_factory) -> None:
    content = await test_db_factory.create_db(suffix="content")
    ledger = await test_db_factory.create_db(suffix="ledger")
    await runtime_db.require_separate_database(content, ledger, ledger_name="example ledger")

    with pytest.raises(ValueError, match="example ledger must be outside"):
        await runtime_db.require_separate_database(content, content, ledger_name="example ledger")
    # Another schema, or another manager, of the content database is that database.
    same = AsyncDatabaseManager(
        DatabaseConfig(connection_string=content.config.get_dsn(), schema="other_schema")
    )
    await same.connect()
    try:
        with pytest.raises(ValueError, match="example ledger must use a separate database"):
            await runtime_db.require_separate_database(content, same, ledger_name="example ledger")
    finally:
        await same.disconnect()


@pytest_asyncio.fixture
async def prepared_runtime_database(database_url: str):
    """A private LOGIN role with SELECT but no database/schema DDL authority."""
    admin = await asyncpg.connect(database_url)
    role = "prepared_runtime_" + uuid4().hex
    password = secrets.token_hex(24)
    await admin.execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'")
    try:
        await admin.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        await admin.execute("CREATE TABLE public.prepared_marker (id integer PRIMARY KEY)")
        await admin.execute("INSERT INTO public.prepared_marker VALUES (1)")
        await admin.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
        await admin.execute(f"GRANT SELECT ON public.prepared_marker TO {role}")
        parsed = urlsplit(database_url)
        runtime_url = urlunsplit(
            parsed._replace(netloc=f"{role}:{password}@{parsed.hostname}:{parsed.port or 5432}")
        )
        configured = ExampleSettings(_env_file=None, database_url=runtime_url)
        yield configured, admin, role
    finally:
        await admin.execute(f"DROP OWNED BY {role}")
        await admin.execute(f"DROP ROLE {role}")
        await admin.close()


@pytest.mark.parametrize("schema", ["public", "prepared_content", "MixedCase"])
def test_prepared_runtime_startup_path_matches_its_checked_pin(tmp_path: Path, schema: str):
    configured = ExampleSettings(
        _env_file=None, database_url="postgresql://unconnected/fixture", db_schema=schema
    )

    async def require_marker(db: AsyncDatabaseManager) -> None:
        assert await db.fetch_value("SELECT id FROM {{tables.prepared_marker}}") == 1

    database = NaappDatabase(
        configured,
        module_name="must_not_prepare",
        migrations_path=tmp_path / "absent-migrations",
        schema_preparation=VerifyPreparedSchema(check=require_marker),
    )
    config = database.db.config
    assert config is not None
    intended = f'"{schema}", pg_catalog'
    assert config.get_server_settings()["search_path"] == intended
    assert config.shared_pool_search_path == intended


async def test_prepared_runtime_connects_without_create_and_closes_its_owned_pool(
    prepared_runtime_database, tmp_path: Path
):
    configured, admin, role = prepared_runtime_database

    async def check_prepared(db: AsyncDatabaseManager) -> None:
        assert db.schema == configured.db_schema
        assert await db.fetch_value("SELECT id FROM {{tables.prepared_marker}}") == 1
        assert await db.fetch_value("SELECT current_schemas(false)") == ["public", "pg_catalog"]
        assert not await db.fetch_value(
            "SELECT has_schema_privilege(current_user, 'public', 'CREATE')"
        )

    database = NaappDatabase(
        configured,
        module_name="must_not_prepare",
        migrations_path=tmp_path / "absent-migrations",
        schema_preparation=VerifyPreparedSchema(check=check_prepared),
    )
    try:
        await database.connect()
        assert (
            await admin.fetchval("SELECT count(*) FROM pg_stat_activity WHERE usename=$1", role) > 0
        )
        with pytest.raises(QueryError) as denied:
            await database.db.execute("CREATE TABLE public.runtime_must_not_create (id integer)")
        assert isinstance(denied.value.__cause__, asyncpg.InsufficientPrivilegeError)
    finally:
        await database.disconnect()
    assert await admin.fetchval("SELECT count(*) FROM pg_stat_activity WHERE usename=$1", role) == 0
    assert await admin.fetchval("SELECT to_regclass('public.schema_migrations')") is None


async def test_failed_prepared_schema_check_closes_every_runtime_connection(
    prepared_runtime_database, tmp_path: Path
):
    configured, admin, role = prepared_runtime_database

    class PreparedSchemaRefused(RuntimeError):
        """The prepared content cannot be served under the configured identity."""

    async def refuse_prepared(db: AsyncDatabaseManager) -> None:
        assert await db.fetch_value("SELECT id FROM {{tables.prepared_marker}}") == 1
        raise PreparedSchemaRefused("Restore the matching prepared database before starting.")

    database = NaappDatabase(
        configured,
        module_name="must_not_prepare",
        migrations_path=tmp_path / "absent-migrations",
        schema_preparation=VerifyPreparedSchema(check=refuse_prepared),
    )
    with pytest.raises(PreparedSchemaRefused):
        await database.connect()
    assert await admin.fetchval("SELECT count(*) FROM pg_stat_activity WHERE usename=$1", role) == 0
    assert await admin.fetchval("SELECT to_regclass('public.schema_migrations')") is None

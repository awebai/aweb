"""A database Library migrated on its own starts on the shared runtime and keeps
its observed teams and pinned team keys."""

from __future__ import annotations

from pathlib import Path

from aweb_naapp.runtime.team_auth import Principal, record_observed_principal
from aweb_naapp.runtime.team_key_pins import DatabaseTeamKeyPins
from aweb_naapp_testing.databases import TEST_SCHEMA
from fastapi.testclient import TestClient
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig

from library.api import create_app
from library.config import Settings

_LIBRARY_MIGRATIONS = Path(__file__).resolve().parents[1] / "src" / "library" / "migrations"
_TEAM_ID = "team:upgrade.test"


async def _migrate_as_library_alone(database_url: str) -> None:
    existing = AsyncDatabaseManager(
        DatabaseConfig(connection_string=database_url, schema=TEST_SCHEMA)
    )
    await existing.connect()
    try:
        await AsyncMigrationManager(
            existing, migrations_path=str(_LIBRARY_MIGRATIONS), module_name="library"
        ).apply_pending_migrations()
        await record_observed_principal(
            existing,
            Principal(
                team_id=_TEAM_ID,
                did_key="did:key:zmember",
                did_aw=None,
                address=None,
                alias="member",
                certificate_id="certificate",
                team_did_key="did:key:zteam",
                did_aw_registry_verified=False,
            ),
        )
        await DatabaseTeamKeyPins(lambda: existing).first_sight(_TEAM_ID, "did:key:zteam")
    finally:
        await existing.disconnect()


async def test_a_database_library_migrated_alone_starts_on_the_runtime_with_its_rows(
    database_url: str,
) -> None:
    await _migrate_as_library_alone(database_url)

    settings = Settings(
        _env_file=None,
        database_url=database_url,
        db_schema=TEST_SCHEMA,
        public_origin="http://127.0.0.1:8765",
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/v1/blueprints").status_code == 200

    reopened = AsyncDatabaseManager(
        DatabaseConfig(connection_string=database_url, schema=TEST_SCHEMA)
    )
    await reopened.connect()
    try:
        pinned = await reopened.fetch_value(
            "SELECT team_did_key FROM {{tables.team_key_pins}} WHERE team_id = $1", _TEAM_ID
        )
        team = await reopened.fetch_value(
            "SELECT team_id FROM {{tables.teams}} WHERE team_id = $1", _TEAM_ID
        )
    finally:
        await reopened.disconnect()
    assert pinned == "did:key:zteam"
    assert team == _TEAM_ID

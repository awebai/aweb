"""The shared teams/agents record of authenticated principals, on real PostgreSQL."""

from __future__ import annotations

from pathlib import Path

import pytest
from pgdbm import AsyncMigrationManager

import aweb_naapp.runtime
from aweb_naapp.runtime.team_auth import Principal, record_observed_principal

MIGRATIONS = Path(aweb_naapp.runtime.__file__).parent / "migrations"


def principal(**changes) -> Principal:
    fields = dict(team_id="backend:example.com", did_key="did:key:z6MkAlice", did_aw=None, address=None,
                  alias="alice", certificate_id="cert-1", team_did_key="did:key:z6MkTeam")
    return Principal(**{**fields, **changes})


async def migrate(db) -> None:
    await AsyncMigrationManager(db, migrations_path=str(MIGRATIONS), module_name="aweb_naapp").apply_pending_migrations()


@pytest.fixture
async def db(test_db_factory):
    return await test_db_factory.create_db(suffix="naapp_principals")


async def test_first_and_repeated_observations_upsert_one_row_each(db):
    await migrate(db)
    await record_observed_principal(db, principal())
    await record_observed_principal(
        db, principal(did_aw="did:aw:alice", address="example.com/alice", certificate_id="cert-2",
                      team_did_key="did:key:z6MkRotated"),
    )
    teams = await db.fetch_all("SELECT team_id, team_did_key FROM {{tables.teams}}")
    agents = await db.fetch_all("SELECT did_aw, address, latest_certificate_id FROM {{tables.agents}}")
    assert [dict(r) for r in teams] == [{"team_id": "backend:example.com", "team_did_key": "did:key:z6MkRotated"}]
    assert [dict(r) for r in agents] == [
        {"did_aw": "did:aw:alice", "address": "example.com/alice", "latest_certificate_id": "cert-2"}
    ]


async def test_same_key_under_another_alias_is_another_agent(db):
    await migrate(db)
    await record_observed_principal(db, principal())
    await record_observed_principal(db, principal(alias="alice-2"))
    assert (await db.fetch_one("SELECT count(*) AS n FROM {{tables.agents}}"))["n"] == 2


async def test_migration_adopts_tables_an_app_already_created(db):
    # An app whose own initial migration created identical tables keeps its rows.
    await db.execute(
        "CREATE TABLE {{tables.teams}} (team_id TEXT PRIMARY KEY, team_did_key TEXT NOT NULL, "
        "first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
    )
    await db.execute("INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ('kept:example.com', 'k')")
    await migrate(db)
    await record_observed_principal(db, principal())
    rows = await db.fetch_all("SELECT team_id FROM {{tables.teams}} ORDER BY team_id")
    assert [r["team_id"] for r in rows] == ["backend:example.com", "kept:example.com"]

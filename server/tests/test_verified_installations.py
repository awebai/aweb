"""Verified origin bytes and conditional authority writes on real PostgreSQL."""

from __future__ import annotations

import asyncio
import json

import pytest
import pytest_asyncio

from aweb.app_registry import get_active_app_key, get_installation_on, get_installed_app_event_type, list_installed_apps
from aweb.installations import InstallationError, install_verified_manifest_on
import test_app_manifest_fetch as manifest_fixture

origin = manifest_fixture.origin
pytestmark = pytest.mark.asyncio
TEAM = "demo:example.com"


@pytest_asyncio.fixture
async def db(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1, 'example.com', 'demo', 'did:key:team')",
        TEAM,
    )
    return db


async def fetched(origin, app_version="1.0.0"):
    doc = json.loads(origin.manifest(version=app_version))
    doc["app_keys"][0]["purposes"].append("app-grant-read")
    origin.publish(json.dumps(doc).encode())
    return await origin.fetcher.fetch(origin.url)


async def install(db, evidence, expected_generation=None, scopes=None):
    async with db.transaction() as tx:
        return await install_verified_manifest_on(
            tx, team_id=TEAM, fetched=evidence,
            granted_scopes=scopes or ["fixture:read"],
            expected_generation=expected_generation,
        )


async def current(db):
    async with db.transaction() as tx:
        return await get_installation_on(tx, team_id=TEAM, app_id="fixture")


async def test_new_install_uses_origin_evidence_and_only_selected_scopes(db, origin):
    evidence = await fetched(origin)
    row = await install(db, evidence)
    assert row["installation_id"]
    assert row["generation"] == 1
    assert (row["state"], row["origin_verified"]) == ("active", True)
    assert row["granted_scopes"] == ["fixture:read"]
    assert row["digest"] == evidence.digest
    assert await db.fetch_value("SELECT manifest_bytes FROM {{tables.team_app_installs}}") == evidence.data
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_keys}}") == 1


async def test_update_keeps_id_and_allocates_a_higher_generation(db, origin):
    first = await install(db, await fetched(origin))
    updated = await install(db, await fetched(origin, "2.0.0"), first["generation"])
    assert updated["installation_id"] == first["installation_id"]
    assert updated["generation"] == first["generation"] + 1
    assert updated["app_version"] == "2.0.0"
    assert updated["digest"] != first["digest"]


@pytest.mark.parametrize("expected", [None, 999])
async def test_an_update_cannot_guess_or_omit_the_previous_generation(db, origin, expected):
    evidence = await fetched(origin)
    before = await install(db, evidence)
    with pytest.raises(InstallationError) as refusal:
        await install(db, evidence, expected)
    assert refusal.value.code == ("generation_required" if expected is None else "generation_conflict")
    assert await current(db) == before
    assert await db.fetch_value("SELECT last_generation FROM {{tables.team_app_install_counters}}") == 1


async def test_concurrent_updates_have_one_winner_and_no_lost_write(db, origin):
    evidence = await fetched(origin)
    await install(db, evidence)
    results = await asyncio.gather(install(db, evidence, 1), install(db, evidence, 1), return_exceptions=True)
    assert sum(isinstance(r, dict) for r in results) == 1
    refused = next(r for r in results if isinstance(r, InstallationError))
    assert refused.code == "generation_conflict"
    assert (await current(db))["generation"] == 2
    assert await db.fetch_value("SELECT last_generation FROM {{tables.team_app_install_counters}}") == 2


async def test_reinstall_never_reuses_an_identity_or_generation(db, origin):
    evidence = await fetched(origin)
    first = await install(db, evidence)
    # This test exercises the install side, after a lifecycle transaction has
    # already completed retirement. The C2 cancellation proof is separate.
    await db.execute("UPDATE {{tables.team_app_installs}} SET state = 'uninstalled'")
    second = await install(db, evidence, first["generation"])
    assert second["installation_id"] != first["installation_id"]
    assert second["generation"] > first["generation"]


async def test_caller_rollback_keeps_keys_identity_and_counter_unchanged(db, origin):
    evidence = await fetched(origin)
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await install_verified_manifest_on(tx, team_id=TEAM, fetched=evidence, granted_scopes=["fixture:read"])
            raise RuntimeError("caller transaction failed")
    assert await current(db) is None
    for table in ("team_app_keys", "team_app_event_types", "team_app_install_counters"):
        assert await db.fetch_value("SELECT COUNT(*) FROM {{tables." + table + "}}") == 0


async def test_unrequested_scope_is_refused_without_installing(db, origin):
    with pytest.raises(InstallationError) as refusal:
        await install(db, await fetched(origin), scopes=["not:requested"])
    assert refusal.value.code == "scope_not_requested"
    assert await current(db) is None


@pytest.mark.parametrize("state", ["pending_origin_verification", "uninstalled"])
async def test_inactive_rows_refuse_ordinary_authority_but_keep_grant_status_key(db, origin, state):
    evidence = await fetched(origin)
    await install(db, evidence)
    kid, did_key, _ = evidence.manifest.app_keys[0]
    async def key(purpose):
        return await get_active_app_key(db, team_id=TEAM, app_id="fixture", kid=kid, did_key=did_key, purpose=purpose)
    assert await key("app-event")
    assert await get_installed_app_event_type(db, team_id=TEAM, app_id="fixture", local_event_type="workspace.changed")
    await db.execute("UPDATE {{tables.team_app_installs}} SET state = $1", state)
    assert await key("app-event") is None
    assert await get_installed_app_event_type(db, team_id=TEAM, app_id="fixture", local_event_type="workspace.changed") is None
    assert await list_installed_apps(db, team_id=TEAM) == []
    assert await key("app-grant-read")

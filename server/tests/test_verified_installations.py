"""Verified origin bytes and conditional authority writes on real PostgreSQL."""

from __future__ import annotations

import asyncio
import json

import pytest
import pytest_asyncio

from aweb.app_registry import get_active_app_key, get_installation_on, get_installed_app_event_type, list_installed_apps
from aweb.installations import InstallationError, install_verified_manifest_on, verify_pending_installations
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


async def make_pending(db):
    await db.execute("UPDATE {{tables.team_app_installs}} SET state='pending_origin_verification', origin_verified=FALSE, manifest_bytes=NULL")


async def test_pending_verifier_preserves_pin_scopes_identity_and_generation(db, origin):
    evidence = await fetched(origin)
    before = await install(db, evidence)
    await make_pending(db)
    reports = await verify_pending_installations(db, fetcher=origin.fetcher)
    assert reports[0]["outcome"] == "verified"
    after = await current(db)
    for key in ("installation_id", "generation", "digest", "origin", "granted_scopes"):
        assert after[key] == before[key]
    assert after["state"] == "active" and after["origin_verified"]


async def test_pending_verifier_fetches_the_pinned_version_when_a_newer_variant_exists(db, origin):
    from test_app_manifest_fetch import CATALOG, LEGACY
    old_bytes = origin.manifest(1)
    origin.routes[CATALOG] = (404, b"", [])
    origin.routes[LEGACY] = (200, old_bytes, [])
    old = await origin.fetcher.fetch(origin.url)
    before = await install(db, old)
    await make_pending(db)
    origin.publish(origin.manifest())
    reports = await verify_pending_installations(db, fetcher=origin.fetcher)
    assert reports[0]["outcome"] == "verified"
    assert (await current(db))["digest"] == before["digest"]
    assert (await current(db))["manifest_version"] == 1


async def test_changed_origin_bytes_leave_pending_with_a_reason(db, origin):
    await install(db, await fetched(origin))
    await make_pending(db)
    before = await current(db)
    await fetched(origin, "2.0.0")
    reports = await verify_pending_installations(db, fetcher=origin.fetcher)
    assert reports[0]["outcome"] == "pending"
    after = await current(db)
    assert after["state"] == "pending_origin_verification"
    assert after["origin_verification_error"] == "manifest_changed"
    for key in ("installation_id", "generation", "digest", "origin", "granted_scopes"):
        assert after[key] == before[key]


async def test_verification_retires_legacy_planted_keys_and_events_before_activation(db, origin):
    evidence = await fetched(origin)
    await install(db, evidence)
    did_key = evidence.manifest.app_keys[0][1]
    for table, purposes in (("team_app_emit_keys", False), ("team_app_keys", True)):
        columns = ", purposes" if purposes else ""
        values = ", ARRAY['app-event']" if purposes else ""
        await db.execute(
            "INSERT INTO {{tables."+table+"}} (team_id,app_id,origin,digest,key_id,did_key"+columns+") VALUES ($1,'fixture',$2,$3,'planted',$4"+values+")",
            TEAM, origin.url, evidence.digest, did_key,
        )
    await db.execute(
        "INSERT INTO {{tables.team_app_event_types}} (team_id,app_id,origin,digest,event_type,default_delivery_intent,description) VALUES ($1,'fixture',$2,$3,'planted','wake','')",
        TEAM, origin.url, evidence.digest,
    )
    await make_pending(db)
    await verify_pending_installations(db, fetcher=origin.fetcher)
    assert (await current(db))["state"] == "active"
    for table in ("team_app_emit_keys", "team_app_keys"):
        assert await db.fetch_value("SELECT revoked_at FROM {{tables."+table+"}} WHERE key_id='planted'") is not None
    assert await get_installed_app_event_type(db, team_id=TEAM, app_id="fixture", local_event_type="planted") is None
    assert await get_active_app_key(db, team_id=TEAM, app_id="fixture", kid="planted", did_key=did_key, purpose="app-event") is None

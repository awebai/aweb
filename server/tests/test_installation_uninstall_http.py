"""Mounted admin uninstall through real TLS, policy reads and PostgreSQL."""

import asyncio
import json
from datetime import datetime

import pytest
import test_installation_http as http_fixture
from aweb_naapp.runtime.app_credentials import AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKey
from awid.did import did_from_public_key
from nacl.signing import SigningKey
from test_app_manifest_fetch import digest
from test_installation_http import admin, confirmation, post
from test_verified_installations import current

client = http_fixture.client
db = http_fixture.db
origin = http_fixture.origin
pytestmark = pytest.mark.asyncio


async def test_admin_uninstall_works_with_origin_offline_and_revokes_hooks(client, db, origin):
    await admin(db)
    installed = await post(client, confirmation(origin))
    assert installed.status_code == 200, installed.text
    before = installed.json()
    assert await db.fetch_value("SELECT count(*) FROM {{tables.app_hook_bindings}} WHERE state='pending'") > 0
    origin.tls.seen.clear()
    origin.publish(b"origin no longer serves a manifest")
    retired = await post(client, {"expected_generation": before["generation"]}, "fixture/uninstall")
    assert retired.status_code == 200, retired.text
    after = retired.json()
    assert after["state"] == "uninstalled"
    assert after["installation_id"] == before["installation_id"]
    assert after["generation"] > before["generation"]
    assert after["digest"] == before["digest"] and after["granted_scopes"] == before["granted_scopes"]
    assert not origin.tls.seen
    assert await db.fetch_value("SELECT count(*) FROM {{tables.app_hook_bindings}} WHERE state IN ('active','pending')") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.app_hook_bindings}} WHERE ended_by='uninstall'") > 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.audit_log}} WHERE event_type='apps.uninstall' AND outcome='success'") == 1


async def test_member_cannot_uninstall_through_the_mounted_route(client, db, origin):
    await admin(db)
    installed = (await post(client, confirmation(origin))).json()
    before = await current(db)
    await db.execute("DELETE FROM aweb.test_install_admins")
    refused = await post(client, {"expected_generation": installed["generation"]}, "fixture/uninstall")
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["code"] == "admin_required"
    assert await current(db) == before


async def test_uninstall_requires_generation_and_old_confirm_cannot_reinstall(client, db, origin):
    await admin(db)
    pin = confirmation(origin)
    first = (await post(client, pin)).json()
    refused = await post(client, {}, "fixture/uninstall")
    assert refused.status_code == 422
    retired = await post(client, {"expected_generation": first["generation"]}, "fixture/uninstall")
    assert retired.status_code == 200, retired.text
    stale = await post(client, dict(pin, expected_generation=first["generation"]))
    assert stale.status_code == 409, stale.text
    assert stale.json()["detail"]["code"] == "generation_conflict"
    assert (await current(db))["state"] == "uninstalled"
    second = await post(client, dict(pin, expected_generation=retired.json()["generation"]))
    assert second.status_code == 200, second.text
    assert second.json()["installation_id"] != first["installation_id"]
    assert second.json()["generation"] > retired.json()["generation"]
    third_retire = await post(client, {"expected_generation": second.json()["generation"]}, "fixture/uninstall")
    assert third_retire.status_code == 200, third_retire.text
    third = await post(client, dict(pin, expected_generation=third_retire.json()["generation"]))
    assert third.status_code == 200, third.text
    assert third.json()["installation_id"] not in {first["installation_id"], second.json()["installation_id"]}
    assert third.json()["generation"] > second.json()["generation"]


async def test_uninstall_repeat_is_idempotent_and_stale_generation_cannot_mutate(client, db, origin):
    await admin(db)
    first = (await post(client, confirmation(origin))).json()
    retired = await post(client, {"expected_generation": first["generation"]}, "fixture/uninstall")
    assert retired.status_code == 200, retired.text
    repeat = await post(client, {"expected_generation": retired.json()["generation"]}, "fixture/uninstall")
    assert repeat.status_code == 200 and repeat.json() == retired.json(), repeat.text
    stale = await post(client, {"expected_generation": first["generation"]}, "fixture/uninstall")
    assert stale.status_code == 409, stale.text
    assert stale.json()["detail"]["code"] == "generation_conflict"
    assert await db.fetch_value("SELECT last_generation FROM {{tables.team_app_install_counters}}") == retired.json()["generation"]


@pytest.mark.parametrize("generation", [None, True, 0, -1, 9223372036854775808, "1"])
async def test_invalid_uninstall_generation_has_no_effect(client, db, origin, generation):
    await admin(db)
    assert (await post(client, confirmation(origin))).status_code == 200
    before = await current(db)
    refused = await post(client, {"expected_generation": generation}, "fixture/uninstall")
    assert refused.status_code == 422, refused.text
    assert await current(db) == before


async def test_missing_installation_is_named_and_does_not_allocate_generation(client, db):
    await admin(db)
    response = await post(client, {"expected_generation": 1}, "fixture/uninstall")
    assert response.status_code == 404, response.text
    assert response.json()["detail"]["code"] == "installation_not_found"
    assert await db.fetch_value("SELECT count(*) FROM {{tables.team_app_install_counters}}") == 0


async def test_uninstall_and_update_cannot_both_consume_the_same_generation(client, db, origin):
    await admin(db)
    pin = confirmation(origin)
    first = (await post(client, pin)).json()
    uninstall, update = await asyncio.gather(
        post(client, {"expected_generation": first["generation"]}, "fixture/uninstall"),
        post(client, dict(pin, expected_generation=first["generation"])),
    )
    assert sorted([uninstall.status_code, update.status_code]) == [200, 409]
    winner = uninstall if uninstall.status_code == 200 else update
    loser = update if uninstall.status_code == 200 else uninstall
    assert loser.json()["detail"]["code"] == "generation_conflict"
    after = await current(db)
    assert (after["generation"], after["state"]) == (winner.json()["generation"], winner.json()["state"])
    assert after["generation"] == first["generation"] + 1


async def test_caller_rollback_restores_installation_hooks_and_generation_counter(client, db, origin):
    from aweb.installations import uninstall_installation_on

    await admin(db)
    assert (await post(client, confirmation(origin))).status_code == 200
    before = await current(db)
    bindings = await db.fetch_all("SELECT binding_id,state,ended_by FROM {{tables.app_hook_bindings}} ORDER BY binding_id")
    with pytest.raises(RuntimeError, match="caller rollback"):
        async with db.transaction() as tx:
            await uninstall_installation_on(tx, team_id=http_fixture.TEAM, app_id="fixture", expected_generation=1)
            raise RuntimeError("caller rollback")
    assert await current(db) == before
    assert await db.fetch_all("SELECT binding_id,state,ended_by FROM {{tables.app_hook_bindings}} ORDER BY binding_id") == bindings
    assert await db.fetch_value("SELECT last_generation FROM {{tables.team_app_install_counters}}") == before["generation"]


async def lifecycle_app(client, db, origin):
    await admin(db)
    key = SigningKey.generate()
    signer_key = AppKey(kid="lifecycle-read", did_key=did_from_public_key(bytes(key.verify_key)), signing_key=key)
    manifest = json.loads(origin.manifest())
    manifest["app_keys"].append({"kid": signer_key.kid, "did_key": signer_key.did_key,
                                 "purposes": ["app-grant-read", "hook-resolve"]})
    raw = json.dumps(manifest).encode()
    origin.publish(raw)
    pin = {"app_id": "fixture", "origin": origin.url, "digest": digest(raw), "granted_scopes": ["fixture:read"]}
    first = await post(client, pin)
    assert first.status_code == 200, first.text

    async def read(purpose, path):
        signer = AppCredentialSigner(app_id="fixture", key=signer_key, purpose=purpose)
        return await client.get(path, headers=signer.sign(method="GET", target="http://test" + path, team_id=http_fixture.TEAM).headers)

    return pin, first, read


async def test_real_uninstall_revokes_signed_grant_and_hook_reads_without_losing_status(client, db, origin):
    pin, first, read = await lifecycle_app(client, db, origin)

    binding_id = await db.fetch_value("SELECT binding_id FROM {{tables.app_hook_bindings}} LIMIT 1")
    grant_path = "/api/v1/apps/self/grant"
    hook_path = "/api/v1/apps/self/hooks/bindings?binding_id=" + str(binding_id)
    grant = await read("app-grant-read", grant_path)
    assert grant.status_code == 200 and grant.json()["state"] == "active", grant.text
    hooks = await read("hook-resolve", hook_path)
    assert hooks.status_code == 200 and hooks.json()["bindings"], hooks.text
    retired = await post(client, {"expected_generation": first.json()["generation"]}, "fixture/uninstall")
    assert retired.status_code == 200, retired.text
    grant = await read("app-grant-read", grant_path)
    assert grant.status_code == 200, grant.text
    assert (grant.json()["state"], grant.json()["installation_id"], grant.json()["generation"]) == (
        "uninstalled", first.json()["installation_id"], retired.json()["generation"])
    assert grant.json()["granted_scopes"] == first.json()["granted_scopes"]
    hooks = await read("hook-resolve", hook_path)
    assert hooks.status_code == 403, hooks.text
    assert hooks.json()["detail"] == "app_key_not_registered"

    new = await post(client, dict(pin, expected_generation=retired.json()["generation"]))
    assert new.status_code == 200, new.text
    assert new.json()["installation_id"] != first.json()["installation_id"]
    hooks = await read("hook-resolve", hook_path)
    assert hooks.status_code == 200, hooks.text
    assert all(binding["state"] != "active" for binding in hooks.json()["bindings"])
    assert any(binding["ended_by"] == "uninstall" for binding in hooks.json()["bindings"])


async def test_other_team_uninstall_cannot_mutate_the_callers_installation(client, db, origin):
    await admin(db)
    installed = await post(client, confirmation(origin))
    before = await current(db)
    refused = await client.post('/api/v1/apps/fixture/uninstall?team_id=other:example.com',
                                json={'expected_generation': installed.json()['generation']},
                                headers=http_fixture.headers())
    assert refused.status_code == 404, refused.text
    assert await current(db) == before


async def test_grant_creation_time_is_fixed_for_repin_and_changes_only_on_reinstall(client, db, origin):
    pin, first, read = await lifecycle_app(client, db, origin)
    path = "/api/v1/apps/self/grant"
    response = await read("app-grant-read", path)
    assert response.status_code == 200, response.text
    assert "installed_at" in response.json(), "grant-read must expose the installation creation time"
    created = datetime.fromisoformat(response.json()["installed_at"])
    repin = await post(client, dict(pin, expected_generation=first.json()["generation"]))
    assert repin.status_code == 200, repin.text
    assert repin.json()["installation_id"] == first.json()["installation_id"]
    assert repin.json()["generation"] > first.json()["generation"]
    assert datetime.fromisoformat((await read("app-grant-read", path)).json()["installed_at"]) == created
    retired = await post(client, {"expected_generation": repin.json()["generation"]}, "fixture/uninstall")
    assert retired.status_code == 200, retired.text
    assert datetime.fromisoformat((await read("app-grant-read", path)).json()["installed_at"]) == created
    replacement = await post(client, dict(pin, expected_generation=retired.json()["generation"]))
    assert replacement.status_code == 200, replacement.text
    assert replacement.json()["installation_id"] != first.json()["installation_id"]
    assert datetime.fromisoformat((await read("app-grant-read", path)).json()["installed_at"]) > created

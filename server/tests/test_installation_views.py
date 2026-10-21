"""Installation management comparisons use the shared manifest interpreter."""

import json

import pytest
import test_verified_installations as store_fixture
from aweb_naapp.manifest import load_manifest

from aweb.installation_views import installation_view_on, semantic_diff

origin = store_fixture.origin
db = store_fixture.db
pytestmark = pytest.mark.asyncio


async def test_diff_ignores_declaration_order_but_names_changed_endpoints_and_purposes(origin):
    doc = json.loads(origin.manifest())
    old = load_manifest(json.dumps(doc).encode())
    doc["tools"].reverse()
    doc["app_keys"].reverse()
    assert not any(semantic_diff(old, load_manifest(json.dumps(doc).encode()))[key]["changed"]
                   for key in ("tools", "endpoints", "app_keys", "surfaces"))
    changed = doc["tools"][0]
    changed["path"] = "/changed"
    key = doc["app_keys"][0]
    key["purposes"].append("app-grant-read")
    diff = semantic_diff(old, load_manifest(json.dumps(doc).encode()))
    assert diff["endpoints"]["changed"] == [changed["name"]]
    assert diff["app_keys"]["changed"] == [key["kid"]]


async def test_missing_old_bytes_marks_comparison_unavailable(origin):
    diff = semantic_diff(None, load_manifest(origin.manifest()))
    assert diff["available"] is False
    assert diff["requested_scopes"]["added"]


async def test_management_reads_show_pinned_declarations_and_explicit_unreported_lifecycle(db, origin):
    evidence = await store_fixture.fetched(origin)
    installed = await store_fixture.install(db, evidence)
    async with db.transaction() as tx:
        view = await installation_view_on(tx, team_id=store_fixture.TEAM, app_id="fixture")
    assert view["installation_id"] == installed["installation_id"]
    assert view["manifest"] == evidence.manifest.document
    assert view["resolved"] == evidence.manifest.view()
    assert view["lifecycle"]["declarations"] == evidence.manifest.view()["lifecycle"]
    assert view["lifecycle"]["report"] == {"available": False}


async def test_every_update_returns_owner_activated_hooks_to_pending(db, origin):
    evidence = await store_fixture.fetched(origin)
    first = await store_fixture.install(db, evidence)
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.app_hook_bindings}} WHERE state='pending'") > 0
    await db.execute(
        """UPDATE {{tables.app_hook_bindings}} SET state='active',
               activated_at=date_trunc('milliseconds',transaction_timestamp()),
               active_from=date_trunc('milliseconds',transaction_timestamp())+INTERVAL '60 seconds',
               activation_act_sha256=$1""", "a" * 64,
    )
    updated = await store_fixture.install(db, evidence, first["generation"])
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.app_hook_bindings}} WHERE state='active'") == 0
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.app_hook_bindings}} WHERE state='superseded'") > 0
    async with db.transaction() as tx:
        view = await installation_view_on(tx, team_id=store_fixture.TEAM, app_id="fixture")
    assert view["hook_bindings"]
    assert all(binding["state"] == "pending" and binding["generation"] == updated["generation"] for binding in view["hook_bindings"])

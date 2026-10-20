"""Installs that carry the exact manifest bytes, against the real route and database."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from httpx import ASGITransport, AsyncClient

import aweb.routes.apps as apps_routes
from aweb.app_registry import get_active_app_emit_key, get_installed_app_event_type
from tests.test_app_events_http import _make_app_keypair
from tests.test_app_registry_http import TEAM_ID, _build_apps_app, _fake_team_identity, _seed_team_and_agent

ORIGIN = "https://notes.example"


def _manifest(*, did_key: str, scopes: list[str] | None = None) -> bytes:
    return json.dumps(
        {
            "manifest_version": 1,
            "app": {"id": "notes", "version": "1.2.0", "origin": ORIGIN},
            "tools": [
                {"name": "list", "method": "GET", "path": "/v1/notes", "scopes": scopes or ["notes:read"]},
                {"name": "create", "method": "POST", "path": "/v1/notes", "scopes": ["notes:read", "notes:write"]},
            ],
            "events": [{"type": "notes/note.saved", "default_delivery_intent": "wake"}],
            "event_emitters": [{"kid": "notes:emit-1", "did_key": did_key}],
        },
        separators=(",", ":"),
    ).encode()


def _body(manifest: bytes | None, *, did_key: str, granted_scopes=None, events=None, emitters=None, digest=None) -> dict:
    digest = digest or "sha256:" + hashlib.sha256(manifest or b"").hexdigest()
    body = {
        "app_id": "notes",
        "origin": ORIGIN,
        "app_version": "1.2.0",
        "manifest_version": 1,
        "digest": digest,
        "granted_scopes": granted_scopes if granted_scopes is not None else ["notes:read", "notes:write"],
        "events": events if events is not None else [{"type": "note.saved", "default_delivery_intent": "wake"}],
        "event_emitters": emitters if emitters is not None else [{"kid": "notes:emit-1", "did_key": did_key}],
    }
    if manifest is not None:
        body["manifest"] = base64.b64encode(manifest).decode()
    return body


@pytest.fixture
def app(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    return _build_apps_app(aweb_cloud_db.aweb_db)


async def _install(app, body: dict):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.post("/v1/apps/install", json=body)


async def _install_rows(db):
    return await db.fetch_all(
        "SELECT digest, registered_from_manifest_bytes FROM {{tables.team_app_installs}} WHERE team_id = $1", TEAM_ID
    )


async def _audit_rows(db):
    rows = await db.fetch_all(
        "SELECT event_type, resource, outcome FROM {{tables.audit_log}} WHERE team_id = $1 ORDER BY created_at",
        TEAM_ID,
    )
    return [dict(row) for row in rows]


@pytest.mark.asyncio
async def test_bytes_that_agree_register_their_keys_and_declarations(app, aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)

    response = await _install(app, _body(manifest, did_key=did_key))

    assert response.status_code == 200, response.text
    assert await get_active_app_emit_key(db, team_id=TEAM_ID, app_id="notes", kid="notes:emit-1", did_key=did_key) is not None
    assert await get_installed_app_event_type(db, team_id=TEAM_ID, app_id="notes", local_event_type="note.saved") is not None
    assert [row["registered_from_manifest_bytes"] for row in await _install_rows(db)] == [True]


@pytest.mark.asyncio
async def test_bytes_alone_supply_keys_and_declarations(app, aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)

    response = await _install(app, _body(manifest, did_key=did_key, events=[], emitters=[]))

    assert response.status_code == 200, response.text
    assert await get_active_app_emit_key(db, team_id=TEAM_ID, app_id="notes", kid="notes:emit-1", did_key=did_key) is not None
    assert await get_installed_app_event_type(db, team_id=TEAM_ID, app_id="notes", local_event_type="note.saved") is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["emitters", "events", "scopes"])
async def test_fields_that_disagree_with_the_bytes_refuse_the_install(app, aweb_cloud_db, field):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    _, did_key = _make_app_keypair()
    _, planted = _make_app_keypair()
    manifest = _manifest(did_key=did_key)
    overrides = {
        "emitters": {"emitters": [{"kid": "notes:emit-1", "did_key": did_key}, {"kid": "planted", "did_key": planted}]},
        "events": {"events": [{"type": "note.saved", "default_delivery_intent": "steer"}]},
        "scopes": {"granted_scopes": ["notes:read", "notes:admin"]},
    }[field]

    response = await _install(app, _body(manifest, did_key=did_key, **overrides))

    assert response.status_code == 422, response.text
    assert await _install_rows(db) == []
    assert await get_active_app_emit_key(db, team_id=TEAM_ID, app_id="notes", kid="planted", did_key=planted) is None


@pytest.mark.asyncio
async def test_a_team_may_grant_fewer_scopes_than_the_bytes_request(app, aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)

    response = await _install(app, _body(manifest, did_key=did_key, granted_scopes=["notes:read"]))

    assert response.status_code == 200, response.text
    assert response.json()["granted_scopes"] == ["notes:read"]


@pytest.mark.asyncio
async def test_bytes_that_do_not_hash_to_the_digest_refuse_the_install(app, aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)

    response = await _install(app, _body(manifest, did_key=did_key, digest="sha256:" + "0" * 64))

    assert response.status_code == 422, response.text
    assert await _install_rows(db) == []


@pytest.mark.asyncio
async def test_an_install_without_bytes_behaves_as_before_and_is_counted(app, aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    _, did_key = _make_app_keypair()

    response = await _install(app, _body(None, did_key=did_key, digest="sha256:" + "a" * 64))

    assert response.status_code == 200, response.text
    assert await get_active_app_emit_key(db, team_id=TEAM_ID, app_id="notes", kid="notes:emit-1", did_key=did_key) is not None
    assert [row["registered_from_manifest_bytes"] for row in await _install_rows(db)] == [False]


@pytest.mark.asyncio
async def test_install_writes_the_operator_audit_row_with_its_registration(app, aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db)
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)

    accepted = await _install(app, _body(manifest, did_key=did_key))
    refused = await _install(app, _body(manifest, did_key=did_key, granted_scopes=["notes:admin"]))

    assert accepted.status_code == 200, accepted.text
    assert refused.status_code == 422, refused.text
    assert await _audit_rows(db) == [
        {"event_type": "apps.install", "resource": "app:notes", "outcome": "success"},
        {"event_type": "apps.install", "resource": "app:notes", "outcome": "denied"},
    ]

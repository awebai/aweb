from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
import test_installation_http as install_http
from fastapi import FastAPI

from aweb.app_registry import reserved_app_ids
from aweb.audit import AuditActor, set_verified_audit_actor
from aweb.routes.apps import router as apps_router
from aweb.team_auth_deps import TeamIdentity

client = install_http.client
db = install_http.db
origin = install_http.origin

TEAM_ID = "backend:acme.com"
AGENT_ID = UUID("00000000-0000-0000-0000-000000000123")
DIGEST_1 = "sha256:" + "a" * 64
DIGEST_2 = "sha256:" + "b" * 64


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


def _build_apps_app(aweb_db) -> FastAPI:
    app = FastAPI()
    app.include_router(apps_router)
    app.state.db = _DbShim(aweb_db)
    return app


async def _fake_team_identity(request, db_infra) -> TeamIdentity:
    # Real team-certificate auth sets the verified operator-audit actor.
    set_verified_audit_actor(
        request,
        AuditActor(team_id=TEAM_ID, principal_type="c", auth_mode="team_auth_v2", did_key="did:key:z6Mkalice"),
    )
    return TeamIdentity(
        team_id=TEAM_ID,
        alias="alice",
        did_key="did:key:z6Mkalice",
        did_aw="did:aw:alice",
        address="acme.com/alice",
        agent_id=str(AGENT_ID),
        identity_scope="global",
        certificate_id="cert-001",
    )


async def _seed_team_and_agent(aweb_db) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        TEAM_ID,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            agent_id, team_id, did_key, alias, human_name, status, identity_scope
        )
        VALUES ($1, $2, 'did:key:z6Mkalice', 'alice', 'Alice', 'active', 'global')
        ON CONFLICT DO NOTHING
        """,
        AGENT_ID,
        TEAM_ID,
    )


@pytest.mark.asyncio
async def test_list_apps_empty_team_returns_empty_apps(client):
    response = await client.get(f"/api/v1/apps/installed?team_id={install_http.TEAM}", headers=install_http.headers())
    assert response.status_code == 200, response.text
    assert response.json() == {"team_id": install_http.TEAM, "apps": []}


@pytest.mark.asyncio
async def test_install_and_list_apps_returns_verified_identity_and_scope_projection(client, db, origin):
    await install_http.admin(db)
    body = install_http.confirmation(origin)
    body["granted_scopes"] *= 2
    installed = await install_http.post(client, body)
    assert installed.status_code == 200, installed.text
    record = installed.json()
    assert record["granted_scopes"] == ["fixture:read"]
    assert record["installation_id"] and record["generation"] == 1
    assert record["state"] == "active" and record["origin_verified"]
    response = await client.get(f"/api/v1/apps/installed?team_id={install_http.TEAM}", headers=install_http.headers())
    assert response.status_code == 200
    assert response.json()["apps"] == [record]


@pytest.mark.asyncio
async def test_zero_scope_install_remains_listed_with_empty_grants(client, db, origin):
    await install_http.admin(db)
    body = install_http.confirmation(origin)
    body["granted_scopes"] = []
    response = await install_http.post(client, body)
    assert response.status_code == 200, response.text
    response = await client.get(f"/api/v1/apps/installed?team_id={install_http.TEAM}", headers=install_http.headers())
    assert response.json()["apps"][0]["granted_scopes"] == []


@pytest.mark.asyncio
async def test_internal_gateway_cannot_select_another_team(client):
    response = await client.get(f"/api/v1/apps/installed?team_id={TEAM_ID}", headers=install_http.headers())
    assert response.status_code == 404


def test_reserved_app_ids_are_loaded_from_cli_artifact():
    artifact = Path(__file__).resolve().parents[2] / "test-vectors/reserved-app-ids-v1.json"
    import json
    assert reserved_app_ids() == frozenset(json.loads(artifact.read_bytes())["reserved_app_ids"])


@pytest.mark.asyncio
@pytest.mark.parametrize("app_id", ["id", "whoami", "plugin"])
async def test_install_rejects_reserved_app_id(client, origin, app_id):
    body = install_http.confirmation(origin)
    body["app_id"] = app_id
    response = await install_http.post(client, body)
    assert response.status_code == 409, response.text
    assert not origin.tls.seen


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["http://plain.example", "https://example.test/path", "https://example.test:bad", "https://[malformed"])
async def test_install_rejects_malformed_or_non_https_origin(client, db, origin, invalid):
    await install_http.admin(db)
    body = install_http.confirmation(origin)
    body["origin"] = invalid
    response = await install_http.post(client, body)
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "origin_invalid"
    assert not origin.tls.seen


@pytest.mark.asyncio
async def test_conditional_update_repins_exact_bytes_and_selected_scopes(client, db, origin):
    await install_http.admin(db)
    first = await install_http.post(client, install_http.confirmation(origin))
    before = first.json()
    data = origin.manifest(version="2.0.0")
    origin.publish(data)
    body = {"app_id":"fixture", "origin":origin.url, "digest":install_http.digest(data),
            "granted_scopes":[], "expected_generation":before["generation"]}
    response = await install_http.post(client, body)
    assert response.status_code == 200, response.text
    assert response.json()["digest"] != before["digest"]
    assert response.json()["installation_id"] == before["installation_id"]
    assert response.json()["generation"] == before["generation"] + 1
    assert response.json()["granted_scopes"] == []


@pytest.mark.asyncio
async def test_a_key_id_cannot_be_rebound_to_another_did_from_new_origin_bytes(client, db, origin):
    import json

    from test_app_events_http import _make_app_keypair
    await install_http.admin(db)
    before = (await install_http.post(client, install_http.confirmation(origin))).json()
    document = json.loads(origin.manifest())
    document["app_keys"][0]["did_key"] = _make_app_keypair()[1]
    data = json.dumps(document).encode()
    origin.publish(data)
    response = await install_http.post(client, {"app_id":"fixture", "origin":origin.url, "digest":install_http.digest(data),
                                               "granted_scopes":[], "expected_generation":before["generation"]})
    assert response.status_code == 409, response.text
    assert await db.fetch_value("SELECT generation FROM {{tables.team_app_installs}}") == before["generation"]
    assert await db.fetch_value("SELECT digest FROM {{tables.team_app_installs}}") == before["digest"]

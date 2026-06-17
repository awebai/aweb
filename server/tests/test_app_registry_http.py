from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import aweb.routes.apps as apps_routes
from aweb.app_registry import install_app, reserved_app_ids
from aweb.internal_auth import build_internal_auth_header_value
from aweb.routes.apps import router as apps_router
from aweb.team_auth_deps import TeamIdentity

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
async def test_list_apps_empty_team_returns_empty_apps(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    app = _build_apps_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(f"/v1/apps/installed?team_id={TEAM_ID}")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"team_id": TEAM_ID, "apps": []}


@pytest.mark.asyncio
async def test_install_and_list_apps_returns_contract_shape(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    app = _build_apps_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        install_resp = await client.post(
            "/v1/apps/install",
            json={
                "app_id": "folio",
                "origin": "https://FOLIO.aweb.ai/",
                "app_version": "1.x",
                "manifest_version": 1,
                "digest": DIGEST_1,
                "granted_scopes": ["folio:write", "folio:read", "folio:write"],
            },
        )
        list_resp = await client.get(f"/v1/apps/installed?team_id={TEAM_ID}")

    assert install_resp.status_code == 200, install_resp.text
    assert install_resp.json() == {
        "app_id": "folio",
        "origin": "https://folio.aweb.ai",
        "app_version": "1.x",
        "manifest_version": 1,
        "digest": DIGEST_1,
        "granted_scopes": ["folio:read", "folio:write"],
    }
    assert list_resp.status_code == 200, list_resp.text
    assert list_resp.json() == {
        "team_id": TEAM_ID,
        "apps": [install_resp.json()],
    }


@pytest.mark.asyncio
async def test_zero_scope_install_remains_listed_with_empty_grants(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    app = _build_apps_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        install_resp = await client.post(
            "/v1/apps/install",
            json={
                "app_id": "folio",
                "origin": "https://folio.aweb.ai",
                "app_version": "1.x",
                "manifest_version": 1,
                "digest": DIGEST_1,
                "granted_scopes": [],
            },
        )
        list_resp = await client.get(f"/v1/apps/installed?team_id={TEAM_ID}")

    assert install_resp.status_code == 200, install_resp.text
    assert list_resp.status_code == 200, list_resp.text
    assert list_resp.json()["apps"] == [
        {
            "app_id": "folio",
            "origin": "https://folio.aweb.ai",
            "app_version": "1.x",
            "manifest_version": 1,
            "digest": DIGEST_1,
            "granted_scopes": [],
        }
    ]


@pytest.mark.asyncio
async def test_internal_gateway_auth_can_read_installed_apps(aweb_cloud_db, monkeypatch):
    app = _build_apps_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)
    await install_app(
        aweb_cloud_db.aweb_db,
        team_id=TEAM_ID,
        app_id="folio",
        origin="https://folio.aweb.ai",
        app_version="1.x",
        manifest_version=1,
        digest=DIGEST_1,
        granted_scopes=["folio:read"],
        installed_by_agent_id=str(AGENT_ID),
    )
    secret = "test-internal-secret"
    user_id = "00000000-0000-0000-0000-000000000999"
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)
    auth = build_internal_auth_header_value(
        secret=secret,
        team_id=TEAM_ID,
        principal_type="u",
        principal_id=user_id,
        actor_id=str(AGENT_ID),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            f"/v1/apps/installed?team_id={TEAM_ID}",
            headers={
                "X-AWEB-Auth": auth,
                "X-Team-ID": TEAM_ID,
                "X-User-ID": user_id,
                "X-AWEB-Actor-ID": str(AGENT_ID),
            },
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["apps"][0]["app_id"] == "folio"


def test_reserved_app_ids_are_loaded_from_cli_artifact():
    artifact = Path(__file__).resolve().parents[2] / "test-vectors" / "reserved-app-ids-v1.json"
    expected = set(json.loads(artifact.read_text())["reserved_app_ids"])

    assert reserved_app_ids() == expected
    assert "introspect" in reserved_app_ids()


@pytest.mark.asyncio
@pytest.mark.parametrize("app_id", ["mail", "doctor", "introspect"])
async def test_install_rejects_reserved_app_id(aweb_cloud_db, monkeypatch, app_id):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    app = _build_apps_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/apps/install",
            json={
                "app_id": app_id,
                "origin": f"https://{app_id}.example.com",
                "app_version": "1.0.0",
                "manifest_version": 1,
                "digest": DIGEST_1,
                "granted_scopes": [],
            },
        )

    assert resp.status_code == 409
    assert "reserved" in resp.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("origin", "detail_fragment"),
    [
        ("https://example.com:bad", "port"),
        ("https://example.com:99999", "port"),
        ("http://[::1", "origin URL"),
        ("http://[not-an-ip]", "origin URL"),
    ],
)
async def test_install_rejects_malformed_origin_parse_errors(
    aweb_cloud_db, monkeypatch, origin, detail_fragment
):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    app = _build_apps_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/apps/install",
            json={
                "app_id": "folio",
                "origin": origin,
                "app_version": "1.0.0",
                "manifest_version": 1,
                "digest": DIGEST_1,
                "granted_scopes": [],
            },
        )

    assert resp.status_code == 422
    assert detail_fragment in resp.json()["detail"]


@pytest.mark.asyncio
async def test_install_rejects_same_app_id_from_different_origin(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    app = _build_apps_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post(
            "/v1/apps/install",
            json={
                "app_id": "folio",
                "origin": "https://folio.aweb.ai",
                "app_version": "1.x",
                "manifest_version": 1,
                "digest": DIGEST_1,
                "granted_scopes": ["folio:read"],
            },
        )
        second = await client.post(
            "/v1/apps/install",
            json={
                "app_id": "folio",
                "origin": "https://evil.example.com",
                "app_version": "1.x",
                "manifest_version": 1,
                "digest": DIGEST_2,
                "granted_scopes": ["folio:read"],
            },
        )

    assert first.status_code == 200, first.text
    assert second.status_code == 409
    assert "different origin" in second.json()["detail"]


@pytest.mark.asyncio
async def test_reinstall_same_origin_repins_digest_and_scopes(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(apps_routes, "get_team_identity", _fake_team_identity)
    app = _build_apps_app(aweb_cloud_db.aweb_db)
    await _seed_team_and_agent(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/v1/apps/install",
            json={
                "app_id": "folio",
                "origin": "https://folio.aweb.ai",
                "app_version": "1.x",
                "manifest_version": 1,
                "digest": DIGEST_1,
                "granted_scopes": ["folio:read"],
            },
        )
        reinstall = await client.post(
            "/v1/apps/install",
            json={
                "app_id": "folio",
                "origin": "https://folio.aweb.ai",
                "app_version": "1.y",
                "manifest_version": 1,
                "digest": DIGEST_2,
                "granted_scopes": ["folio:read", "folio:write"],
            },
        )
        listed = await client.get(f"/v1/apps/installed?team_id={TEAM_ID}")

    assert reinstall.status_code == 200, reinstall.text
    assert listed.json()["apps"] == [
        {
            "app_id": "folio",
            "origin": "https://folio.aweb.ai",
            "app_version": "1.y",
            "manifest_version": 1,
            "digest": DIGEST_2,
            "granted_scopes": ["folio:read", "folio:write"],
        }
    ]

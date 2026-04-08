"""Tests for dashboard read endpoints (JWT-authenticated)."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import jwt
import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from aweb.routes.dashboard import router as dashboard_router

_JWT_SECRET = "test-dashboard-secret-at-least-32bytes!"


def _make_jwt(team_addresses: list[str], user_id: str = "user-123") -> str:
    return jwt.encode(
        {"user_id": user_id, "team_addresses": team_addresses, "exp": int(time.time()) + 3600},
        _JWT_SECRET,
        algorithm="HS256",
    )


class _FakeRegistryClient:
    def __init__(self, *, visibility: str = "private") -> None:
        self.visibility = visibility
        self.calls: list[tuple[str, str]] = []

    async def get_team(self, domain: str, name: str):
        self.calls.append((domain, name))
        return SimpleNamespace(
            team_id="team-1",
            domain=domain,
            name=name,
            display_name="",
            team_did_key="did:key:z6Mkteam",
            visibility=self.visibility,
            created_at="2026-04-08T00:00:00Z",
        )


class _FailingRegistryClient:
    async def get_team(self, domain: str, name: str):
        raise RuntimeError(f"registry unavailable for {domain}/{name}")


def _build_app(aweb_db, *, registry_client=None):
    app = FastAPI()
    app.include_router(dashboard_router)

    class _DbShim:
        def get_manager(self, name="aweb"):
            return aweb_db

    app.state.db = _DbShim()
    app.state.dashboard_jwt_secret = _JWT_SECRET
    if registry_client is not None:
        app.state.awid_registry_client = registry_client
    return app


async def _seed(aweb_db):
    """Create a team with agents, messages, tasks for dashboard testing."""
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ('acme.com/backend', 'acme.com', 'backend', 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
    )

    alice_id = uuid.uuid4()
    bob_id = uuid.uuid4()

    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_address, did_key, alias, lifetime, role, status)
        VALUES ($1, 'acme.com/backend', 'did:key:z6Mkalice', 'alice', 'persistent', 'developer', 'active'),
               ($2, 'acme.com/backend', 'did:key:z6Mkbob', 'bob', 'ephemeral', 'reviewer', 'active')
        """,
        alice_id, bob_id,
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (team_address, from_agent_id, to_agent_id, from_alias, to_alias, subject, body)
        VALUES ('acme.com/backend', $1, $2, 'alice', 'bob', 'Hello', 'Hi Bob!')
        """,
        alice_id, bob_id,
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (team_address, task_number, task_ref_suffix, title, status, priority, task_type)
        VALUES ('acme.com/backend', 1, 'aaaa', 'Fix bug', 'open', 2, 'task')
        """,
    )

    return str(alice_id), str(bob_id)


@pytest.mark.asyncio
async def test_list_agents(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["agents"]) == 2
    aliases = {a["alias"] for a in data["agents"]}
    assert aliases == {"alice", "bob"}


@pytest.mark.asyncio
async def test_agent_detail(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/agents/alice",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["alias"] == "alice"
    assert data["role"] == "developer"


@pytest.mark.asyncio
async def test_messages(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/messages",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["messages"]) == 1
    assert data["messages"][0]["subject"] == "Hello"


@pytest.mark.asyncio
async def test_tasks(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/tasks",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["tasks"]) == 1
    assert data["tasks"][0]["title"] == "Fix bug"


@pytest.mark.asyncio
async def test_unauthorized_team_returns_403(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    token = _make_jwt(["other.com/team"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_missing_token_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/teams/acme.com/backend/agents")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_public_team_allows_anonymous_dashboard_reads(aweb_cloud_db):
    registry_client = _FakeRegistryClient(visibility="public")
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=registry_client)
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/teams/acme.com/backend/agents")

    assert resp.status_code == 200
    assert len(resp.json()["agents"]) == 2
    assert registry_client.calls == [("acme.com", "backend")]


@pytest.mark.asyncio
async def test_private_team_with_valid_jwt_does_not_fail_on_registry_lookup_error(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=_FailingRegistryClient())
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert len(resp.json()["agents"]) == 2


@pytest.mark.asyncio
async def test_anonymous_request_fails_closed_when_registry_lookup_errors(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db, registry_client=_FailingRegistryClient())
    await _seed(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/teams/acme.com/backend/agents")

    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_usage_endpoint(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/usage",
            params={"team_address": "acme.com/backend"},
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["team_address"] == "acme.com/backend"
    assert data["messages_sent"] >= 1
    assert data["active_agents"] >= 2


@pytest.mark.asyncio
async def test_status_endpoint(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/status",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["team_address"] == "acme.com/backend"
    assert data["agent_count"] == 2


@pytest.mark.asyncio
async def test_roles_active_empty(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/roles/active",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert resp.json()["roles"] is None


@pytest.mark.asyncio
async def test_instructions_active_empty(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/instructions/active",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 200
    assert resp.json()["instructions"] is None


@pytest.mark.asyncio
async def test_agent_not_found_returns_404(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    await _seed(aweb_cloud_db.aweb_db)
    token = _make_jwt(["acme.com/backend"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/agents/nonexistent",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_expired_jwt_returns_401(aweb_cloud_db):
    app = _build_app(aweb_cloud_db.aweb_db)
    token = jwt.encode(
        {"user_id": "user-123", "team_addresses": ["acme.com/backend"], "exp": int(time.time()) - 3600},
        _JWT_SECRET,
        algorithm="HS256",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/teams/acme.com/backend/agents",
            headers={"X-Dashboard-Token": token},
        )

    assert resp.status_code == 401

"""Tests for GET /v1/agents endpoint and agent presence."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


async def _init_project(client: AsyncClient, slug: str, alias: str) -> dict:
    """Bootstrap a project + agent + API key via /v1/init."""
    resp = await client.post(
        "/v1/init",
        json={
            "project_slug": slug,
            "project_name": f"Project {slug}",
            "alias": alias,
            "human_name": f"Human {alias}",
            "agent_type": "agent",
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_list_agents_returns_project_agents(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-list", "alice-agent")
            api_key = data["api_key"]
            headers = {"Authorization": f"Bearer {api_key}"}

            # Add a second agent in the same project
            await _init_project(c, "test/agents-list", "bob-agent")

            resp = await c.get("/v1/agents", headers=headers)
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["project_id"] == data["project_id"]
            agents = body["agents"]
            assert len(agents) == 2
            aliases = {a["alias"] for a in agents}
            assert aliases == {"alice-agent", "bob-agent"}

            for agent in agents:
                assert "agent_id" in agent
                assert "alias" in agent
                assert "human_name" in agent
                assert "online" in agent


@pytest.mark.asyncio
async def test_list_agents_requires_auth(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/v1/agents")
            assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_agents_scoped_to_project(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            proj_a = await _init_project(c, "test/agents-scope-a", "alice-a")
            proj_b = await _init_project(c, "test/agents-scope-b", "alice-b")

            # Project A should only see its own agents
            resp = await c.get(
                "/v1/agents",
                headers={"Authorization": f"Bearer {proj_a['api_key']}"},
            )
            assert resp.status_code == 200
            agents = resp.json()["agents"]
            assert len(agents) == 1
            assert agents[0]["alias"] == "alice-a"

            # Project B should only see its own agents
            resp = await c.get(
                "/v1/agents",
                headers={"Authorization": f"Bearer {proj_b['api_key']}"},
            )
            assert resp.status_code == 200
            agents = resp.json()["agents"]
            assert len(agents) == 1
            assert agents[0]["alias"] == "alice-b"


@pytest.mark.asyncio
async def test_list_agents_without_redis_shows_offline(aweb_db_infra):
    """Without Redis, all agents should show as offline."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-no-redis", "alice-offline")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            resp = await c.get("/v1/agents", headers=headers)
            assert resp.status_code == 200
            agents = resp.json()["agents"]
            assert len(agents) == 1
            assert agents[0]["online"] is False
            assert agents[0].get("last_seen") is None


@pytest.mark.asyncio
async def test_list_agents_includes_access_mode(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-mode", "alice")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            resp = await c.get("/v1/agents", headers=headers)
            assert resp.status_code == 200
            agents = resp.json()["agents"]
            assert len(agents) == 1
            assert agents[0]["access_mode"] == "open"


@pytest.mark.asyncio
async def test_patch_agent_access_mode(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-patch", "alice")
            headers = {"Authorization": f"Bearer {data['api_key']}"}
            agent_id = data["agent_id"]

            resp = await c.patch(
                f"/v1/agents/{agent_id}",
                headers=headers,
                json={"access_mode": "contacts_only"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["access_mode"] == "contacts_only"

            # Verify via list
            list_resp = await c.get("/v1/agents", headers=headers)
            agents = list_resp.json()["agents"]
            assert agents[0]["access_mode"] == "contacts_only"


@pytest.mark.asyncio
async def test_patch_agent_invalid_access_mode(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-patch-inv", "alice")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            resp = await c.patch(
                f"/v1/agents/{data['agent_id']}",
                headers=headers,
                json={"access_mode": "invalid"},
            )
            assert resp.status_code == 422


@pytest.mark.asyncio
async def test_patch_agent_not_found(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-patch-nf", "alice")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            resp = await c.patch(
                f"/v1/agents/{uuid.uuid4()}",
                headers=headers,
                json={"access_mode": "contacts_only"},
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_agent_cross_project_rejected(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            proj_a = await _init_project(c, "test/agents-cross-a", "alice")
            proj_b = await _init_project(c, "test/agents-cross-b", "bob")

            resp = await c.patch(
                f"/v1/agents/{proj_a['agent_id']}",
                headers={"Authorization": f"Bearer {proj_b['api_key']}"},
                json={"access_mode": "contacts_only"},
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_agent_revert_to_open(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-revert", "alice")
            headers = {"Authorization": f"Bearer {data['api_key']}"}
            agent_id = data["agent_id"]

            # Set to contacts_only
            await c.patch(
                f"/v1/agents/{agent_id}",
                headers=headers,
                json={"access_mode": "contacts_only"},
            )

            # Revert to open
            resp = await c.patch(
                f"/v1/agents/{agent_id}",
                headers=headers,
                json={"access_mode": "open"},
            )
            assert resp.status_code == 200
            assert resp.json()["access_mode"] == "open"


@pytest.mark.asyncio
async def test_list_agents_hides_internal_by_default(aweb_db_infra):
    """Agents with agent_type='human' (internal auth bridge actors) are excluded by default."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-internal", "alice")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            # Manually insert an internal agent (agent_type='human')
            aweb_db = aweb_db_infra.get_manager("aweb")
            from uuid import UUID

            await aweb_db.execute(
                """
                INSERT INTO {{tables.agents}} (project_id, alias, human_name, agent_type)
                VALUES ($1, $2, $3, $4)
                """,
                UUID(data["project_id"]),
                "cowork-internal",
                "Internal Actor",
                "human",
            )

            # Default listing should hide the internal agent
            resp = await c.get("/v1/agents", headers=headers)
            assert resp.status_code == 200
            agents = resp.json()["agents"]
            aliases = {a["alias"] for a in agents}
            assert "alice" in aliases
            assert "cowork-internal" not in aliases


@pytest.mark.asyncio
async def test_list_agents_include_internal_shows_all(aweb_db_infra):
    """With include_internal=true, internal agents are included."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/agents-include", "alice")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            # Manually insert an internal agent
            aweb_db = aweb_db_infra.get_manager("aweb")
            from uuid import UUID

            await aweb_db.execute(
                """
                INSERT INTO {{tables.agents}} (project_id, alias, human_name, agent_type)
                VALUES ($1, $2, $3, $4)
                """,
                UUID(data["project_id"]),
                "cowork-internal",
                "Internal Actor",
                "human",
            )

            # With include_internal=true, both should appear
            resp = await c.get("/v1/agents", headers=headers, params={"include_internal": "true"})
            assert resp.status_code == 200
            agents = resp.json()["agents"]
            aliases = {a["alias"] for a in agents}
            assert "alice" in aliases
            assert "cowork-internal" in aliases

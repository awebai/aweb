"""Tests for the project status snapshot endpoint."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


def auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _init_project(c: AsyncClient, slug: str = "status-test", alias: str = "alice") -> dict:
    """Bootstrap a project and return the init response."""
    resp = await c.post("/v1/init", json={"project_slug": slug, "alias": alias})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_status_returns_agents(aweb_db_infra):
    """GET /v1/status returns the project's agents."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            resp = await c.get("/v1/status", headers=auth(info["api_key"]))
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["project_id"] == info["project_id"]
            assert len(body["agents"]) >= 1
            alice = next(a for a in body["agents"] if a["alias"] == "alice")
            assert "agent_id" in alice


@pytest.mark.asyncio
async def test_status_returns_claims(aweb_db_infra):
    """GET /v1/status includes active claims."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            api_key = info["api_key"]

            # Create and assign a task
            task = await c.post(
                "/v1/tasks",
                headers=auth(api_key),
                json={"title": "Do stuff"},
            )
            task_ref = task.json()["task_ref"]
            await c.patch(
                f"/v1/tasks/{task_ref}",
                headers=auth(api_key),
                json={"assignee_agent_id": info["agent_id"]},
            )

            resp = await c.get("/v1/status", headers=auth(api_key))
            body = resp.json()
            assert len(body["claims"]) == 1
            assert body["claims"][0]["title"] == "Do stuff"


@pytest.mark.asyncio
async def test_status_returns_active_policy(aweb_db_infra):
    """GET /v1/status includes active policy when set."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            api_key = info["api_key"]

            # Create and activate a policy
            pol = await c.post(
                "/v1/policies",
                headers=auth(api_key),
                json={"content": {"v": 1}},
            )
            policy_id = pol.json()["policy_id"]
            await c.post(f"/v1/policies/{policy_id}/activate", headers=auth(api_key))

            resp = await c.get("/v1/status", headers=auth(api_key))
            body = resp.json()
            assert body["active_policy"]["policy_id"] == policy_id
            assert body["active_policy"]["version"] == 1


@pytest.mark.asyncio
async def test_status_no_active_policy(aweb_db_infra):
    """GET /v1/status returns null active_policy when none set."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            resp = await c.get("/v1/status", headers=auth(info["api_key"]))
            body = resp.json()
            assert body["active_policy"] is None


@pytest.mark.asyncio
async def test_status_scoped_to_project(aweb_db_infra):
    """Status data is scoped to the caller's project."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info_a = await _init_project(c, slug="stat-a", alias="alice")
            info_b = await _init_project(c, slug="stat-b", alias="bob")

            resp_a = await c.get("/v1/status", headers=auth(info_a["api_key"]))
            resp_b = await c.get("/v1/status", headers=auth(info_b["api_key"]))

            agents_a = [a["alias"] for a in resp_a.json()["agents"]]
            agents_b = [a["alias"] for a in resp_b.json()["agents"]]
            assert "alice" in agents_a
            assert "bob" not in agents_a
            assert "bob" in agents_b
            assert "alice" not in agents_b

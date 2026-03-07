"""Tests for the claims query endpoint."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


def auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _init_project(c: AsyncClient, slug: str = "claims-test", alias: str = "alice") -> dict:
    """Bootstrap a project and return the init response."""
    resp = await c.post("/v1/init", json={"project_slug": slug, "alias": alias})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_claims_empty(aweb_db_infra):
    """GET /v1/claims returns empty list when no tasks are assigned."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            resp = await c.get("/v1/claims", headers=auth(info["api_key"]))
            assert resp.status_code == 200, resp.text
            assert resp.json()["claims"] == []


@pytest.mark.asyncio
async def test_claims_shows_assigned_tasks(aweb_db_infra):
    """GET /v1/claims returns tasks assigned to agents."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            api_key = info["api_key"]
            agent_id = info["agent_id"]

            # Create a task
            task_resp = await c.post(
                "/v1/tasks",
                headers=auth(api_key),
                json={"title": "Fix the bug"},
            )
            assert task_resp.status_code == 200, task_resp.text
            task_ref = task_resp.json()["task_ref"]

            # Assign to self
            patch = await c.patch(
                f"/v1/tasks/{task_ref}",
                headers=auth(api_key),
                json={"assignee_agent_id": agent_id},
            )
            assert patch.status_code == 200, patch.text

            # Query claims
            resp = await c.get("/v1/claims", headers=auth(api_key))
            assert resp.status_code == 200, resp.text
            claims = resp.json()["claims"]
            assert len(claims) == 1
            assert claims[0]["title"] == "Fix the bug"
            assert claims[0]["assignee_agent_id"] == agent_id
            assert claims[0]["assignee_alias"] == "alice"


@pytest.mark.asyncio
async def test_claims_excludes_closed_tasks(aweb_db_infra):
    """Closed tasks are not listed in claims."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            api_key = info["api_key"]

            # Create and assign a task
            task_resp = await c.post(
                "/v1/tasks",
                headers=auth(api_key),
                json={"title": "Close me"},
            )
            task_ref = task_resp.json()["task_ref"]
            await c.patch(
                f"/v1/tasks/{task_ref}",
                headers=auth(api_key),
                json={"assignee_agent_id": info["agent_id"]},
            )
            await c.patch(
                f"/v1/tasks/{task_ref}",
                headers=auth(api_key),
                json={"status": "in_progress"},
            )

            # Close it
            await c.patch(
                f"/v1/tasks/{task_ref}",
                headers=auth(api_key),
                json={"status": "closed"},
            )

            # Claims should be empty
            resp = await c.get("/v1/claims", headers=auth(api_key))
            assert resp.json()["claims"] == []


@pytest.mark.asyncio
async def test_claims_scoped_to_project(aweb_db_infra):
    """Claims from other projects are not visible."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info_a = await _init_project(c, slug="claims-a", alias="alice")
            info_b = await _init_project(c, slug="claims-b", alias="bob")

            # Create and assign a task in project A
            task = await c.post(
                "/v1/tasks",
                headers=auth(info_a["api_key"]),
                json={"title": "A's task"},
            )
            task_ref = task.json()["task_ref"]
            await c.patch(
                f"/v1/tasks/{task_ref}",
                headers=auth(info_a["api_key"]),
                json={"assignee_agent_id": info_a["agent_id"]},
            )

            # Project B should see no claims
            resp_b = await c.get("/v1/claims", headers=auth(info_b["api_key"]))
            assert resp_b.json()["claims"] == []

            # Project A should see one claim
            resp_a = await c.get("/v1/claims", headers=auth(info_a["api_key"]))
            assert len(resp_a.json()["claims"]) == 1

"""Tests for aweb agent lifecycle endpoints mounted through beadhub."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from beadhub.api import create_app
from beadhub.notifications import ensure_system_sender


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.asyncio
async def test_agent_log_endpoint_accessible(db_infra, redis_client_async):
    """GET /v1/agents/me/log returns the agent's audit log."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post(
                "/v1/init",
                json={
                    "project_slug": "lifecycle-log",
                    "alias": "log-agent",
                    "agent_type": "agent",
                },
            )
            assert init.status_code == 200, init.text
            api_key = init.json()["api_key"]

            resp = await client.get("/v1/agents/me/log", headers=_auth_headers(api_key))
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert "log" in data
            assert data["agent_id"] == init.json()["agent_id"]
            # Bootstrap creates a "create" log entry
            assert len(data["log"]) >= 1
            assert data["log"][0]["operation"] == "create"


@pytest.mark.asyncio
async def test_ephemeral_agent_deregister(db_infra, redis_client_async):
    """DELETE /v1/agents/me deregisters an ephemeral agent."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post(
                "/v1/init",
                json={
                    "project_slug": "lifecycle-dereg",
                    "alias": "dereg-agent",
                    "agent_type": "agent",
                    "lifetime": "ephemeral",
                },
            )
            assert init.status_code == 200, init.text
            api_key = init.json()["api_key"]

            resp = await client.delete("/v1/agents/me", headers=_auth_headers(api_key))
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["status"] == "deregistered"
            assert data["agent_id"] == init.json()["agent_id"]

            # Agent should no longer appear in the list (soft-deleted)
            list_resp = await client.get("/v1/agents", headers=_auth_headers(api_key))
            assert list_resp.status_code == 200, list_resp.text
            aliases = [a["alias"] for a in list_resp.json().get("agents", [])]
            assert "dereg-agent" not in aliases


@pytest.mark.asyncio
async def test_patch_agent_access_mode(db_infra, redis_client_async):
    """PATCH /v1/agents/me updates access_mode."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post(
                "/v1/init",
                json={
                    "project_slug": "lifecycle-patch",
                    "alias": "patch-agent",
                    "agent_type": "agent",
                },
            )
            assert init.status_code == 200, init.text
            api_key = init.json()["api_key"]

            resp = await client.patch(
                "/v1/agents/me",
                json={"access_mode": "contacts_only"},
                headers=_auth_headers(api_key),
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["access_mode"] == "contacts_only"

            # Verify persisted by reading agent list
            list_resp = await client.get("/v1/agents", headers=_auth_headers(api_key))
            assert list_resp.status_code == 200, list_resp.text
            agent = next(a for a in list_resp.json()["agents"] if a["alias"] == "patch-agent")
            assert agent["access_mode"] == "contacts_only"


@pytest.mark.asyncio
async def test_system_agent_excluded_from_listing(db_infra, redis_client_async):
    """GET /v1/agents should not include the system notification agent."""
    app = create_app(db_infra=db_infra, redis=redis_client_async, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post(
                "/v1/init",
                json={
                    "project_slug": "lifecycle-sysagent",
                    "alias": "real-agent",
                    "agent_type": "agent",
                },
            )
            assert init.status_code == 200, init.text
            api_key = init.json()["api_key"]
            project_id = init.json()["project_id"]

            # Create the system notification sender for this project
            await ensure_system_sender(db_infra, project_id)

            # GET /v1/agents should only show the real agent, not the system one
            resp = await client.get("/v1/agents", headers=_auth_headers(api_key))
            assert resp.status_code == 200, resp.text
            agents = resp.json()["agents"]
            agent_types = [a.get("agent_type") for a in agents]
            aliases = [a["alias"] for a in agents]
            assert (
                "system" not in agent_types
            ), f"System agent should be excluded from listing, got types: {agent_types}"
            assert (
                "system" not in aliases
            ), f"System alias should not appear in listing, got: {aliases}"

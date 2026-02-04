"""Tests for POST /v1/agents/heartbeat endpoint."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.presence import get_agent_presence


async def _init_project(client: AsyncClient, slug: str, alias: str) -> dict:
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
async def test_heartbeat_updates_presence(aweb_db_infra, async_redis):
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/heartbeat", "alice-hb")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            resp = await c.post("/v1/agents/heartbeat", headers=headers)
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["agent_id"] == data["agent_id"]
            assert "last_seen" in body
            assert body["ttl_seconds"] > 0

            # Verify presence was actually set in Redis
            presence = await get_agent_presence(async_redis, data["agent_id"])
            assert presence is not None
            assert presence["alias"] == "alice-hb"
            assert presence["agent_id"] == data["agent_id"]


@pytest.mark.asyncio
async def test_heartbeat_requires_auth(aweb_db_infra, async_redis):
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/v1/agents/heartbeat")
            assert resp.status_code == 401


@pytest.mark.asyncio
async def test_heartbeat_without_redis_still_succeeds(aweb_db_infra):
    """Heartbeat should succeed even without Redis (best-effort)."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/heartbeat-no-redis", "alice-nr")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            resp = await c.post("/v1/agents/heartbeat", headers=headers)
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["agent_id"] == data["agent_id"]


@pytest.mark.asyncio
async def test_heartbeat_makes_agent_online_in_listing(aweb_db_infra, async_redis):
    """After heartbeat, agent should show as online in GET /v1/agents."""
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            data = await _init_project(c, "test/heartbeat-online", "alice-on")
            headers = {"Authorization": f"Bearer {data['api_key']}"}

            # Before heartbeat: offline
            resp = await c.get("/v1/agents", headers=headers)
            assert resp.status_code == 200
            agents = resp.json()["agents"]
            assert len(agents) == 1
            assert agents[0]["online"] is False

            # Send heartbeat
            resp = await c.post("/v1/agents/heartbeat", headers=headers)
            assert resp.status_code == 200

            # After heartbeat: online
            resp = await c.get("/v1/agents", headers=headers)
            assert resp.status_code == 200
            agents = resp.json()["agents"]
            assert len(agents) == 1
            assert agents[0]["online"] is True
            assert agents[0]["last_seen"] is not None

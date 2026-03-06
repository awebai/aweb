from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")

    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "test-project",
        "Test Project",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_id,
        project_id,
        "agent-1",
        "Agent One",
        "agent",
    )

    api_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_id,
        api_key[:12],
        hash_api_key(api_key),
        True,
    )

    return {"api_key": api_key}


@pytest.mark.asyncio
async def test_version_header_present_when_env_set(aweb_db_infra, monkeypatch):
    monkeypatch.setenv("AWEB_LATEST_AW_VERSION", "v0.27.0")
    seeded = await _seed(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.headers.get("x-latest-client-version") == "v0.27.0"

            # Also present on authenticated endpoints
            resp = await client.get("/v1/tasks", headers=_auth_headers(seeded["api_key"]))
            assert resp.headers.get("x-latest-client-version") == "v0.27.0"


@pytest.mark.asyncio
async def test_version_header_absent_when_env_not_set(aweb_db_infra, monkeypatch):
    monkeypatch.delenv("AWEB_LATEST_AW_VERSION", raising=False)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
            assert "x-latest-client-version" not in resp.headers

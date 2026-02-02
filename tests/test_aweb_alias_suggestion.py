from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


@pytest.mark.asyncio
async def test_suggest_alias_prefix_for_missing_project_returns_alice(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/agents/suggest-alias-prefix",
                json={"project_slug": "test/suggest-missing"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["project_slug"] == "test/suggest-missing"
            assert data["project_id"] is None
            assert data["name_prefix"] == "alice"


@pytest.mark.asyncio
async def test_suggest_alias_prefix_skips_used_prefixes(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post(
                "/v1/init",
                json={
                    "project_slug": "test/suggest-used",
                    "project_name": "Test Suggest Used",
                    "alias": "alice-agent",
                    "human_name": "Alice",
                    "agent_type": "agent",
                },
            )
            assert init.status_code == 200, init.text

            resp = await client.post(
                "/v1/agents/suggest-alias-prefix",
                json={"project_slug": "test/suggest-used"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["project_id"] is not None
            assert data["name_prefix"] == "bob"


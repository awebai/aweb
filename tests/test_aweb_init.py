from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


@pytest.mark.asyncio
async def test_aweb_init_bootstraps_project_agent_and_key(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post(
                "/v1/init",
                json={
                    "project_slug": "test/aweb-init",
                    "project_name": "Test Aweb Init",
                    "alias": "test-agent",
                    "human_name": "Test Human",
                    "agent_type": "agent",
                },
            )
            assert init.status_code == 200, init.text
            data = init.json()
            assert data["status"] == "ok"
            assert data["project_id"]
            assert data["project_slug"] == "test/aweb-init"
            assert data["agent_id"]
            assert data["alias"] == "test-agent"
            assert data["api_key"].startswith("aw_sk_")

            api_key = data["api_key"]
            project_id = data["project_id"]

            introspect = await client.get(
                "/v1/auth/introspect",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert introspect.status_code == 200, introspect.text
            introspected = introspect.json()
            assert introspected["project_id"] == project_id
            assert introspected["agent_id"] == data["agent_id"]
            assert introspected["alias"] == "test-agent"

            current = await client.get(
                "/v1/projects/current",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert current.status_code == 200, current.text
            cur = current.json()
            assert cur["project_id"] == project_id
            assert cur["slug"] == "test/aweb-init"
            assert cur["name"] == "Test Aweb Init"

            init_again = await client.post(
                "/v1/init",
                json={
                    "project_slug": "test/aweb-init",
                    "project_name": "Should be ignored",
                    "alias": "test-agent",
                    "human_name": "Should be ignored",
                    "agent_type": "agent",
                },
            )
            assert init_again.status_code == 200, init_again.text
            again = init_again.json()
            assert again["project_id"] == project_id
            assert again["agent_id"] == data["agent_id"]


@pytest.mark.asyncio
async def test_aweb_init_allocates_alias_when_omitted(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            init = await client.post(
                "/v1/init",
                json={
                    "project_slug": "test/aweb-init-auto-alias",
                    "project_name": "Test Aweb Init Auto Alias",
                    "human_name": "Test Human",
                    "agent_type": "agent",
                },
            )
            assert init.status_code == 200, init.text
            data = init.json()
            assert data["alias"] == "alice"
            assert data["created"] is True


@pytest.mark.asyncio
async def test_aweb_init_allocates_next_alias_when_taken(aweb_db_infra):
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            first = await client.post(
                "/v1/init",
                json={
                    "project_slug": "test/aweb-init-auto-alias-next",
                    "project_name": "Test Aweb Init Auto Alias Next",
                    "alias": "alice-agent",
                    "human_name": "Test Human",
                    "agent_type": "agent",
                },
            )
            assert first.status_code == 200, first.text

            init = await client.post(
                "/v1/init",
                json={
                    "project_slug": "test/aweb-init-auto-alias-next",
                    "project_name": "Test Aweb Init Auto Alias Next",
                    "human_name": "Test Human 2",
                    "agent_type": "agent",
                },
            )
            assert init.status_code == 200, init.text
            data = init.json()
            # "alice" is treated as taken when any existing alias uses the "alice" prefix.
            assert data["alias"] == "bob"

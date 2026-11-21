"""The server against the AWID release production runs, as published.

The release runs in its own process on real PostgreSQL and Redis
(aweb_naapp_testing.production_registry); each registry read reaches it over
HTTP.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from nacl.signing import SigningKey
from redis.asyncio import Redis

from aweb.api import create_app
from aweb.db import DatabaseInfra
from aweb_naapp_testing.production_registry import running_production_registry
from awid.registry import RegistryClient
from awid_service.testing import REGISTRY_URL
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)


@asynccontextmanager
async def _member_of_a_team_on_the_production_release(shared_test_pool, test_db_factory):
    """The server, and alice, a member of a team published on the release."""
    team_name = f"prod-{uuid4().hex[:12]}"
    team_id = f"{team_name}:example.test"
    team_sk, _, team_did = _make_keypair()
    alice_sk, _, alice_did = _make_keypair()
    certificate = _make_certificate(team_sk, team_did, alice_did, team_id=team_id, alias="alice",
                                    identity_scope="local", certificate_id=f"prod-{uuid4().hex}")
    registry_db = await test_db_factory.create_db(suffix="production_awid")
    async with running_production_registry(registry_db.config.get_dsn()) as registry:
        await registry.add_team(team_id, team_did)
        await registry.add_certificate(certificate, team_key=SigningKey(team_sk))
        registry_client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        async with Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
                                  decode_responses=True) as redis:
            db = DatabaseInfra()
            await db.initialize(shared_pool=shared_test_pool)
            try:
                manager = db.get_manager("aweb")
                await manager.execute(
                    "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
                    "VALUES ($1, 'example.test', $2, $3)", team_id, team_name, team_did,
                )
                agent_id = uuid4()
                await manager.execute(
                    "INSERT INTO {{tables.agents}} "
                    "(agent_id, team_id, did_key, alias, identity_scope, inbound_mode) "
                    "VALUES ($1, $2, $3, 'alice', 'local', 'open')", agent_id, team_id, alice_did,
                )
                await manager.execute(
                    "INSERT INTO {{tables.workspaces}} (workspace_id, team_id, agent_id, alias) "
                    "VALUES ($1, $2, $3, 'alice')", uuid4(), team_id, agent_id,
                )
                app = create_app()
                app.state.db = db
                app.state.redis = redis
                app.state.awid_registry_client = registry_client
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                             base_url="http://aweb.test") as client:

                    async def list_agents() -> httpx.Response:
                        return await client.get("/v1/agents", headers=_signed_team_headers(
                            alice_sk, alice_did, team_id, _encode_certificate(certificate),
                        ))

                    yield SimpleNamespace(registry=registry, team_name=team_name,
                                          list_agents=list_agents)
            finally:
                await db.close()
                await registry_client.aclose()


@pytest.mark.asyncio
async def test_a_team_certificate_request_is_admitted_against_the_production_awid_release(
    shared_test_pool, test_db_factory,
):
    async with _member_of_a_team_on_the_production_release(shared_test_pool, test_db_factory) as world:
        response = await world.list_agents()
        team_reads = [call for call in world.registry.transport.calls
                      if call.url.path.startswith(f"/v1/namespaces/example.test/teams/{world.team_name}")]
    assert team_reads, "the server never read the team from the production release"
    assert response.status_code == 200, response.text
    assert [row["alias"] for row in response.json()["agents"]] == ["alice"]


@pytest.mark.asyncio
async def test_an_unreadable_production_awid_still_refuses_a_team_certificate_request(
    shared_test_pool, test_db_factory,
):
    async with _member_of_a_team_on_the_production_release(shared_test_pool, test_db_factory) as world:
        world.registry.transport.down = True
        response = await world.list_agents()
    assert response.status_code == 503, response.text

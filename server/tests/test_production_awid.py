"""The server against the AWID release production runs, as published.

The release runs in its own process on real PostgreSQL and Redis
(aweb_naapp_testing.production_registry); each registry read reaches it over
HTTP.
"""

from __future__ import annotations

import os
from uuid import uuid4

import httpx
import pytest
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


@pytest.mark.asyncio
async def test_a_team_certificate_request_is_admitted_against_the_production_awid_release(
    shared_test_pool, test_db_factory,
):
    team_name = f"prod-{uuid4().hex[:12]}"
    team_id = f"{team_name}:example.test"
    team_sk, _, team_did = _make_keypair()
    alice_sk, _, alice_did = _make_keypair()
    certificate = _make_certificate(team_sk, team_did, alice_did, team_id=team_id, alias="alice",
                                    identity_scope="local", certificate_id=f"prod-{uuid4().hex}")
    registry_db = await test_db_factory.create_db(suffix="production_awid")
    async with running_production_registry(registry_db.config.get_dsn()) as registry:
        await registry.add_team(team_id, team_did)
        await registry.add_certificate(certificate)
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
                    response = await client.get("/v1/agents", headers=_signed_team_headers(
                        alice_sk, alice_did, team_id, _encode_certificate(certificate),
                    ))
            finally:
                await db.close()
                await registry_client.aclose()
        team_reads = [call for call in registry.transport.calls
                      if call.url.path.startswith(f"/v1/namespaces/example.test/teams/{team_name}")]
    assert team_reads, "the server never read the team from the production release"
    assert response.status_code == 200, response.text
    assert [row["alias"] for row in response.json()["agents"]] == ["alice"]

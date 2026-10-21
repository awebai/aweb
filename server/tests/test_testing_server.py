"""aweb.testing: this server in library mode, in-process, for the tests of the
services that rely on it. It reaches AWID only through the transport it is
given; AWID_REGISTRY_URL names an address nothing listens on."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from awid_service.testing import SERVICE_TOKEN, running_registry
from redis.asyncio import Redis

from aweb.testing import running_server
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)

# The AWID client caches team keys in Redis, which other runs share.
TEAM_NAME = f"testing-{uuid4().hex[:12]}"
TEAM_ID = f"{TEAM_NAME}:testing.example"


@pytest_asyncio.fixture
async def stack(test_db_factory, monkeypatch):
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    monkeypatch.setenv("AWID_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("AWID_REGISTRY_URL", "http://127.0.0.1:9")
    awid_db = await test_db_factory.create_db(suffix="testing_awid")
    server_db = await test_db_factory.create_db(suffix="testing_aweb")
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    ) as redis:
        async with running_registry(awid_db.config.get_dsn(), redis=redis) as registry:
            async with running_server(
                server_db.config.get_dsn(), redis, awid_transport=registry.transport
            ) as server:
                yield SimpleNamespace(registry=registry, server=server)


@pytest.mark.asyncio
async def test_the_server_is_healthy_and_reached_through_its_transport(stack) -> None:
    async with stack.server.client() as client:
        health = await client.get("/health")
    assert health.status_code == 200, health.text
    assert health.json()["status"] == "ok"
    assert [request.url.path for request in stack.server.transport.calls] == ["/health"]
    assert stack.registry.transport.calls[0].url.path == "/health"


@pytest.mark.asyncio
async def test_a_member_connects_through_the_servers_own_route(stack) -> None:
    team_sk, _, team_did = _make_keypair()
    member_sk, _, member_did = _make_keypair()
    await stack.registry.add_team(TEAM_ID, team_did)
    cert = _make_certificate(team_sk, team_did, member_did, team_id=TEAM_ID, alias="alice")
    body = json.dumps({"hostname": "test-host"}).encode()
    headers = _signed_team_headers(member_sk, member_did, TEAM_ID, _encode_certificate(cert), body)
    async with stack.server.client() as client:
        connected = await client.post(
            "/v1/connect", content=body, headers={**headers, "Content-Type": "application/json"}
        )
    assert connected.status_code == 200, connected.text
    assert (connected.json()["team_id"], connected.json()["alias"]) == (TEAM_ID, "alice")
    assert f"/v1/namespaces/testing.example/teams/{TEAM_NAME}" in {
        request.url.path for request in stack.registry.transport.calls
    }

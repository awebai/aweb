"""The AWID transport a library-mode host gives the server.

AWID is its own app, in library mode on a test schema, reached in-process
through awid_service.testing's recording transport. ``AWID_REGISTRY_URL``
names an address nothing listens on, so a server that reached AWID any other
way would fail its startup check.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from awid.ratelimit import NoOpRateLimiter
from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app as create_registry_app
from awid_service.testing import ServiceTransport
from redis.asyncio import Redis

from aweb.api import create_app
from aweb.db import DatabaseInfra

UNREACHABLE_REGISTRY = "http://127.0.0.1:9"


@pytest_asyncio.fixture
async def awid(shared_test_pool, monkeypatch):
    # Both services read their settings even in library mode; the databases
    # they use are the ones given here.
    monkeypatch.setenv("AWID_DATABASE_URL", "postgresql://unused/test")
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    monkeypatch.setenv("AWID_REGISTRY_URL", UNREACHABLE_REGISTRY)
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    ) as redis:
        infra = AwidDatabaseInfra(schema="transport_registry")
        await infra.initialize(shared_pool=shared_test_pool)
        registry_app = create_registry_app(db_infra=infra, redis=redis, rate_limiter=NoOpRateLimiter())
        async with registry_app.router.lifespan_context(registry_app):
            yield SimpleNamespace(
                app=registry_app, db=infra.get_manager(), redis=redis, transport=ServiceTransport(registry_app)
            )


@pytest_asyncio.fixture
async def db_infra(shared_test_pool) -> DatabaseInfra:
    infra = DatabaseInfra()
    await infra.initialize(shared_pool=shared_test_pool)
    return infra


@pytest.mark.asyncio
async def test_a_library_mode_server_reaches_awid_through_the_given_transport(awid, db_infra) -> None:
    team_name = f"transport-{uuid4().hex[:12]}"
    await awid.db.execute(
        "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) "
        "VALUES ('example.test', $1, 'did:key:z6MkTransportTeam', 'public')",
        team_name,
    )
    app = create_app(db_infra=db_infra, redis=awid.redis, awid_transport=awid.transport)
    async with app.router.lifespan_context(app):
        assert [request.url.path for request in awid.transport.calls] == ["/health"]
        team = await app.state.awid_registry_client.get_team("example.test", team_name)
    assert team is not None and team.team_did_key == "did:key:z6MkTransportTeam"
    assert awid.transport.calls[-1].url.path == f"/v1/namespaces/example.test/teams/{team_name}"


@pytest.mark.asyncio
async def test_a_library_mode_server_does_not_start_when_its_awid_is_down(awid, db_infra) -> None:
    awid.transport.down = True
    app = create_app(db_infra=db_infra, redis=awid.redis, awid_transport=awid.transport)
    with pytest.raises(RuntimeError, match="Failed to reach AWID registry"):
        async with app.router.lifespan_context(app):
            pass
    assert [request.url.path for request in awid.transport.calls] == ["/health"]


class _RefusingRedis:
    async def ping(self):
        raise RuntimeError("redis refused")


@pytest.mark.asyncio
async def test_a_library_mode_server_starts_when_its_awid_answers_with_a_failed_dependency(
    awid, db_infra
) -> None:
    # The registry answers, so it is reached; its own Redis outage is not a
    # reason for this server to refuse to start.
    awid.app.state.redis = _RefusingRedis()
    app = create_app(db_infra=db_infra, redis=awid.redis, awid_transport=awid.transport)
    async with app.router.lifespan_context(app):
        assert [request.url.path for request in awid.transport.calls] == ["/health"]
    async with httpx.AsyncClient(transport=awid.transport, base_url="http://registry.test") as http:
        assert (await http.get("/health")).status_code == 503


@pytest.mark.asyncio
async def test_a_library_mode_server_does_not_start_on_a_503_that_is_not_a_health_report(
    awid, db_infra
) -> None:
    awid.transport.fault = lambda request, response: httpx.Response(503, json={"detail": "no backend"})
    app = create_app(db_infra=db_infra, redis=awid.redis, awid_transport=awid.transport)
    with pytest.raises(RuntimeError, match="Failed to reach AWID registry"):
        async with app.router.lifespan_context(app):
            pass


def test_a_standalone_server_refuses_a_transport(awid) -> None:
    with pytest.raises(ValueError):
        create_app(awid_transport=awid.transport)

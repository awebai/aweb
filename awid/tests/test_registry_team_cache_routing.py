"""Team read routing through public DNS, real AWID routes and shared Redis."""

from __future__ import annotations

import os
from contextlib import aclosing
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from awid.registry import CachedRegistryClient, RegistryError
from awid.registry_transport import RegistryOverrideTransport
from awid.signing import canonical_json_bytes, sign_message
from awid_service.testing import running_registry
from nacl.signing import SigningKey
from redis.asyncio import Redis
from test_registry_audience_dns import (
    AuthorityAnswer,
    registry_audience_dns as registry_audience_dns,
)
from test_testing_registry import _certificate, _did_key

DOMAIN = "example.com"
OVERRIDE, DEFAULT = "https://override.example", "https://api.awid.ai"


@pytest_asyncio.fixture
async def team_registries(test_db_factory, registry_audience_dns, monkeypatch):
    name = f"r2-{uuid4().hex}"
    team_id = f"{name}:{DOMAIN}"
    first_db = await test_db_factory.create_db(suffix="team_cache_first")
    second_db = await test_db_factory.create_db(suffix="team_cache_second")
    async with (
        Redis.from_url(os.environ["REDIS_URL"], decode_responses=True) as redis,
        running_registry(first_db.config.get_dsn(), redis=redis) as first,
        running_registry(second_db.config.get_dsn(), redis=redis) as second,
    ):
        keys = {}
        for registry, label in ((first, "first"), (second, "second")):
            team_key, member_key = SigningKey.generate(), SigningKey.generate()
            keys[label] = _did_key(team_key)
            await registry.add_team(team_id, keys[label])
            for kind in ("revoked", "active"):
                cert = _certificate(team_key, member_key, f"{label}-{kind}")
                cert.pop("signature")
                cert["team_id"] = team_id
                cert["signature"] = sign_message(
                    bytes(team_key), canonical_json_bytes(cert)
                )
                await registry.add_certificate(cert, team_key=team_key)
                if kind == "revoked":
                    await registry.revoke(f"{label}-revoked")
            registry.transport.calls.clear()

        async def deliver(_transport, request):
            # Substitute only the HTTP connection. Both origins still use
            # the SDK's public routing and the actual registry handlers.
            routes = {OVERRIDE: first, DEFAULT: second}
            origin = f"{request.url.scheme}://{request.url.netloc.decode()}"
            return await routes[origin].transport.handle_async_request(request)

        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", deliver)
        monkeypatch.setattr(RegistryOverrideTransport, "handle_async_request", deliver)
        async with aclosing(CachedRegistryClient(DEFAULT, redis)) as client:
            yield client, first, second, keys, name


@pytest.fixture
def cache_age(monkeypatch):
    # Advance the evidence clock while Redis retains the real cache entries.
    from awid import registry

    now = registry._cache_now
    offset = [0]
    monkeypatch.setattr(registry, "_cache_now", lambda: now() + offset[0])
    return offset


async def read_team(client, name):
    team = await client.get_team(DOMAIN, name)
    assert team is not None
    return (
        team.team_did_key,
        await client.get_team_public_key(DOMAIN, name),
        await client.get_team_revocations(DOMAIN, name),
        await client.get_team_revocations_for_certificates(
            DOMAIN, name, ["first-revoked", "second-revoked"]
        ),
        [
            cert.certificate_id
            for cert in await client.list_team_certificates(DOMAIN, name)
        ],
    )


def expected_team(key, label):
    return key, key, {f"{label}-revoked"}, {f"{label}-revoked"}, [f"{label}-active"]


@pytest.mark.asyncio
async def test_warm_team_reads_do_not_query_dns(team_registries, registry_audience_dns):
    client, first, second, keys, name = team_registries
    assert await read_team(client, name) == expected_team(keys["first"], "first")
    before_dns = list(registry_audience_dns.queries)
    before_http = list(first.transport.calls)
    assert before_dns and len(before_http) == 4
    # A different SDK instance proves the locator is in shared Redis.
    async with aclosing(CachedRegistryClient(DEFAULT, client.redis_client)) as reader:
        assert await read_team(reader, name) == expected_team(keys["first"], "first")
    assert registry_audience_dns.queries == before_dns
    assert first.transport.calls == before_http
    assert second.transport.calls == []


@pytest.mark.asyncio
async def test_dns_outage_uses_only_the_answering_origins_grace(
    team_registries, registry_audience_dns, cache_age
):
    client, first, second, keys, name = team_registries
    assert await client.get_team_public_key(DOMAIN, name) == keys["first"]
    assert await client.get_team_revocations(DOMAIN, name) == {"first-revoked"}
    queries = len(registry_audience_dns.queries)
    cache_age[0] = 180  # Outside freshness and stale-while-refresh, within grace.
    registry_audience_dns.answer = AuthorityAnswer.UNAVAILABLE
    assert await client.get_team_public_key(DOMAIN, name) == keys["first"]
    assert await client.get_team_revocations_for_certificates(
        DOMAIN, name, ["first-revoked", "second-revoked"]
    ) == {"first-revoked"}
    assert len(registry_audience_dns.queries) > queries
    assert len(first.transport.calls) == 2 and second.transport.calls == []

    # The same outage must not reset either fact's original age.
    cache_age[0] = 901
    second.transport.down = True
    with pytest.raises(RegistryError):
        await client.get_team_public_key(DOMAIN, name)
    with pytest.raises(RegistryError):
        await client.get_team_revocations(DOMAIN, name)


@pytest.mark.asyncio
async def test_team_reads_change_origins_only_after_freshness_expires(
    team_registries, registry_audience_dns, cache_age
):
    client, first, second, keys, name = team_registries
    assert await read_team(client, name) == expected_team(keys["first"], "first")
    registry_audience_dns.answer = AuthorityAnswer.PUBLIC_DEFAULT
    assert await read_team(client, name) == expected_team(keys["first"], "first")
    assert second.transport.calls == []

    cache_age[0] = 601
    assert await read_team(client, name) == expected_team(keys["second"], "second")
    assert len(first.transport.calls) == len(second.transport.calls) == 4


@pytest.mark.asyncio
async def test_failed_registry_read_does_not_install_a_warm_origin(
    team_registries, registry_audience_dns
):
    client, first, second, keys, name = team_registries
    first.transport.down = True
    with pytest.raises(RegistryError) as refused:
        await client.get_team_public_key(DOMAIN, name)
    assert refused.value.status_code == 503
    assert len(first.transport.calls) == 1 and second.transport.calls == []

    registry_audience_dns.answer = AuthorityAnswer.PUBLIC_DEFAULT
    assert await client.get_team_public_key(DOMAIN, name) == keys["second"]
    assert len(first.transport.calls) == len(second.transport.calls) == 1
    assert len(registry_audience_dns.queries) == 2

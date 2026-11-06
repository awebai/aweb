"""The public controller-key read shares revocation freshness/grace bounds."""

import json
import logging
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio

import awid.registry as registry_module
from awid.registry import CachedRegistryClient, RegistryError
from test_registry_client import FakeRedis, ScanUnavailableRedis


@pytest_asyncio.fixture
async def key_cache(monkeypatch):
    clock = [1_000_000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock[0])
    state = {"key": "did:key:old", "status": 200, "requests": 0}

    def handler(request):
        assert request.url.path == "/v1/namespaces/example.com/teams/backend"
        state["requests"] += 1
        clock[0] += state.get("advance", 0)
        if state["status"] != 200:
            return httpx.Response(state["status"], json={"detail": "registry unavailable"})
        return httpx.Response(200, json={
            "team_id": "backend:example.com", "domain": "example.com",
            "name": "backend", "team_did_key": state["key"], "created_at": "2026-01-01T00:00:00Z",
        })

    redis = FakeRedis()
    registry = CachedRegistryClient(
        registry_url="http://registry.test", redis_client=redis,
        transport=httpx.MockTransport(handler),
    )
    try:
        yield SimpleNamespace(clock=clock, state=state, redis=redis, registry=registry)
    finally:
        await registry.aclose()


async def _key(env):
    return await env.registry.get_team_public_key("example.com", "backend")


@pytest.mark.asyncio
async def test_key_is_fresh_for_revocation_ttl_then_refetched(key_cache):
    env = key_cache
    ttl = registry_module._TEAM_REVOCATIONS_CACHE_TTL_SECONDS
    assert ttl == 60
    assert await _key(env) == "did:key:old"
    env.state["key"] = "did:key:new"
    env.clock[0] += ttl - 1
    assert await _key(env) == "did:key:old"
    assert env.state["requests"] == 1
    env.clock[0] += 1
    assert await _key(env) == "did:key:new"
    assert env.state["requests"] == 2
    env.clock[0] += 1
    assert await _key(env) == "did:key:new"
    assert env.state["requests"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("age", [899, 900, 901])
async def test_key_outage_grace_is_bounded_by_original_fetch_age(key_cache, caplog, age):
    env = key_cache
    assert registry_module._TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS == 900
    assert await _key(env) == "did:key:old"
    cached_before = dict(env.redis.values)
    env.clock[0] += age
    env.state["status"] = 500
    with caplog.at_level(logging.WARNING):
        if age <= 900:
            assert await _key(env) == "did:key:old"
            assert "example.com/backend" in caplog.text
            assert f"aged {age}s" in caplog.text
            assert "registry unavailable" in caplog.text
        else:
            with pytest.raises(RegistryError):
                await _key(env)
    assert env.state["requests"] == 2
    assert env.redis.values == cached_before  # failed reads never renew grace


@pytest.mark.asyncio
async def test_key_outage_without_cached_authority_refuses(key_cache):
    key_cache.state["status"] = 500
    with pytest.raises(RegistryError):
        await _key(key_cache)


@pytest.mark.asyncio
async def test_failed_refresh_cannot_cross_grace_deadline(key_cache):
    env = key_cache
    assert await _key(env) == "did:key:old"
    env.clock[0] += 899
    env.state.update(status=500, advance=2)
    with pytest.raises(RegistryError):
        await _key(env)


@pytest.mark.asyncio
async def test_key_read_does_not_inherit_long_lived_metadata(key_cache):
    env = key_cache
    assert (await env.registry.get_team("example.com", "backend")).team_did_key == "did:key:old"
    env.state["key"] = "did:key:new"
    assert await _key(env) == "did:key:new"
    assert env.state["requests"] == 2


@pytest.mark.asyncio
async def test_key_not_found_is_not_cached_or_served_as_outage_grace(key_cache):
    env = key_cache
    env.state["status"] = 404
    assert await _key(env) is None
    assert env.redis.values == {}
    env.state["status"] = 200
    assert await _key(env) == "did:key:old"
    env.clock[0] += 61
    env.state["status"] = 404
    assert await _key(env) is None
    assert env.redis.values == {}
    env.state["status"] = 500
    with pytest.raises(RegistryError):
        await _key(env)
    assert env.state["requests"] == 4


@pytest.mark.asyncio
@pytest.mark.parametrize("scan_unavailable", [False, True])
async def test_certificate_cache_invalidation_clears_key_even_if_scan_fails(key_cache, scan_unavailable):
    env = key_cache
    if scan_unavailable:
        object.__setattr__(env.registry, "redis_client", ScanUnavailableRedis())
    assert await _key(env) == "did:key:old"
    env.state["key"] = "did:key:new"
    if scan_unavailable:
        with pytest.raises(OSError, match="Redis scan unavailable"):
            await env.registry.invalidate_team_certificate_cache("example.com", "backend")
    else:
        await env.registry.invalidate_team_certificate_cache("example.com", "backend")
    assert await _key(env) == "did:key:new"
    assert env.state["requests"] == 2


@pytest.mark.asyncio
async def test_key_retention_uses_revocation_grace_not_metadata_swr(key_cache):
    env = key_cache
    assert await _key(env) == "did:key:old"
    entry = next(iter(env.redis.values.values()))
    assert json.loads(entry)["fetched_at"] == env.clock[0]
    assert set(env.redis.expirations.values()) == {
        registry_module._TEAM_REVOCATIONS_CACHE_TTL_SECONDS
        + registry_module._TEAM_REVOCATIONS_OUTAGE_GRACE_SECONDS
    }

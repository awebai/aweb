"""Scoped status caching retains the server's existing revocation availability."""

import asyncio
import json

import httpx
import pytest

import awid.registry as registry_module
from awid.registry import CachedRegistryClient, RegistryError
from test_registry_client import FakeRedis


@pytest.fixture
def status_cache(monkeypatch):
    now, requests, status = [1000], [], [200]
    redis = FakeRedis()
    monkeypatch.setattr(registry_module, "_cache_now", lambda: now[0])

    async def upstream(request):
        requests.append(request)
        if status[0] != 200:
            return httpx.Response(status[0])
        ids = json.loads(request.content)["certificate_ids"]
        return httpx.Response(200, json={"certificates": [
            {"certificate_id": cid, "status": "revoked" if cid == "revoked" else "active",
             "team_id": "ops:example.com", "team_did_key": "current-controller", "revoked_at": None}
            for cid in ids
        ]})

    client = CachedRegistryClient("http://registry.test", redis, transport=httpx.MockTransport(upstream))
    return client, redis, now, requests, status


@pytest.mark.asyncio
async def test_warm_scoped_read_decodes_only_requested_ids_and_does_no_http(status_cache):
    client, redis, now, requests, _ = status_cache
    try:
        assert await client.get_team_revocations_for_certificates("example.com", "ops", ["active", "revoked"]) == {"revoked"}
        before = len(requests)
        assert await client.get_team_revocations_for_certificates("example.com", "ops", ["active"]) == set()
        assert len(requests) == before == 1
        assert all(len(value) < 512 for value in redis.values.values())
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_revocation_outage_keeps_original_age_and_900_second_bound(status_cache):
    client, redis, now, requests, status = status_cache
    try:
        assert await client.get_team_revocations_for_certificates("example.com", "ops", ["active"]) == set()
        original = dict(redis.values)
        status[0] = 503
        now[0] += 121
        assert await client.get_team_revocations_for_certificates("example.com", "ops", ["active"]) == set()
        assert redis.values == original
        now[0] = 1901
        with pytest.raises(RegistryError):
            await client.get_team_revocations_for_certificates("example.com", "ops", ["active"])
        assert redis.values == original
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_concurrent_misses_share_one_bounded_batch(status_cache):
    client, _, _, requests, _ = status_cache
    try:
        answers = await asyncio.gather(*[
            client.get_team_revocations_for_certificates("example.com", "ops", ["active", "revoked"])
            for _ in range(12)
        ])
        assert answers == [{"revoked"}] * 12
        assert len(requests) == 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_explicit_fresh_read_does_not_use_outage_grace(status_cache):
    client, _, _, _, status = status_cache
    try:
        assert await client.get_team_revocations_for_certificates("example.com", "ops", ["active"]) == set()
        status[0] = 503
        with pytest.raises(RegistryError):
            await client.get_team_revocations_for_certificates("example.com", "ops", ["active"], fresh=True)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_stale_serve_refreshes_once_and_auth_refusal_drops_the_entry(status_cache):
    client, redis, now, requests, status = status_cache
    try:
        await client.get_team_revocations_for_certificates("example.com", "ops", ["active"])
        now[0] += 61
        status[0] = 403
        assert await client.get_team_revocations_for_certificates("example.com", "ops", ["active"]) == set()
        tasks = set(client._refresh_tasks.values())
        await asyncio.gather(*tasks, return_exceptions=True)
        with pytest.raises(RegistryError) as error:
            await client.get_team_revocations_for_certificates("example.com", "ops", ["active"])
        assert error.value.status_code == 403
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_registration_reuses_the_observation_without_importing_revocation_grace(status_cache):
    client, _, now, requests, status = status_cache
    try:
        assert await client.get_team_revocations_for_certificates("example.com", "ops", ["active"]) == set()
        assert await client.get_team_registrations_for_certificates("example.com", "ops", ["active"]) == {"active"}
        assert len(requests) == 1
        status[0] = 503
        now[0] += 1201
        with pytest.raises(RegistryError):
            await client.get_team_registrations_for_certificates("example.com", "ops", ["active"])
    finally:
        await client.aclose()

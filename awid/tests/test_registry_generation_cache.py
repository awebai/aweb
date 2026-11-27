"""R9: invalidation cannot scan unrelated Redis keys or revive old evidence."""

import asyncio
import copy
import json
import os
import time
import uuid

import httpx
import pytest
from redis.asyncio import Redis

from awid.registry import CachedRegistryClient, RegistryClient, RegistryError
from test_id_status_client import (
    BUNDLE,
    DOMAIN,
    SUBJECT,
    _evidence,
    _fixture,
    env as env,
)


@pytest.mark.asyncio
async def test_id_invalidation_uses_no_keyspace_scan(env):
    calls = []

    async def scan_iter(**kwargs):
        calls.append(kwargs)
        for key in list(env.redis.values):
            yield key

    env.redis.scan_iter = scan_iter
    await _evidence(env)
    await env.client._invalidate_id_status_cache(DOMAIN)
    env.status[DOMAIN] = _fixture("alice-revoked-now")
    assert (await _evidence(env)).status == env.status[DOMAIN]
    assert calls == []


@pytest.mark.asyncio
async def test_generation_loss_never_reuses_retained_evidence(env):
    await _evidence(env)
    # Keep every evidence entry, lose only its generation metadata.
    generation_keys = [
        key for key in env.redis.values if key.startswith("awid:cache_generation:")
    ]
    assert generation_keys
    await env.redis.delete(*generation_keys)
    env.status[DOMAIN] = _fixture("alice-revoked-now")
    assert (await _evidence(env)).status == env.status[DOMAIN]
    assert len(env.requests) == 2


@pytest.mark.asyncio
async def test_inflight_pre_invalidation_response_does_not_poison_next_read(env):
    acquired, release = asyncio.Event(), asyncio.Event()
    old = copy.deepcopy(env.status[DOMAIN])

    async def delayed(request):
        acquired.set()
        await release.wait()
        return httpx.Response(200, json=old)

    first = CachedRegistryClient(
        "http://registry.test",
        env.redis,
        transport=httpx.MockTransport(delayed),
        domain_registry_resolver=env.route,
        domain_verifier=env.verify_domain,
    )
    task = asyncio.create_task(first.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN))
    try:
        await asyncio.wait_for(acquired.wait(), 1)
        await env.client._invalidate_id_status_cache(DOMAIN)
        await env.client._invalidate_id_status_cache(DOMAIN)
        env.status[DOMAIN] = _fixture("alice-revoked-now")
        release.set()
        await task
        assert (await _evidence(env)).status == env.status[DOMAIN]
    finally:
        release.set()
        await task
        await first.aclose()


@pytest.mark.asyncio
async def test_two_registry_origins_do_not_share_status_cache(env):
    await _evidence(env)
    expected = _fixture("alice-revoked-now")

    async def handler(request):
        return httpx.Response(200, json=expected)

    other = CachedRegistryClient(
        "http://other-registry.test",
        env.redis,
        transport=httpx.MockTransport(handler),
        domain_registry_resolver=lambda _domain: asyncio.sleep(
            0, result="http://other-registry.test"
        ),
        domain_verifier=env.verify_domain,
    )
    try:
        assert (
            await other.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)
        ).status == expected
    finally:
        await other.aclose()


@pytest.mark.asyncio
async def test_lost_mutation_reply_rotates_the_generation_again(env, monkeypatch):
    await _evidence(env)
    generations = []

    async def committed_but_reply_lost(self, *args, **kwargs):
        generations.append(env.redis.values[self._id_status_generation_key(DOMAIN)])
        # Another read can finish between the pre-write fence and the commit.
        await _evidence(env)
        env.status[DOMAIN] = _fixture("alice-revoked-now")
        raise RegistryError("reply lost", status_code=503)

    monkeypatch.setattr(
        RegistryClient, "register_id_certificate", committed_but_reply_lost
    )
    with pytest.raises(RegistryError, match="reply lost"):
        await env.client.register_id_certificate(
            BUNDLE, signer=None, expected_head=None, invitation_id=None
        )
    assert (
        env.redis.values[env.client._id_status_generation_key(DOMAIN)] != generations[0]
    )
    assert (await _evidence(env)).status == env.status[DOMAIN]


@pytest.mark.asyncio
async def test_address_and_certificate_generation_scopes_are_isolated(env):
    client = env.client
    key = client._team_certificates_generation_key(DOMAIN, "team")
    other = client._team_certificates_generation_key(DOMAIN, "other")
    address = client._address_generation_key(DOMAIN, client.registry_url)
    original = [
        await client._generation_cache_key("data", scope)
        for scope in (key, other, address)
    ]
    await client._invalidate_team_certificate_cache_keys(DOMAIN, "team")
    current = [
        await client._generation_cache_key("data", scope)
        for scope in (key, other, address)
    ]
    assert current[0] != original[0]
    assert current[1:] == original[1:]
    await client._invalidate_address_cache(domain=DOMAIN, name="agent", did_aws=[])
    assert await client._generation_cache_key("data", address) != current[2]


class CountedRedis(Redis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.commands = []

    async def execute_command(self, *args, **kwargs):
        self.commands.append(str(args[0]).upper())
        return await super().execute_command(*args, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("unrelated", [0, 10_000, 1_000_000])
async def test_real_redis_invalidation_cost_is_independent_of_keyspace(unrelated):
    """Same production invalidator before/after; no simulated Redis cost."""
    redis = CountedRedis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    )
    prefix = f"r9-cost:{uuid.uuid4().hex}:"
    domain = f"{uuid.uuid4().hex}.example"
    client = CachedRegistryClient("http://registry.test", redis)
    try:
        for start in range(0, unrelated, 5_000):
            await redis.mset(
                {
                    f"{prefix}{i}": "x"
                    for i in range(start, min(start + 5_000, unrelated))
                }
            )
        redis.commands.clear()
        started = time.perf_counter()
        await client._invalidate_id_status_cache(domain)
        elapsed = time.perf_counter() - started
        observed = {
            "unrelated": unrelated,
            "commands": len(redis.commands),
            "scan": redis.commands.count("SCAN"),
            "elapsed_seconds": elapsed,
        }
        print("R9_COST " + json.dumps(observed, sort_keys=True), flush=True)
        assert observed["scan"] == 0
        assert observed["commands"] <= 2
    finally:
        for start in range(0, unrelated, 5_000):
            await redis.delete(
                *(f"{prefix}{i}" for i in range(start, min(start + 5_000, unrelated)))
            )
        await client.aclose()
        await redis.aclose()

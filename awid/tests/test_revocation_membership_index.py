"""The complete CRL is evidence; a derived index cannot authorize alone."""

import json
import os
import time
import tracemalloc
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

import awid.registry as registry_module
from awid import revocation_cache
from awid.registry import CachedRegistryClient, RegistryError


class CountedRedis(Redis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.commands = []
        self.payload_bytes = 0

    async def execute_command(self, *args, **kwargs):
        self.commands.append(str(args[0]).upper())
        result = await super().execute_command(*args, **kwargs)

        def size(value):
            if isinstance(value, (str, bytes)):
                return len(value)
            if isinstance(value, (tuple, list)):
                return sum(size(item) for item in value)
            return 0

        self.payload_bytes += size(result)
        return result


@pytest_asyncio.fixture
async def crl(monkeypatch):
    clock, calls, upstream = [1000], [], [200, {"revoked"}]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock[0])
    redis = CountedRedis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    )
    domain = uuid4().hex + ".example"

    def registry(request):
        assert request.method == "GET" and request.url.path.endswith("/revocations")
        calls.append(request)
        return httpx.Response(
            upstream[0],
            json={
                "revocations": [{"certificate_id": cid} for cid in sorted(upstream[1])],
                "has_more": False,
            },
        )

    client = CachedRegistryClient(
        "http://registry.test", redis, transport=httpx.MockTransport(registry)
    )
    key = client._team_revocations_cache_key(domain, "ops")
    env = SimpleNamespace(
        client=client,
        redis=redis,
        domain=domain,
        clock=clock,
        calls=calls,
        upstream=upstream,
        key=key,
        index=key + ":membership",
        meta=key + ":membership-meta",
    )
    try:
        yield env
    finally:
        await redis.delete(env.key, env.index, env.meta)
        await client.aclose()
        await redis.aclose()


async def selected(env, ids=("active", "revoked"), *, fresh=False):
    return await env.client.get_team_revocations_for_certificates(
        env.domain, "ops", list(ids), fresh=fresh
    )


async def publish(env, values):
    await env.client._write_cache_entry(
        env.key, value=set(values), ttl_seconds=60, retention_seconds=960, encode=sorted
    )


@pytest.mark.asyncio
async def test_first_warm_membership_read_uses_the_current_crl_key_index(crl):
    # Populate through the real SDK key builder and its ordinary complete-list
    # path. The FIRST subsequent member check must use the index; a fallback
    # that repairs an unindexed v2 entry would hide a broken publish classifier.
    assert await crl.client.get_team_revocations(crl.domain, "ops") == {"revoked"}
    crl.redis.commands.clear()
    assert await selected(crl) == {"revoked"}
    assert crl.redis.commands == ["EVAL"]
    assert len(crl.calls) == 1
    assert await crl.redis.exists(crl.index, crl.meta) == 2


@pytest.mark.asyncio
async def test_complete_list_stamp_and_index_publish_with_one_expiry(crl):
    await publish(crl, {"revoked"})
    assert await selected(crl) == {"revoked"}
    assert await crl.redis.pexpiretime(crl.index) <= await crl.redis.pexpiretime(
        crl.key
    )
    assert await crl.redis.pexpiretime(crl.meta) <= await crl.redis.pexpiretime(crl.key)
    # A new complete set in the SAME clock second cannot reuse an old index.
    await publish(crl, {"active"})
    assert await selected(crl) == {"active"}
    assert json.loads(await crl.redis.get(crl.key))["fetched_at"] == 1000
    assert crl.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    ["missing", "expired", "wrong_type", "version", "old_writer", "list_missing"],
)
async def test_broken_index_uses_complete_list_never_false_nonrevocation(crl, fault):
    await publish(crl, {"revoked"})
    assert await selected(crl) == {"revoked"}
    if fault == "missing":
        await crl.redis.delete(crl.index)
    elif fault == "expired":
        await crl.redis.pexpire(crl.index, 0)
    elif fault == "wrong_type":
        await crl.redis.set(crl.index, "not-a-membership-set")
    elif fault == "version":
        meta = json.loads(await crl.redis.get(crl.meta))
        meta["prefix"] = "not-the-list-version"
        await crl.redis.set(crl.meta, json.dumps(meta), ex=960)
    elif fault == "old_writer":
        await crl.redis.set(
            crl.key,
            json.dumps({"fetched_at": 1000, "fresh_until": 1060, "value": ["active"]}),
            ex=960,
        )
    else:
        await crl.redis.delete(crl.key)
    assert await selected(crl) == ({"active"} if fault == "old_writer" else {"revoked"})
    assert len(crl.calls) == (1 if fault == "list_missing" else 0)


@pytest.mark.asyncio
async def test_upgrade_backfill_keeps_original_fetch_age_and_remaining_expiry(crl):
    await crl.redis.set(
        crl.key,
        json.dumps({"fetched_at": 980, "fresh_until": 1040, "value": ["revoked"]}),
        px=123456,
    )
    original_expiry = await crl.redis.pexpiretime(crl.key)
    assert await selected(crl) == {"revoked"}
    stored = json.loads(await crl.redis.get(crl.key))
    assert (stored["fetched_at"], stored["fresh_until"]) == (980, 1040)
    assert await crl.redis.pexpiretime(crl.index) <= original_expiry
    assert await crl.redis.pexpiretime(crl.key) <= original_expiry
    assert crl.calls == []


@pytest.mark.asyncio
async def test_outage_preserves_original_age_and_explicit_fresh_never_uses_grace(crl):
    await publish(crl, {"revoked"})
    original = await crl.redis.get(crl.meta)
    crl.upstream[0] = 503
    crl.clock[0] = 1121
    assert await selected(crl) == {"revoked"}
    assert await crl.redis.get(crl.meta) == original
    with pytest.raises(RegistryError):
        await selected(crl, fresh=True)
    crl.clock[0] = 1901
    with pytest.raises(RegistryError):
        await selected(crl)
    assert await crl.redis.get(crl.meta) == original


@pytest.mark.asyncio
async def test_explicit_invalidation_and_authorization_refusal_remove_every_derived_key(
    crl,
):
    await publish(crl, {"revoked"})
    assert await selected(crl) == {"revoked"}
    await crl.client.invalidate_team_certificate_cache(crl.domain, "ops")
    assert await crl.redis.exists(crl.key, crl.index, crl.meta) == 0
    await publish(crl, {"revoked"})
    crl.clock[0] = 1121
    crl.upstream[0] = 403
    with pytest.raises(RegistryError) as error:
        await selected(crl)
    assert error.value.status_code == 403
    assert await crl.redis.exists(crl.key, crl.index, crl.meta) == 0


@pytest.mark.asyncio
async def test_old_backfill_cannot_restore_a_concurrently_replaced_complete_list(crl):
    await publish(crl, {"revoked"})
    old = await crl.client._read_cache_entry(crl.key, decode=set)
    await publish(crl, {"active"})
    assert not await revocation_cache.publish(
        crl.redis, crl.key, old["payload"], retention_seconds=960, expected=old["raw"]
    )
    assert await selected(crl) == {"active"}


@pytest.mark.asyncio
async def test_corrupt_empty_prefix_never_allows_an_index_without_its_list(crl):
    await publish(crl, {"revoked"})
    meta = json.loads(await crl.redis.get(crl.meta))
    meta["prefix"] = ""
    await crl.redis.set(crl.meta, json.dumps(meta), ex=960)
    await crl.redis.delete(crl.key)
    crl.upstream[1] = {"active"}
    assert await selected(crl) == {"active"}
    assert len(crl.calls) == 1


@pytest.mark.asyncio
async def test_r9_generation_change_discards_index_and_team_invalidation_discards_all(
    crl,
):
    await publish(crl, {"revoked"})
    await crl.client._invalidate_team_certificate_cache_keys(crl.domain, "ops")
    assert await crl.redis.exists(crl.key) == 1
    assert await crl.redis.exists(crl.index, crl.meta) == 0
    assert await selected(crl) == {"revoked"}
    assert crl.calls == []
    await crl.client._invalidate_team_cache(crl.domain, "ops")
    assert await crl.redis.exists(crl.key, crl.index, crl.meta) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("history", [0, 1000, 100000])
async def test_real_redis_membership_work_does_not_materialize_history(crl, history):
    values = {f"revoked-{n}" for n in range(history)}
    wanted = ["active", "revoked-0", f"revoked-{history - 1}"]
    await publish(crl, values)
    assert await selected(crl, wanted) == values.intersection(wanted)

    async def measure(indexed):
        crl.redis.commands.clear()
        crl.redis.payload_bytes = 0
        tracemalloc.start()
        started = time.perf_counter()
        for _ in range(16):
            result = (
                await selected(crl, wanted)
                if indexed
                else (
                    await crl.client.get_team_revocations(crl.domain, "ops")
                ).intersection(wanted)
            )
            assert result == values.intersection(wanted)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return {
            "commands": len(crl.redis.commands),
            "returned_payload_bytes": crl.redis.payload_bytes,
            "peak_traced_bytes": peak,
            "seconds": elapsed,
        }

    before, after = await measure(False), await measure(True)
    print(
        "R8_CRL_COST "
        + json.dumps(
            {"history": history, "before": before, "after": after}, sort_keys=True
        ),
        flush=True,
    )
    assert after["returned_payload_bytes"] < 16 * 2048
    assert len(crl.calls) == 0

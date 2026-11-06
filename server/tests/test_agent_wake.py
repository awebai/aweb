"""Agent wakes: post-commit scope, counted publication with retry, process-wide hub.

Everything runs against the real Redis. Link faults are real: a TCP proxy in
front of Redis is cut, so the code under test sees a real connection failure.
"""

from __future__ import annotations

import asyncio
import logging
import os
from uuid import uuid4

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from aweb.agent_wake import (
    AgentWakeHub,
    AgentWakePublisher,
    agent_wake_key,
    agent_wake_scope,
    did_wake_key,
    read_wake_marks,
    record_agent_wake,
    team_room_wake_key,
    wake_kinds_for_key,
)
from tests.redis_fault_proxy import RedisFaultProxy

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest_asyncio.fixture
async def redis():
    async with Redis.from_url(REDIS_URL, decode_responses=True) as client:
        yield client


@pytest_asyncio.fixture
async def proxy():
    proxy = RedisFaultProxy(REDIS_URL)
    await proxy.start()
    yield proxy
    await proxy.stop()


@pytest_asyncio.fixture
async def hub(redis):
    hub = AgentWakeHub(redis)
    await hub.start()
    yield hub
    await hub.close()


@pytest_asyncio.fixture
async def publisher(redis):
    publisher = AgentWakePublisher(redis)
    yield publisher
    await publisher.close()


def _did_key() -> str:
    return did_wake_key(f"did:key:z6Mk{uuid4().hex}")


def _publication_failed(caplog) -> bool:
    return any(
        r.getMessage().startswith("Agent wake publication failed; retrying")
        for r in caplog.records
    )


async def _next_batch(subscription, timeout=2.0):
    await asyncio.wait_for(subscription.wait(), timeout)
    return subscription.take()


def test_wake_keys_name_the_predicate_the_snapshot_filters_on():
    assert did_wake_key("did:aw:abc") == "did:did:aw:abc"
    assert agent_wake_key("4c0a") == "agent:4c0a"
    assert team_room_wake_key("backend:acme.com") == "team-room:backend:acme.com"
    assert wake_kinds_for_key(did_wake_key("did:aw:abc")) == ("mail", "chat")
    assert wake_kinds_for_key(agent_wake_key("4c0a")) == ("control", "app")
    assert wake_kinds_for_key(team_room_wake_key("t")) == ("room",)


@pytest.mark.asyncio
async def test_scope_publishes_after_exit_and_counts_the_key(redis, hub, publisher):
    key = _did_key()
    async with hub.subscribe([key]) as subscription:
        before = await read_wake_marks(redis, [key])
        with agent_wake_scope(publisher):
            record_agent_wake(key, "mail")
            await asyncio.sleep(0.2)
            assert subscription.take().kinds == set()
        batch = await _next_batch(subscription)
    assert batch.kinds == {"mail"}
    assert batch.resync is False
    after = await read_wake_marks(redis, [key])
    assert after[(key, "mail")] != before[(key, "mail")]
    assert after[(key, "chat")] == before[(key, "chat")]


@pytest.mark.asyncio
async def test_nested_scope_records_into_the_outermost_scope(hub, publisher):
    key = _did_key()
    async with hub.subscribe([key]) as subscription:
        with agent_wake_scope(publisher):
            with agent_wake_scope(publisher):
                record_agent_wake(key, "chat")
            await asyncio.sleep(0.2)
            assert subscription.take().kinds == set()
            record_agent_wake(key, "mail")
        batch = await _next_batch(subscription)
    assert batch.kinds == {"chat", "mail"}


@pytest.mark.asyncio
async def test_scope_left_by_an_exception_still_publishes(redis, hub, publisher):
    # The write may have committed before the exception; a spurious wake
    # costs one snapshot, a lost one costs the reconcile bound.
    key = _did_key()
    async with hub.subscribe([key]) as subscription:
        with pytest.raises(RuntimeError):
            with agent_wake_scope(publisher):
                record_agent_wake(key, "mail")
                raise RuntimeError("failed after commit")
        batch = await _next_batch(subscription)
    assert batch.kinds == {"mail"}
    assert (await read_wake_marks(redis, [key]))[(key, "mail")] is not None


@pytest.mark.asyncio
async def test_record_outside_a_scope_is_logged_and_dropped(redis, caplog):
    key = _did_key()
    with caplog.at_level(logging.WARNING, logger="aweb.agent_wake"):
        record_agent_wake(key, "mail")
    assert [r.getMessage() for r in caplog.records] == [
        f"Agent wake {key} (mail) recorded outside a wake scope; it is not published"
    ]
    assert (await read_wake_marks(redis, [key]))[(key, "mail")] is None


@pytest.mark.asyncio
async def test_scope_without_publisher_drops_wakes_quietly(redis, caplog):
    key = _did_key()
    with caplog.at_level(logging.WARNING, logger="aweb.agent_wake"):
        with agent_wake_scope(None):
            record_agent_wake(key, "mail")
    assert caplog.records == []
    assert (await read_wake_marks(redis, [key]))[(key, "mail")] is None


@pytest.mark.asyncio
async def test_failed_publication_is_retried_until_redis_returns(redis, hub, proxy, caplog):
    key = _did_key()
    faulty = Redis.from_url(proxy.url, decode_responses=True, socket_timeout=1, socket_connect_timeout=1)
    publisher = AgentWakePublisher(faulty)
    try:
        async with hub.subscribe([key]) as subscription:
            proxy.cut()
            with caplog.at_level(logging.WARNING, logger="aweb.agent_wake"):
                with agent_wake_scope(publisher):
                    record_agent_wake(key, "mail")
                for _ in range(200):
                    if _publication_failed(caplog):
                        break
                    await asyncio.sleep(0.1)
            assert _publication_failed(caplog)
            assert subscription.take().kinds == set()
            assert (await read_wake_marks(redis, [key]))[(key, "mail")] is None
            proxy.restore()
            batch = await _next_batch(subscription, timeout=8.0)
        assert batch.kinds == {"mail"}
        assert (await read_wake_marks(redis, [key]))[(key, "mail")] is not None
    finally:
        await publisher.close()
        await faulty.aclose()


@pytest.mark.asyncio
async def test_hub_resubscribes_after_losing_redis_and_asks_for_resync(redis, proxy, publisher):
    key = _did_key()
    link = Redis.from_url(proxy.url, decode_responses=True, socket_connect_timeout=1)
    hub = AgentWakeHub(link)
    await hub.start()
    try:
        async with hub.subscribe([key]) as subscription:
            proxy.cut()
            await asyncio.sleep(0.3)
            proxy.restore()
            batch = await _next_batch(subscription, timeout=8.0)
            assert batch.resync is True
            with agent_wake_scope(publisher):
                record_agent_wake(key, "chat")
            batch = await _next_batch(subscription)
            assert batch.kinds == {"chat"}
            assert batch.resync is False
    finally:
        await hub.close()
        await link.aclose()


@pytest.mark.asyncio
async def test_subscription_is_live_when_subscribe_returns(hub, publisher):
    key = _did_key()
    async with hub.subscribe([key]) as subscription:
        with agent_wake_scope(publisher):
            record_agent_wake(key, "mail")
        batch = await _next_batch(subscription)
    assert batch.kinds == {"mail"}


@pytest.mark.asyncio
async def test_streams_share_channels_and_release_them_on_exit(redis, hub, publisher):
    key = _did_key()
    channel = f"agent-wake:{key}"
    async with hub.subscribe([key]) as first:
        async with hub.subscribe([key]) as second:
            with agent_wake_scope(publisher):
                record_agent_wake(key, "mail")
            assert (await _next_batch(first)).kinds == {"mail"}
            assert (await _next_batch(second)).kinds == {"mail"}
            assert dict(await redis.pubsub_numsub(channel))[channel] == 1
        assert dict(await redis.pubsub_numsub(channel))[channel] == 1
    for _ in range(20):
        if dict(await redis.pubsub_numsub(channel))[channel] == 0:
            break
        await asyncio.sleep(0.05)
    assert dict(await redis.pubsub_numsub(channel))[channel] == 0


@pytest.mark.asyncio
async def test_marks_expire_so_redis_keeps_no_key_per_identity_forever(redis, publisher):
    key = _did_key()
    with agent_wake_scope(publisher):
        record_agent_wake(key, "mail")
    for _ in range(40):
        if (await read_wake_marks(redis, [key]))[(key, "mail")] is not None:
            break
        await asyncio.sleep(0.05)
    ttl = await redis.ttl(f"agent-mark:mail:{key}")
    assert 86000 < ttl <= 86400


@pytest.mark.asyncio
async def test_close_flushes_wakes_still_pending_at_shutdown(redis, hub, proxy):
    key = _did_key()
    link = Redis.from_url(proxy.url, decode_responses=True, socket_timeout=1, socket_connect_timeout=1)
    publisher = AgentWakePublisher(link)
    try:
        # The subscriber stands for a surviving process.
        async with hub.subscribe([key]) as subscription:
            proxy.cut()
            with agent_wake_scope(publisher):
                record_agent_wake(key, "mail")
            await asyncio.sleep(0.3)
            assert subscription.take().kinds == set()
            proxy.restore()
            started = asyncio.get_running_loop().time()
            await publisher.close()
            assert asyncio.get_running_loop().time() - started < 2.5
            batch = await _next_batch(subscription)
        assert batch.kinds == {"mail"}
        assert (await read_wake_marks(redis, [key]))[(key, "mail")] is not None
    finally:
        await link.aclose()


@pytest.mark.asyncio
async def test_close_gives_up_on_unreachable_redis_within_its_bound(proxy, caplog):
    key = _did_key()
    link = Redis.from_url(proxy.url, decode_responses=True, socket_timeout=1, socket_connect_timeout=1)
    publisher = AgentWakePublisher(link)
    try:
        proxy.cut()
        with agent_wake_scope(publisher):
            record_agent_wake(key, "mail")
        await asyncio.sleep(0.2)
        started = asyncio.get_running_loop().time()
        with caplog.at_level(logging.WARNING, logger="aweb.agent_wake"):
            await publisher.close()
        assert asyncio.get_running_loop().time() - started < 3.0
        assert any(
            "unpublished at shutdown" in r.getMessage() for r in caplog.records
        )
    finally:
        await link.aclose()


@pytest.mark.asyncio
async def test_publisher_runs_no_task_while_nothing_is_pending(redis, hub):
    key = _did_key()
    publisher = AgentWakePublisher(redis)
    async with hub.subscribe([key]) as subscription:
        with agent_wake_scope(publisher):
            record_agent_wake(key, "mail")
        assert (await _next_batch(subscription)).kinds == {"mail"}
    await asyncio.sleep(0.05)
    assert publisher._task is not None and publisher._task.done()
    await publisher.close()

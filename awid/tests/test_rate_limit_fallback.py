"""Real refused Redis connections retain a bounded per-process limit."""

import asyncio
import logging
import socket

import pytest
from redis.asyncio import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry

from awid.ratelimit import RedisFixedWindowRateLimiter


@pytest.mark.asyncio
@pytest.mark.parametrize("concurrency", [1, 61])
async def test_real_redis_outage_keeps_per_process_limits_and_actionable_error(
    caplog, concurrency
):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        async with Redis(
            host="127.0.0.1",
            port=reserved.getsockname()[1],
            socket_connect_timeout=0.1,
            socket_timeout=0.1,
            retry=Retry(NoBackoff(), 0),
        ) as redis:
            limiter = RedisFixedWindowRateLimiter(redis=redis)
            caplog.set_level(logging.ERROR, logger="awid.ratelimit")

            async def hit():
                return await limiter.hit(
                    bucket="did_key",
                    key="private-test-reader",
                    limit=60,
                    window_seconds=3600,
                )

            if concurrency == 1:
                decisions = [await hit() for _ in range(61)]
            else:
                decisions = await asyncio.gather(*(hit() for _ in range(concurrency)))
    assert sum(decision.allowed for decision in decisions) == 60
    assert sum(not decision.allowed for decision in decisions) == 1
    assert min(decision.remaining for decision in decisions) == 0
    assert limiter.is_degraded
    assert limiter.health_name == "MemoryFixedWindowRateLimiter"
    failures = [record for record in caplog.records if record.levelno == logging.ERROR]
    assert len(failures) == 1
    assert failures[0].getMessage() == (
        "AWID Redis rate limiting is unavailable; using bounded per-process limits. "
        "Restore Redis connectivity to restore shared limits."
    )


@pytest.mark.asyncio
async def test_memory_window_pruning_does_not_reset_a_longer_bucket(monkeypatch):
    from awid.ratelimit import MemoryFixedWindowRateLimiter

    now = 0.0
    # Time is the input to this pure counter rule; no registry or decision is replaced.
    monkeypatch.setattr("awid.ratelimit.time.time", lambda: now)
    limiter = MemoryFixedWindowRateLimiter()
    first = await limiter.hit(
        bucket="hourly", key="reader", limit=1, window_seconds=3600
    )
    assert first.allowed
    now = 61.0
    await limiter.hit(bucket="minute", key="reader", limit=60, window_seconds=60)
    second = await limiter.hit(
        bucket="hourly", key="reader", limit=1, window_seconds=3600
    )
    assert not second.allowed
    assert second.reset_epoch_seconds == first.reset_epoch_seconds == 3600

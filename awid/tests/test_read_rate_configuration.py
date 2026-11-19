"""R7 capacity sizing uses the real limiter; writes keep their original budget."""

import os
import uuid

import httpx
import pytest
from fastapi import Depends, FastAPI
from redis.asyncio import Redis

from awid.ratelimit import MemoryFixedWindowRateLimiter, RedisFixedWindowRateLimiter, rate_limit_dep
from awid_service.config import get_settings


def test_read_limits_are_loaded_at_startup(monkeypatch):
    monkeypatch.setenv("AWID_READ_RATE_LIMITS", '{"id_certificate_status":600,"certificate_status":120}')
    assert get_settings().read_rate_limits == {"id_certificate_status":600,"certificate_status":120}


@pytest.mark.parametrize("raw", ['[]', '{', '{"team_create":100}', '{"unknown":1}',
                                 '{"id_certificate_status":true}', '{"id_certificate_status":0}',
                                 '{"id_certificate_status":-1}', '{"id_certificate_status":2.5}'])
def test_bad_read_limit_configuration_refuses_startup(monkeypatch, raw):
    monkeypatch.setenv("AWID_READ_RATE_LIMITS", raw)
    with pytest.raises(ValueError, match="AWID_READ_RATE_LIMITS"):
        get_settings()


def probe_app(limiter):
    app = FastAPI()
    app.state.rate_limiter = limiter
    app.state.awid_read_rate_limits = {"id_certificate_status":2}

    @app.get("/probe", dependencies=[Depends(rate_limit_dep("id_certificate_status"))])
    def probe():
        return {"ok": True}

    return app


async def exercise(limiter):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=probe_app(limiter)),
                                base_url="http://testserver") as client:
        responses = [await client.get("/probe") for _ in range(3)]
    return responses


@pytest.mark.asyncio
async def test_configured_read_budget_is_enforced_by_the_real_dependency():
    responses = await exercise(MemoryFixedWindowRateLimiter())
    assert [r.status_code for r in responses] == [200,200,429]
    assert responses[-1].headers["X-RateLimit-Limit"] == "2"
    assert int(responses[-1].headers["Retry-After"]) >= 0


@pytest.mark.asyncio
async def test_real_redis_read_budget_uses_the_same_configuration():
    redis = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    # A unique bucket key keeps the fixed-window script real and isolated.
    class ScopedLimiter(RedisFixedWindowRateLimiter):
        async def hit(self, **kwargs):
            return await super().hit(**(kwargs | {"key": unique}))

    unique = uuid.uuid4().hex
    try:
        responses = await exercise(ScopedLimiter(redis=redis))
        assert [r.status_code for r in responses] == [200,200,429]
    finally:
        await redis.aclose()

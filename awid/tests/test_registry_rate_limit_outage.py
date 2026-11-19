"""An actual unreachable Redis must not turn public registry reads into 500s."""

from __future__ import annotations

import logging
import socket
from contextlib import aclosing

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.ratelimit import RedisFixedWindowRateLimiter
from awid.registry import RegistryClient
from awid_service.main import create_app
from redis.asyncio import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry


@pytest.mark.asyncio
async def test_real_redis_connection_failure_keeps_bounded_reads_and_reports_degraded(
    awid_db_infra,
    caplog,
):
    # Own the socket throughout: nothing else can claim it, and it has no
    # listener. Redis itself must encounter the real connection refusal.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        async with Redis(
            host="127.0.0.1",
            port=port,
            socket_connect_timeout=0.2,
            socket_timeout=0.2,
            retry=Retry(NoBackoff(), 0),
        ) as redis:
            limiter = RedisFixedWindowRateLimiter(redis=redis)
            app = create_app(db_infra=awid_db_infra, redis=redis, rate_limiter=limiter)
            caplog.set_level(logging.ERROR, logger="awid.ratelimit")
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://registry.test",
                ) as client:
                    # Register through the real client during the outage;
                    # positive reads retain the normal rate-limit headers.
                    seed, public_key = generate_keypair()
                    did_key = did_from_public_key(public_key)
                    async with aclosing(
                        RegistryClient(
                            registry_url="http://registry.test",
                            transport=httpx.ASGITransport(app=app),
                        )
                    ) as registry:
                        mapping = await registry.register_did(did_key, seed)
                    reset = None
                    served = 0
                    for _ in range(122):
                        response = await client.get(f"/v1/did/{mapping.did_aw}/key")
                        next_reset = response.headers.get("X-RateLimit-Reset")
                        assert next_reset is not None, response.text
                        if next_reset != reset:
                            reset, served = next_reset, 0
                        if response.status_code == 429:
                            assert served == 60
                            assert response.headers["X-RateLimit-Remaining"] == "0"
                            assert "Retry-After" in response.headers
                            break
                        assert response.status_code == 200, response.text
                        assert response.json()["current_did_key"] == did_key
                        served += 1
                        assert (
                            int(response.headers["X-RateLimit-Remaining"])
                            == 60 - served
                        )
                    else:
                        pytest.fail(
                            "Unreachable Redis left the public read rate limit unenforced"
                        )
                    health = await client.get("/health")
                    assert health.status_code == 200, health.text
                    assert health.json()["status"] == "degraded"
                    assert health.json()["checks"]["database"] == "ok"
                    assert (
                        health.json()["checks"]["rate_limiter"]
                        == "MemoryFixedWindowRateLimiter"
                    )
                    assert (await client.get("/live")).status_code == 200
            assert any(
                record.levelno == logging.ERROR
                and "Restore Redis connectivity to restore shared limits."
                in record.getMessage()
                for record in caplog.records
            )

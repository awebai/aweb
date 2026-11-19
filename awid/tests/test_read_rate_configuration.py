"""Read budgets reach the registry's routes through both startup modes."""

import logging
import os
import uuid
from contextlib import AsyncExitStack

import httpx
import pytest
from redis.asyncio import Redis

from awid_service.config import get_settings
from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app
from conftest import build_signed_headers


def test_read_limits_are_parsed_from_the_environment(monkeypatch):
    monkeypatch.setenv("AWID_READ_RATE_LIMITS", '{"id_certificate_status":600,"certificate_status":120}')
    assert get_settings().read_rate_limits == {"id_certificate_status": 600, "certificate_status": 120}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        "[]", "{", '{"team_create":100}', '{"unknown":1}',
        '{"id_certificate_status":true}', '{"id_certificate_status":0}',
        '{"id_certificate_status":-1}', '{"id_certificate_status":2.5}',
    ],
)
async def test_bad_read_limit_configuration_refuses_startup(monkeypatch, raw):
    monkeypatch.setenv("AWID_READ_RATE_LIMITS", raw)
    app = create_app()
    with pytest.raises(ValueError, match="AWID_READ_RATE_LIMITS"):
        async with app.router.lifespan_context(app):
            pytest.fail("Registry started with invalid read budgets")


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["standalone", "library"])
@pytest.mark.parametrize("backend", ["memory", "redis"])
async def test_real_registry_startup_applies_read_budgets_without_changing_writes(
    test_db_factory, controller_identity, monkeypatch, mode, backend,
):
    db = await test_db_factory.create_db(suffix="read_budgets")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("AWID_DATABASE_URL", db.config.get_dsn())
    monkeypatch.setenv("AWID_REDIS_URL", redis_url)
    monkeypatch.setenv("AWID_RATE_LIMIT_BACKEND", backend)
    monkeypatch.setenv("AWID_READ_RATE_LIMITS", '{"namespace_get":2}')
    monkeypatch.delenv("AWID_RATE_LIMIT_DISABLED", raising=False)
    monkeypatch.delenv("AWID_SERVICE_TOKEN", raising=False)

    # The ASGI peer address isolates the production limiter's bucket, without a
    # replacement key extractor or limiter. Namespace state comes from its API.
    ip = "127." + ".".join(str(n) for n in uuid.uuid4().bytes[:3])
    signing_key, controller_did = controller_identity
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    async with Redis.from_url(redis_url, decode_responses=True) as redis:
        await redis.ping()
        try:
            async with AsyncExitStack() as resources:
                if mode == "library":
                    infra = AwidDatabaseInfra(schema="awid")
                    resources.push_async_callback(infra.close)
                    await infra.initialize()
                    app = create_app(db_infra=infra, redis=redis)
                else:
                    app = create_app()
                await resources.enter_async_context(app.router.lifespan_context(app))
                client = await resources.enter_async_context(httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app, client=(ip, 12345)),
                    base_url="http://testserver",
                ))

                async def register_namespace():
                    return await client.post(
                        "/v1/namespaces", json={"domain": "local"},
                        headers=build_signed_headers(
                            signing_key, controller_did, domain="local", operation="register",
                        ),
                    )

                registered = await register_namespace()
                assert registered.status_code == 200, registered.text
                namespace = registered.json()
                assert namespace["domain"] == "local"
                assert namespace["controller_did"] == controller_did
                assert registered.headers["X-RateLimit-Limit"] == "10"
                assert registered.headers["X-RateLimit-Remaining"] == "9"

                for remaining in (1, 0):
                    read = await client.get("/v1/namespaces/local")
                    assert read.status_code == 200, read.text
                    assert read.json() == namespace
                    assert read.headers["X-RateLimit-Limit"] == "2"
                    assert read.headers["X-RateLimit-Remaining"] == str(remaining)
                limited = await client.get("/v1/namespaces/local")
                assert limited.status_code == 429
                assert limited.json() == {"detail": "rate limit exceeded"}
                assert limited.headers["X-RateLimit-Limit"] == "2"
                assert int(limited.headers["Retry-After"]) >= 0

                # Saturating one configured read bucket leaves other reads and
                # the released write budget intact, including real signed writes.
                listed = await client.get("/v1/namespaces")
                assert listed.status_code == 200, listed.text
                assert listed.json()["namespaces"] == [namespace]
                assert listed.headers["X-RateLimit-Limit"] == "30"
                for remaining in (8, 7):
                    repeated = await register_namespace()
                    assert repeated.status_code == 200, repeated.text
                    assert repeated.json() == namespace
                    assert repeated.headers["X-RateLimit-Limit"] == "10"
                    assert repeated.headers["X-RateLimit-Remaining"] == str(remaining)
        finally:
            owned = [key async for key in redis.scan_iter(match=f"aweb:rl:*:{ip}:*")]
            if owned:
                await redis.delete(*owned)
            # Standalone startup owns logging; restore the caller's handlers
            # after its real lifespan has stopped, including on a test failure.
            standalone_handlers = [handler for handler in root.handlers if handler not in handlers]
            root.handlers[:] = handlers
            root.setLevel(level)
            for handler in standalone_handlers:
                handler.close()

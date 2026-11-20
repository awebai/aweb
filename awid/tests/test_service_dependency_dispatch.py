"""State getters must not queue behind unrelated synchronous application work.

The small ASGI app below tests dependency dispatch only. The registry case uses
the real registry routes, SDK controller signatures and PostgreSQL fixture.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio.to_thread
import pytest
from fastapi import Depends, FastAPI
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.dns_verify import verify_domain
from awid.registry import RegistryClient, RegistryError
from awid_service.deps import get_db, get_domain_verifier, get_redis
from awid_service.testing import REGISTRY_URL, ServiceTransport, running_registry


@asynccontextmanager
async def occupied_thread_pool() -> AsyncIterator[None]:
    """Hold the actual shared worker token until the request has finished."""
    limiter = anyio.to_thread.current_default_thread_limiter()
    original_capacity = limiter.total_tokens
    assert limiter.borrowed_tokens == 0
    limiter.total_tokens = 1
    started = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()

    def unrelated_sync_work() -> None:
        loop.call_soon_threadsafe(started.set)
        release.wait()

    worker = asyncio.create_task(anyio.to_thread.run_sync(unrelated_sync_work))
    try:
        async with asyncio.timeout(5):
            await started.wait()
        assert limiter.borrowed_tokens == limiter.total_tokens == 1
        yield
    finally:
        release.set()
        try:
            async with asyncio.timeout(5):
                await worker
            assert limiter.borrowed_tokens == 0
            assert limiter.statistics().tasks_waiting == 0
        finally:
            limiter.total_tokens = original_capacity


@pytest.mark.asyncio
@pytest.mark.parametrize("dependency", [get_db, get_redis, get_domain_verifier])
async def test_state_getter_does_not_consume_thread_capacity(dependency) -> None:
    app = FastAPI()
    app.state.db = object()
    app.state.redis = object()
    expected = {
        get_db: app.state.db,
        get_redis: app.state.redis,
        get_domain_verifier: verify_domain,
    }[dependency]

    @app.get("/health")
    async def read_state(value: Any = Depends(dependency)) -> dict[str, bool]:
        return {"same_owner": value is expected}

    client = RegistryClient(
        registry_url=REGISTRY_URL,
        transport=ServiceTransport(app),
        timeout_seconds=0.1,
    )
    try:
        async with occupied_thread_pool():
            assert await client.health() == {"same_owner": True}
            assert anyio.to_thread.current_default_thread_limiter().borrowed_tokens == 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_registered_team_setup_does_not_queue_for_a_worker(
    test_db_factory,
) -> None:
    database = await test_db_factory.create_db(suffix="awid_thread_dispatch")
    team_key = SigningKey.generate()
    team_did = did_from_public_key(bytes(team_key.verify_key))
    async with running_registry(database.config.get_dsn()) as registry:
        controller = await registry.ensure_namespace(domain="example.com")
        client = RegistryClient(registry_url=REGISTRY_URL, transport=registry.transport)
        try:
            async with occupied_thread_pool():
                # The same signed POST and default five-second SDK budget used
                # by Registry.add_team, which failed before admission on R15.
                await client.register_team(
                    domain="example.com",
                    name="backend",
                    display_name="backend",
                    team_did_key=team_did,
                    visibility="public",
                    namespace_controller_signing_key=bytes(controller),
                )
                assert (
                    await client.get_team_public_key("example.com", "backend")
                    == team_did
                )
                with pytest.raises(RegistryError) as refused:
                    await client.register_team(
                        domain="example.com",
                        name="stranger",
                        display_name="stranger",
                        team_did_key=team_did,
                        visibility="public",
                        namespace_controller_signing_key=bytes(SigningKey.generate()),
                    )
                assert refused.value.status_code == 403
                assert (
                    refused.value.detail
                    == "Only the namespace controller can manage teams"
                )
                assert (
                    await client.get_team_public_key("example.com", "stranger") is None
                )
                assert (
                    anyio.to_thread.current_default_thread_limiter().borrowed_tokens
                    == 1
                )
        finally:
            await client.aclose()
        writes = [
            (call.method, call.url.path)
            for call in registry.transport.calls
            if call.method == "POST"
        ]
        assert writes == [
            ("POST", "/v1/namespaces"),
            ("POST", "/v1/namespaces/example.com/teams"),
            ("POST", "/v1/namespaces/example.com/teams"),
        ]

"""Cache-free and cached evidence through the actual AWID routes and database."""

import asyncio
import copy
from contextlib import aclosing
import os

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

import awid.registry as registry_module
from awid.id_certificates import verify_id_chain
from awid.registry import CachedRegistryClient, RegistryClient
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid_service.deps import get_domain_verifier
from awid_service.main import create_app
from awid_service.testing import ServiceTransport
from id_tree_support import Tree, VECTORS, at, did_aw, did_key

DOMAIN = "example.com"
SUBJECT = {"id": did_aw("global_agent"), "did_key": did_key("global_agent")}
BUNDLE = {
    "v": 1,
    "type": "aweb.id-chain",
    "certificates": [
        copy.deepcopy(VECTORS["certificates"][name]["signed"])
        for name in ("alice", "global-agent")
    ],
}


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def live_registry(awid_db_infra, manual_clock):
    redis = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    app = create_app(
        db_infra=awid_db_infra, redis=redis, rate_limiter=MemoryFixedWindowRateLimiter()
    )
    app.state.id_tree_clock = manual_clock
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as service:
                service.app = app
                tree = Tree(service, manual_clock)
                tree.clock.now = at("2026-10-26T00:00:00Z")
                await tree.root()
                for identity in ("alice", "global_agent"):
                    await tree.vector_did(identity)
                await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
                await tree.enroll(
                    "alice", "global-agent", when=at("2026-10-26T00:04:00Z")
                )
                tree.clock.now = at("2026-10-26T00:30:00Z")
                yield app, redis
    finally:
        await redis.aclose()


async def test_base_client_acquires_real_evidence_without_redis(live_registry):
    app, _ = live_registry
    async with aclosing(
        RegistryClient(
            "http://testserver",
            transport=httpx.ASGITransport(app=app),
            domain_verifier=app.dependency_overrides[get_domain_verifier](),
        )
    ) as client:
        evidence = await client.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)
    assert evidence.age_seconds >= 1
    assert verify_id_chain(
        BUNDLE, subject=SUBJECT, evidence=evidence, domain=DOMAIN
    ) == {
        "outcome": "nearest_human",
        "human_id": did_aw("alice"),
        "identity_valid": True,
        "kind": "agent",
        "reason": "verified",
    }


async def test_live_and_cached_acquisition_have_identical_evidence_and_start_age(
    live_registry, monkeypatch
):
    app, redis = live_registry
    now = [0]
    monkeypatch.setattr(registry_module, "_monotonic_ns", lambda: now[0])
    authority = app.dependency_overrides[get_domain_verifier]()

    async def timed_authority(domain):
        result = await authority(domain)
        # Only the clock is controlled; DNS fixture authority, status endpoint,
        # database and Redis all take their actual paths.
        now[0] += 2_001_000_000
        return result

    async with aclosing(
        RegistryClient(
            "http://testserver",
            transport=httpx.ASGITransport(app=app),
            domain_verifier=timed_authority,
        )
    ) as live:
        cached = CachedRegistryClient(
            "http://testserver",
            redis,
            transport=httpx.ASGITransport(app=app),
            domain_verifier=timed_authority,
        )
        key = cached._id_status_cache_key(
            {"v": 1, "domain": DOMAIN, "ids": [did_aw("alice"), did_aw("global_agent")]}
        )
        try:
            await redis.delete(key)
            first = await live.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)
            second = await cached.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)
            assert first == second
            assert first.age_seconds == 3
        finally:
            await redis.delete(key)
            await cached.aclose()


async def test_live_registry_outage_returns_unavailable_evidence(live_registry):
    app, _ = live_registry
    listener = await asyncio.start_server(
        lambda reader, writer: writer.close(), "127.0.0.1", 0
    )
    port = listener.sockets[0].getsockname()[1]
    listener.close()
    await listener.wait_closed()
    async with aclosing(
        RegistryClient(
            f"http://127.0.0.1:{port}",
            domain_verifier=app.dependency_overrides[get_domain_verifier](),
        )
    ) as client:
        evidence = await client.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)
    assert (
        evidence.age_seconds is None
        and not evidence.status
        and not evidence.namespace_authority
    )


async def test_malformed_actual_status_response_is_unavailable(live_registry):
    app, _ = live_registry
    transport = ServiceTransport(app)

    def corrupt(request, response):
        assert response.status_code == 200
        return httpx.Response(200, content=b"[]")

    transport.fault = corrupt
    async with aclosing(
        RegistryClient(
            "http://testserver",
            transport=transport,
            domain_verifier=app.dependency_overrides[get_domain_verifier](),
        )
    ) as client:
        evidence = await client.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)
    assert (
        evidence.age_seconds is None
        and not evidence.status
        and not evidence.namespace_authority
    )
    assert len(transport.calls) == 1


async def test_live_evidence_cancellation_propagates(live_registry):
    app, _ = live_registry
    authority = app.dependency_overrides[get_domain_verifier]()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def held_authority(domain):
        result = await authority(domain)
        entered.set()
        await release.wait()
        return result

    async with aclosing(
        RegistryClient(
            "http://testserver",
            transport=httpx.ASGITransport(app=app),
            domain_verifier=held_authority,
        )
    ) as client:
        task = asyncio.create_task(
            client.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)
        )
        try:
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


async def test_live_evidence_timeout_bounds_authority_acquisition(live_registry):
    app, _ = live_registry
    authority = app.dependency_overrides[get_domain_verifier]()
    cancelled = asyncio.Event()

    async def held_authority(domain):
        await authority(domain)
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with aclosing(
        RegistryClient(
            "http://testserver",
            transport=httpx.ASGITransport(app=app),
            domain_verifier=held_authority,
            timeout_seconds=0.02,
        )
    ) as client:
        evidence = await client.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)
    assert evidence.age_seconds is None
    assert cancelled.is_set()


async def test_manual_registry_subclass_keeps_no_argument_post_init_compatibility():
    class ManualRegistryClient(RegistryClient):
        def __init__(self, registry_url):
            object.__setattr__(self, "registry_url", registry_url)
            RegistryClient.__post_init__(self)

    client = ManualRegistryClient("http://127.0.0.1:1")
    try:
        assert client._domain_verifier is None
        assert client.registry_url == "http://127.0.0.1:1"
    finally:
        await client.aclose()

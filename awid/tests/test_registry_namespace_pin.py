"""A protected embedding's namespace pin bypasses discovery and stale caches."""

import httpx
import pytest

from awid.registry import CachedRegistryClient, RegistryClient, RegistryError


class NoCache:
    def __getattr__(self, name):
        raise AssertionError("a pinned fresh namespace read must not use a cache")


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("status", [200, 404, 503])
async def test_pinned_namespace_is_the_only_origin_and_failures_do_not_fall_back(cached, status):
    calls = []

    async def refused_discovery(*args):
        raise AssertionError("the explicit host pin must not discover another registry")

    def upstream(request):
        calls.append(str(request.url))
        return httpx.Response(status, json={"namespace_id": "namespace", "domain": "example.com",
            "controller_did": "public-reference", "verification_status": "verified", "created_at": "2026-11-13T00:00:00Z"})

    kwargs = {"registry_url": "https://ordinary.example", "transport": httpx.MockTransport(upstream),
        "domain_registry_resolver": refused_discovery}
    client = CachedRegistryClient(redis_client=NoCache(), **kwargs) if cached else RegistryClient(**kwargs)
    try:
        if status == 503:
            with pytest.raises(RegistryError) as caught:
                await client.get_namespace_fresh("example.com", registry_origin="https://pinned.example")
            assert caught.value.status_code == 503
        else:
            answer = await client.get_namespace_fresh("example.com", registry_origin="https://pinned.example")
            assert (answer is None) == (status == 404)
            if answer is not None:
                assert answer.domain == "example.com" and answer.controller_did == "public-reference"
        assert calls == ["https://pinned.example/v1/namespaces/example.com"]
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("origin", ["file:///private", "https://pinned.example?query=1", "https://user:password@pinned.example"])
async def test_non_origin_pins_send_nothing(origin):
    def upstream(request):
        raise AssertionError("an invalid pin must refuse before sending")

    client = RegistryClient(registry_url="https://ordinary.example", transport=httpx.MockTransport(upstream))
    try:
        with pytest.raises(ValueError):
            await client.get_namespace_fresh("example.com", registry_origin=origin)
    finally:
        await client.aclose()

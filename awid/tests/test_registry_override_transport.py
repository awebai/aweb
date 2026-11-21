"""Public registry selections cannot turn a read into a private-network dial."""

from __future__ import annotations

import httpx
import pytest
from awid.external_registry import SystemHostResolver
from awid.registry import RegistryClient, RegistryError


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addresses",
    [("127.0.0.1",), ("10.0.0.1",), ("169.254.169.254",), ("2606:4700::1111", "::1")],
)
async def test_dns_override_refuses_nonpublic_answers_before_dial(
    monkeypatch, addresses
):

    async def discover(domain):
        return "https://registry.example.com"

    async def resolve(self, hostname):
        assert hostname == "registry.example.com"
        return addresses

    dials = []

    async def dial(self, request):
        dials.append(str(request.url))
        return httpx.Response(404)

    monkeypatch.setattr(SystemHostResolver, "resolve_all", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", dial)
    registry = RegistryClient("https://api.awid.ai", domain_registry_resolver=discover)
    try:
        with pytest.raises(RegistryError, match="unavailable"):
            await registry.get_namespace("example.com")
    finally:
        await registry.aclose()
    assert dials == []


@pytest.mark.asyncio
async def test_dns_override_dials_only_checked_ip_preserving_host_and_tls_name(
    monkeypatch,
):

    async def discover(domain):
        return "https://registry.example.com:8443"

    lookups = []

    async def resolve(self, hostname):
        lookups.append(hostname)
        return ("1.1.1.1",)

    dials = []

    async def dial(self, request):
        dials.append(
            (
                str(request.url),
                request.headers["Host"],
                request.extensions.get("sni_hostname"),
                request.headers.get("X-AWID-Service-Token"),
            )
        )
        return httpx.Response(404)

    monkeypatch.setattr(SystemHostResolver, "resolve_all", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", dial)
    registry = RegistryClient(
        "https://api.awid.ai",
        service_token="private-home-token-with-more-than-32-bytes",
        domain_registry_resolver=discover,
    )
    try:
        assert await registry.get_namespace("example.com") is None
    finally:
        await registry.aclose()
    assert lookups == ["registry.example.com"]
    assert dials == [
        (
            "https://1.1.1.1:8443/v1/namespaces/example.com",
            "registry.example.com:8443",
            "registry.example.com",
            None,
        )
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize(
    "app_env, enabled, listener, origin, addresses, allowed",
    [
        (
            "development",
            True,
            "http://awid-b:8010",
            "http://awid-a:8010",
            ("172.20.0.2",),
            True,
        ),
        (
            "production",
            True,
            "http://awid-b:8010",
            "http://awid-a:8010",
            ("172.20.0.2",),
            False,
        ),
        (
            "development",
            False,
            "http://awid-b:8010",
            "http://awid-a:8010",
            ("172.20.0.2",),
            False,
        ),
        ("development", True, "", "http://awid-a:8010", ("172.20.0.2",), False),
        ("development", True, "http://", "http://awid-a:8010", ("172.20.0.2",), False),
        (
            "development",
            True,
            "https://server.example.com",
            "http://awid-a:8010",
            ("172.20.0.2",),
            False,
        ),
        (
            "development",
            True,
            "http://awid-b:8010",
            "http://registry.example.com",
            ("1.1.1.1",),
            False,
        ),
        (
            "development",
            True,
            "http://awid-b:8010",
            "https://registry.example.com",
            ("1.1.1.1", "127.0.0.1"),
            False,
        ),
    ],
)
async def test_explicit_development_context_is_scoped_to_isolated_origins(
    monkeypatch,
    cached,
    app_env,
    enabled,
    listener,
    origin,
    addresses,
    allowed,
):
    from awid.external_authority import OriginContext
    from awid.registry import CachedRegistryClient
    from test_registry_client import FakeRedis

    async def discover(domain):
        return origin

    async def resolve(self, hostname):
        return addresses

    dials = []

    async def dial(self, request):
        dials.append(str(request.url))
        return httpx.Response(404)

    monkeypatch.setattr(SystemHostResolver, "resolve_all", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", dial)
    options = {
        "registry_origin_context": OriginContext(app_env, enabled, listener),
        "domain_registry_resolver": discover,
    }
    # Both constructors must preserve the same explicitly selected route
    # policy, including on a cache miss.
    registry = (
        CachedRegistryClient("https://api.awid.ai", FakeRedis(), **options)
        if cached
        else RegistryClient("https://api.awid.ai", **options)
    )
    try:
        if allowed:
            assert await registry.get_namespace("alpha.example.com") is None
        else:
            with pytest.raises(RegistryError, match="unavailable"):
                await registry.get_namespace("alpha.example.com")
    finally:
        await registry.aclose()
    assert len(dials) == int(allowed)
    if allowed:
        assert dials == ["http://172.20.0.2:8010/v1/namespaces/alpha.example.com"]

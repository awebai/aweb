"""DNS-selected registries cannot turn a registry read into a private-network dial."""

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
    import awid.dns_verify

    async def discover(domain):
        return "https://registry.example.com"

    async def resolve(self, hostname):
        assert hostname == "registry.example.com"
        return addresses

    dials = []

    async def dial(self, request):
        dials.append(str(request.url))
        return httpx.Response(404)

    monkeypatch.setattr(awid.dns_verify, "discover_registry_override", discover)
    monkeypatch.setattr(SystemHostResolver, "resolve_all", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", dial)
    registry = RegistryClient("https://api.awid.ai")
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
    import awid.dns_verify

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

    monkeypatch.setattr(awid.dns_verify, "discover_registry_override", discover)
    monkeypatch.setattr(SystemHostResolver, "resolve_all", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", dial)
    registry = RegistryClient(
        "https://api.awid.ai",
        service_token="private-home-token-with-more-than-32-bytes",
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

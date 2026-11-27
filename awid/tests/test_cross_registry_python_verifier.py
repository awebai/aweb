"""The anonymous Python outsider uses DNS routing and the checked SDK transport."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from redis.exceptions import RedisError

from awid.external_registry import SystemHostResolver
from awid.id_certificates import verify_id_chain
from awid.registry import CachedRegistryClient

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cross_registry_python_verifier",
    ROOT / "scripts/cross-registry-python-verifier.py",
)
OUTSIDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OUTSIDER)
VECTORS = json.loads((ROOT / "docs/vectors/id-certificates-v1.json").read_text())
CASE = next(
    case
    for case in VECTORS["verification_cases"]
    if case["name"] == "cached-status-age-60"
)
STATUS = VECTORS["status_fixtures"][CASE["status"]]
BUNDLE = {
    "v": 1,
    "type": "aweb.id-chain",
    "certificates": [VECTORS["certificates"][name]["signed"] for name in CASE["chain"]],
}


class NoCache:
    """An unavailable Redis cannot hide a missing live registry read."""

    async def get(self, *args, **kwargs):
        raise RedisError("cache unavailable")

    def pipeline(self, **kwargs):
        raise RedisError("cache unavailable")

    async def time(self):
        raise RedisError("cache unavailable")

    async def set(self, *args, **kwargs):
        raise RedisError("cache unavailable")


@pytest.fixture
def routed_registry(monkeypatch):
    import dns.asyncresolver

    controller = next(
        epoch
        for epoch in reversed(STATUS["namespace"]["epochs"])
        if epoch["retired_at"] is None
    )["did_key"]
    txt = f"awid=v1; controller={controller}; registry=http://awid-a:8010;"
    lookups, dials = [], []

    async def dns_lookup(name, kind):
        assert (name, kind) == (f"_awid.{STATUS['domain']}", "TXT")
        return [SimpleNamespace(strings=[txt.encode()])]

    async def resolve(self, hostname):
        lookups.append(hostname)
        assert hostname == "awid-a"
        return ("172.20.0.2",)

    async def dial(self, request):
        dials.append(
            (
                str(request.url),
                request.headers["Host"],
                request.extensions["sni_hostname"],
            )
        )
        assert request.method == "POST"
        assert not any(
            name in request.headers
            for name in ("Authorization", "X-AWID-Service-Token")
        )
        return httpx.Response(200, json=STATUS)

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
    monkeypatch.setattr(dns.asyncresolver, "resolve", dns_lookup)
    monkeypatch.setattr(SystemHostResolver, "resolve_all", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", dial)
    return lookups, dials


@pytest.mark.asyncio
async def test_python_outsider_verifies_a_dns_selected_isolated_registry(
    routed_registry,
):
    client = OUTSIDER.outsider_client(NoCache())
    try:
        evidence = await client.id_chain_evidence(
            BUNDLE, CASE["subject"], domain=STATUS["domain"]
        )
        result = verify_id_chain(
            BUNDLE, subject=CASE["subject"], evidence=evidence, domain=STATUS["domain"]
        )
        assert result == CASE["expected"]
    finally:
        await client.aclose()
    assert routed_registry == (
        ["awid-a"],
        [
            (
                "http://172.20.0.2:8010/v1/id-certificates/status",
                "awid-a:8010",
                "awid-a",
            )
        ],
    )


@pytest.mark.asyncio
async def test_sdk_defaults_stay_production_even_under_the_journey_environment(
    routed_registry,
):
    client = CachedRegistryClient("https://api.awid.ai", NoCache())
    try:
        evidence = await client.id_chain_evidence(
            BUNDLE, CASE["subject"], domain=STATUS["domain"]
        )
        result = verify_id_chain(
            BUNDLE, subject=CASE["subject"], evidence=evidence, domain=STATUS["domain"]
        )
        assert result["reason"] == "evidence_unavailable"
    finally:
        await client.aclose()
    assert routed_registry == ([], [])

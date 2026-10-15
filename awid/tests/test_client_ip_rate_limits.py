"""Rate attribution trusts configured first-party proxies, not public peers."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

import awid.ratelimit as ratelimit_module
from awid.ratelimit import ip_bucket_key
from awid_service.main import create_app


CF = "203.0.113.0/24"
EDGE = "203.0.113.9"
PROXIES = "10.24.0.0/13"
PROXY = "10.24.1.7"
PUBLIC = "45.33.32.9"
CLIENT = "198.51.100.7"


@pytest.fixture(autouse=True)
def clean_proxy_config(monkeypatch):
    for name in (
        "AWEB_CF_EDGE_CIDRS", "AWEB_TRUSTED_PROXY_CIDRS",
        "AWEB_TRUST_PROXY_HEADERS", "AWID_RATE_LIMIT_DISABLED",
    ):
        monkeypatch.delenv(name, raising=False)


def request(peer, headers=()):
    return Request({
        "type": "http", "method": "GET", "path": "/",
        "client": (peer, 12345) if peer else None,
        "headers": [(name.encode(), value.encode()) for name, value in headers],
    })


def configure(monkeypatch, cf=CF, proxies=PROXIES):
    monkeypatch.setenv("AWEB_CF_EDGE_CIDRS", cf)
    monkeypatch.setenv("AWEB_TRUSTED_PROXY_CIDRS", proxies)


@pytest.mark.parametrize("peer, chain, expected", [
    (PUBLIC, f"{CLIENT}, {EDGE}", PUBLIC),
    (PROXY, f"{CLIENT}, {PUBLIC}", PROXY),
    (PROXY, f"1.1.1.1, {CLIENT}, {EDGE}", CLIENT),
    (PROXY, f"{CLIENT}, 203.0.113.1, {EDGE}", CLIENT),
    (PROXY, f"{CLIENT}, 10.24.2.8, {EDGE}", CLIENT),
    (PROXY, f"{CLIENT}, garbage, {EDGE}", PROXY),
    (PROXY, f"garbage, {CLIENT}, {EDGE}", PROXY),
    (PROXY, f"{CLIENT}, garbage", PROXY),
    (PROXY, f"{CLIENT}, , {EDGE}", PROXY),
    (PROXY, EDGE, PROXY),
    (None, f"{CLIENT}, {EDGE}", "unknown"),
])
def test_client_ip_chain_boundary(monkeypatch, peer, chain, expected):
    configure(monkeypatch)
    assert ip_bucket_key(request(peer, [("x-forwarded-for", chain)])) == expected


def test_trusted_firstparty_private_callers_may_choose_rate_attribution(monkeypatch):
    # Accepted threat model: docs/awid-sot.md#client-ip-rate-attribution.
    # First-party private services are trusted even when they fabricate the
    # entire CF-looking chain; suffix membership is not ingress authentication.
    configure(monkeypatch)
    assert ip_bucket_key(request(PROXY, [("x-forwarded-for", f"{CLIENT}, {EDGE}")])) == CLIENT


@pytest.mark.parametrize("cf, proxies", [
    ("", PROXIES), (CF, ""), ("bad-cidr", PROXIES), (CF, "bad-cidr"),
    (f"{CF},bad-cidr", PROXIES), (CF, f"{PROXIES},bad-cidr"),
    ('["203.0.113.0/24", 7]', PROXIES), ('{"range":"203.0.113.0/24"}', PROXIES),
])
def test_empty_or_invalid_config_uses_peer(monkeypatch, cf, proxies):
    configure(monkeypatch, cf, proxies)
    assert ip_bucket_key(request(PROXY, [("x-forwarded-for", f"{CLIENT}, {EDGE}")])) == PROXY


@pytest.mark.parametrize("cf, proxies", [
    ('["203.0.113.0/24"]', '["10.24.0.0/13"]'),
    ("203.0.113.0/25|203.0.113.128/25", PROXIES),
])
def test_json_and_pipe_cidr_syntax(monkeypatch, cf, proxies):
    configure(monkeypatch, cf, proxies)
    assert ip_bucket_key(request(PROXY, [("x-forwarded-for", f"{CLIENT}, {EDGE}")])) == CLIENT


def test_repeated_xff_lines_preserve_wire_order(monkeypatch):
    configure(monkeypatch)
    forged = ("x-forwarded-for", f"{CLIENT}, {EDGE}")
    assert ip_bucket_key(request(PROXY, [forged, ("x-forwarded-for", PUBLIC)])) == PROXY
    assert ip_bucket_key(request(PROXY, [("x-forwarded-for", "1.1.1.1"), forged])) == CLIENT


def test_ipv6_client_and_edge(monkeypatch):
    configure(monkeypatch, "2001:db8:ca::/48")
    chain = "2001:0db8:0001::7, 2001:db8:ca::9"
    assert ip_bucket_key(request(PROXY, [("x-forwarded-for", chain)])) == "2001:db8:1::7"


@pytest.mark.parametrize("header", ["x-real-ip", "true-client-ip", "cf-connecting-ip"])
def test_unproven_alternate_headers_and_old_blanket_switch_are_ignored(monkeypatch, header):
    configure(monkeypatch)
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    assert ip_bucket_key(request(PUBLIC, [(header, CLIENT)])) == PUBLIC
    assert ip_bucket_key(request(PUBLIC, [("x-forwarded-for", f"{CLIENT}, {EDGE}")])) == PUBLIC


def test_other_ip_headers_do_not_override_a_valid_xff_client(monkeypatch):
    configure(monkeypatch)
    headers = [("x-forwarded-for", f"{CLIENT}, {EDGE}")]
    headers.extend((name, "198.51.100.200") for name in (
        "x-real-ip", "true-client-ip", "cf-connecting-ip",
    ))
    assert ip_bucket_key(request(PROXY, headers)) == CLIENT


@pytest.mark.asyncio
@pytest.mark.parametrize("peer, forwarded_key", [(PUBLIC, PUBLIC), (PROXY, CLIENT)])
async def test_real_registry_route_redis_buckets(
    awid_db_infra, fake_redis, monkeypatch, peer, forwarded_key,
):
    configure(monkeypatch)
    # Keep the 31-request boundary inside one window even across a wall-clock minute.
    monkeypatch.setattr(ratelimit_module.time, "time", lambda: 1800000000.0)
    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app, client=(peer, 12345))
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            headers = {"x-forwarded-for": f"{CLIENT}, {EDGE}"}
            for _ in range(30):
                assert (await client.get("/v1/namespaces", headers=headers)).status_code == 200
            exhausted = await client.get("/v1/namespaces", headers=headers)
            assert exhausted.status_code == 429
            assert exhausted.headers["X-RateLimit-Remaining"] == "0"
            other = await client.get("/v1/namespaces", headers={
                "x-forwarded-for": f"198.51.100.8, {EDGE}",
            })
            # A public peer cannot rotate its full bucket using a forged XFF.
            assert other.status_code == (429 if peer == PUBLIC else 200)
    keys = [call[0][2] for call in fake_redis.eval_calls]
    assert all(f":namespace_list:{forwarded_key}:" in key for key in keys[:31])
    assert f":namespace_list:{PUBLIC if peer == PUBLIC else '198.51.100.8'}:" in keys[-1]

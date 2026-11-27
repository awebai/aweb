"""Real DNS/registry/PG: lookup failure is not a non-verifying namespace."""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace

import dns.asyncresolver
import dns.flags
import dns.message
import dns.rcode
import dns.rrset
from httpx import ASGITransport, AsyncClient
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from awid.dns_verify import awid_txt_value
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid.registry import RegistryClient, RegistryError
from awid_service.main import create_app
from id_tree_support import (
    DOMAIN,
    ORIGIN,
    Tree,
    at,
    certificate,
    certificate_id,
    did_aw,
    did_key,
)


class AuthorityDNS(asyncio.DatagramProtocol):
    """An owned UDP DNS server; no resolver or authority function is replaced."""

    mode = "valid"

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, wire, peer):
        if self.mode == "timeout":
            return
        query = dns.message.from_wire(wire)
        answer = dns.message.make_response(query)
        answer.flags |= dns.flags.AA
        if self.mode == "missing":
            answer.set_rcode(dns.rcode.NXDOMAIN)
        elif self.mode == "servfail":
            answer.set_rcode(dns.rcode.SERVFAIL)
        elif self.mode != "no_answer":
            record = (
                "awid=v1; controller=not-a-did;"
                if self.mode == "malformed"
                else awid_txt_value(
                    did_key("alice" if self.mode == "wrong_controller" else "root"),
                    ORIGIN,
                )
            )
            answer.answer.append(
                dns.rrset.from_text(
                    query.question[0].name,
                    0,
                    "IN",
                    "TXT",
                    '"' + record + '"',
                )
            )
        self.transport.sendto(answer.to_wire(), peer)


@pytest_asyncio.fixture
async def dns_tree(awid_db_infra, manual_clock, monkeypatch):
    monkeypatch.delenv("AWID_SKIP_DNS_VERIFY", raising=False)
    authority = AuthorityDNS()
    channel, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: authority,
        local_addr=("127.0.0.1", 0),
    )
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = channel.get_extra_info("sockname")[1]
    resolver.timeout, resolver.lifetime = 0.3, 1
    monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
    redis_url = os.environ.get("AWID_REDIS_URL") or os.environ.get(
        "REDIS_URL", "redis://127.0.0.1:6379/0"
    )
    try:
        async with Redis.from_url(redis_url) as redis:
            app = create_app(
                db_infra=awid_db_infra,
                redis=redis,
                rate_limiter=MemoryFixedWindowRateLimiter(),
            )
            app.state.id_tree_clock = manual_clock
            async with app.router.lifespan_context(app):
                async with AsyncClient(
                    transport=ASGITransport(app), base_url=ORIGIN
                ) as client:
                    client.app = app
                    tree = Tree(client, manual_clock)
                    # Do not call Tree.root(), which supplies synthetic DNS.
                    assert (await tree.register_namespace()).status_code == 200
                    for name in ("alice", "other_human"):
                        await tree.did(name)
                    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
                    tree.clock.now = at("2026-10-26T00:05:00Z")
                    yield SimpleNamespace(
                        tree=tree,
                        dns=authority,
                        resolver=resolver,
                        app=app,
                        db=awid_db_infra.get_manager("aweb"),
                    )
    finally:
        channel.close()


async def state(db):
    return (
        await db.fetch_all(
            "SELECT id, revoked_at, effective_from FROM {{tables.id_identities}} ORDER BY id"
        ),
        await db.fetch_all(
            "SELECT certificate_id, superseded_at FROM {{tables.id_certificates}} ORDER BY certificate_id"
        ),
    )


def dns_condition(world, condition):
    world.dns.mode = condition
    if condition == "timeout":
        world.resolver.timeout, world.resolver.lifetime = 0.03, 0.1
    elif condition == "no_nameservers":
        world.resolver.nameservers = []


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["status", "register", "revoke"])
@pytest.mark.parametrize(
    "condition",
    [
        "timeout",
        "no_nameservers",
        "servfail",
        "missing",
        "no_answer",
        "malformed",
        "wrong_controller",
        "no_epoch",
    ],
)
async def test_dns_outage_is_distinct_on_every_id_endpoint(
    dns_tree, operation, condition
):
    world = dns_tree
    if condition == "no_epoch":
        # Model an existing pre-epoch namespace; this is fixture state only.
        await world.db.execute(
            "DELETE FROM {{tables.id_namespace_epochs}} WHERE domain=$1", DOMAIN
        )
    dns_condition(world, condition)
    before = await state(world.db)
    if operation == "status":
        response = await world.tree.client.post(
            "/v1/id-certificates/status",
            json={
                "v": 1,
                "domain": DOMAIN,
                "ids": [did_aw("alice")],
            },
        )
    elif operation == "register":
        response = await world.tree.register([certificate("other-human")])
    else:
        response = await world.tree.revoke(
            "root", "alice", expected_head=certificate_id("alice")
        )
    expected = (
        "dns_unavailable"
        if condition in ("timeout", "no_nameservers", "servfail")
        else "evidence_unavailable"
    )
    assert (response.status_code, response.json()["detail"]["code"]) == (
        503,
        expected,
    ), response.text
    assert await state(world.db) == before
    # A real DNS recovery permits the same operation, rather than turning
    # the temporary failure into a durable empty/missing identity result.
    if expected == "dns_unavailable":
        assert response.headers["Retry-After"] == "1"
        world.dns.mode = "valid"
        world.resolver.nameservers = ["127.0.0.1"]
        world.resolver.timeout, world.resolver.lifetime = 0.3, 1
        if operation == "status":
            recovered = await world.tree.client.post(
                "/v1/id-certificates/status",
                json={
                    "v": 1,
                    "domain": DOMAIN,
                    "ids": [did_aw("alice")],
                },
            )
        elif operation == "register":
            recovered = await world.tree.register([certificate("other-human")])
        else:
            recovered = await world.tree.revoke(
                "root", "alice", expected_head=certificate_id("alice")
            )
        assert recovered.status_code == 200, recovered.text


@pytest.mark.asyncio
async def test_python_client_preserves_retryable_dns_error(dns_tree):
    world = dns_tree
    world.dns.mode = "servfail"
    client = RegistryClient(
        ORIGIN, transport=ASGITransport(world.app), timeout_seconds=2
    )
    try:
        with pytest.raises(RegistryError) as failure:
            await client.fetch_id_certificate_status(
                DOMAIN,
                {
                    "v": 1,
                    "domain": DOMAIN,
                    "ids": [did_aw("alice")],
                },
                registry_origin=ORIGIN,
            )
    finally:
        await client.aclose()
    assert failure.value.status_code == 503
    assert failure.value.code == "dns_unavailable"

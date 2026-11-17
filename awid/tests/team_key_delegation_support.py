"""Owned UDP DNS, real AWID/PG/Redis and signed child delegation for consumers."""

from __future__ import annotations
import asyncio
import os
from types import SimpleNamespace
from uuid import uuid4
import dns.asyncresolver
import dns.message
import dns.rcode
import dns.rrset
import httpx
import pytest_asyncio
from redis.asyncio import Redis
from awid.did import generate_keypair, did_from_public_key
from awid.dns_verify import awid_txt_value
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import CachedRegistryClient
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid_service.main import create_app


def controller_keypair():
    secret, public = generate_keypair()
    return secret, did_from_public_key(public)


class DNS(asyncio.DatagramProtocol):
    def __init__(self, registry_origin):
        self.records = {}
        self.registry_origin = registry_origin

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, wire, peer):
        query = dns.message.from_wire(wire)
        answer = dns.message.make_response(query)
        name = query.question[0].name.to_text().rstrip(".")
        if name in self.records:
            value = awid_txt_value(
                self.records[name], registry_url=self.registry_origin
            )
            answer.answer.append(
                dns.rrset.from_text(name + ".", 0, "IN", "TXT", '"' + value + '"')
            )
        else:
            answer.set_rcode(dns.rcode.NXDOMAIN)
        self.transport.sendto(answer.to_wire(), peer)


@pytest_asyncio.fixture
async def world(awid_db_infra, monkeypatch):
    monkeypatch.delenv("AWID_SKIP_DNS_VERIFY", raising=False)
    domain = f"org-{uuid4().hex}.example.com"
    registry_origin = f"https://registry-{uuid4().hex}.example.com"
    dns_server = DNS(registry_origin)
    channel, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: dns_server, local_addr=("127.0.0.1", 0)
    )
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers, resolver.port = (
        ["127.0.0.1"],
        channel.get_extra_info("sockname")[1],
    )
    monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
    parent, child, team = (
        controller_keypair(),
        controller_keypair(),
        controller_keypair(),
    )
    dns_server.records["_awid.example.com"] = parent[1]
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
            app.state.awid_public_origins = (registry_origin,)
            async with app.router.lifespan_context(app):
                sdk = CachedRegistryClient(
                    registry_url=registry_origin,
                    redis_client=redis,
                    transport=httpx.ASGITransport(app=app),
                )
                try:
                    await sdk.register_namespace("example.com", parent[1], parent[0])
                    await sdk.register_namespace(
                        domain, child[1], child[0], parent_signing_key=parent[0]
                    )
                    await sdk.register_team(
                        domain=domain,
                        name="base",
                        team_did_key=team[1],
                        display_name="PRIVATE",
                        visibility="public",
                        namespace_controller_signing_key=child[0],
                    )
                    await sdk.rotate_team_key(
                        domain,
                        "base",
                        new_team_did_key=team[1],
                        namespace_controller_signing_key=child[0],
                    )
                    yield SimpleNamespace(
                        domain=domain,
                        sdk=sdk,
                        dns=dns_server,
                        parent=parent,
                        child=child,
                        team=team,
                        resolver=SystemTXTOutcomeResolver(),
                        db=awid_db_infra.get_manager("aweb"),
                    )
                finally:
                    await sdk.aclose()
    finally:
        channel.close()

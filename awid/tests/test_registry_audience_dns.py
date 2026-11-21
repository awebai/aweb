"""The public signing audience follows actual DNS, unless explicitly selected."""

from __future__ import annotations

import asyncio
from enum import StrEnum

import dns.asyncresolver
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest
import pytest_asyncio
from awid.did import did_from_public_key, generate_keypair
from awid.dns_verify import awid_txt_value
from awid.registry import RegistryClient


class AuthorityAnswer(StrEnum):
    OVERRIDE = "override"
    PUBLIC_DEFAULT = "public_default"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"


class RegistryAudienceDNS(asyncio.DatagramProtocol):
    """Serve owned TXT packets without replacing registry discovery functions."""

    def __init__(self, *, controller_did_key: str):
        self.controller_did_key = controller_did_key
        self.answer = AuthorityAnswer.OVERRIDE
        self.queries: list[tuple[str, int]] = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, wire, peer):
        query = dns.message.from_wire(wire)
        question = query.question[0]
        self.queries.append((question.name.to_text(), question.rdtype))
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if self.answer == AuthorityAnswer.ABSENT:
            response.set_rcode(dns.rcode.NXDOMAIN)
        elif self.answer == AuthorityAnswer.UNAVAILABLE:
            response.set_rcode(dns.rcode.SERVFAIL)
        else:
            override = (
                "https://override.example"
                if self.answer == AuthorityAnswer.OVERRIDE
                else None
            )
            record = awid_txt_value(self.controller_did_key, override)
            response.answer.append(
                dns.rrset.from_text(question.name, 0, "IN", "TXT", f'"{record}"')
            )
        self.transport.sendto(response.to_wire(), peer)


@pytest_asyncio.fixture
async def registry_audience_dns(monkeypatch):
    _, public_key = generate_keypair()
    authority = RegistryAudienceDNS(controller_did_key=did_from_public_key(public_key))
    channel, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: authority, local_addr=("127.0.0.1", 0)
    )
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = channel.get_extra_info("sockname")[1]
    resolver.timeout, resolver.lifetime = 0.2, 1
    monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
    try:
        yield authority
    finally:
        channel.close()


# docs/awid-sot.md:1459: the audience names the registry actually selected for
# the domain. Explicit operator selection does not consult a DNS override.
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer,configured,expected,queries",
    [
        (
            AuthorityAnswer.OVERRIDE,
            "https://api.awid.ai",
            "https://override.example",
            1,
        ),
        (
            AuthorityAnswer.PUBLIC_DEFAULT,
            "https://api.awid.ai",
            "https://api.awid.ai",
            1,
        ),
        (AuthorityAnswer.ABSENT, "https://api.awid.ai", "https://api.awid.ai", 1),
        (AuthorityAnswer.UNAVAILABLE, "https://api.awid.ai", "https://api.awid.ai", 1),
        (
            AuthorityAnswer.OVERRIDE,
            "https://registry.example",
            "https://registry.example",
            0,
        ),
        (AuthorityAnswer.OVERRIDE, "http://localhost:8110", "http://localhost:8110", 0),
    ],
)
async def test_registry_audience_uses_dns_override_only_for_public_default(
    registry_audience_dns, answer, configured, expected, queries
):
    authority = registry_audience_dns
    authority.answer = answer
    client = RegistryClient(registry_url=configured)
    try:
        assert await client.registry_audience("example.com") == expected
    finally:
        await client.aclose()
    assert authority.queries == [("_awid.example.com.", dns.rdatatype.TXT)] * queries

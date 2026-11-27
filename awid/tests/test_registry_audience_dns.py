"""Public read selection follows actual DNS, unless explicitly selected."""

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
from awid.registry import RegistryClient, RegistryError


class AuthorityAnswer(StrEnum):
    OVERRIDE = "override"
    PUBLIC_DEFAULT = "public_default"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"
    MALFORMED = "malformed"
    AMBIGUOUS = "ambiguous"


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
            record = (
                "awid=v1; controller=not-a-controller;"
                if self.answer == AuthorityAnswer.MALFORMED
                else awid_txt_value(self.controller_did_key, override)
            )
            response.answer.append(
                dns.rrset.from_text(question.name, 0, "IN", "TXT", f'"{record}"')
            )
        if self.answer == AuthorityAnswer.AMBIGUOUS:
            response.answer.append(
                dns.rrset.from_text(
                    question.name, 0, "IN", "TXT", '"awid=v1; controller=invalid;"'
                )
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


# docs/identity-messaging-contract.md:249-256: read discovery remains domain-selected;
# administrative writes use their configured pin instead.
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer", [AuthorityAnswer.MALFORMED, AuthorityAnswer.AMBIGUOUS]
)
async def test_malformed_dns_is_not_a_read_fallback(registry_audience_dns, answer):
    from awid.dns_verify import DnsVerificationError

    registry_audience_dns.answer = answer
    client = RegistryClient("https://api.awid.ai")
    try:
        with pytest.raises(RegistryError) as refused:
            await client.registry_audience("example.com")
        assert refused.value.status_code == 502
        assert str(refused.value) == (
            "AWID registry discovery is invalid for example.com. "
            "Correct the domain's _awid TXT record and retry."
        )
        assert isinstance(refused.value.__cause__, DnsVerificationError)
    finally:
        await client.aclose()
    assert registry_audience_dns.queries == [("_awid.example.com.", dns.rdatatype.TXT)]

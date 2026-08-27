from __future__ import annotations

import dns.flags
import dns.message
import dns.resolver
import dns.rrset
import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.dns_verify import (
    _authoritative_txt_ttl,
    _candidate_domains_for_lookup,
    awid_txt_value,
    discover_authoritative_registry,
    verify_domain,
)


@pytest.mark.asyncio
async def test_authoritative_ttl_walks_parent_uses_ipv6_and_rejects_stale_recursive_content(
    monkeypatch,
):
    expected = "awid=v1; controller=did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2;"
    authoritative = {"record": expected.replace("5G2", "5G3"), "aa": True}
    queries = []

    async def resolve(name, record_type):
        queries.append((str(name), record_type))
        if record_type == "NS":
            if str(name) == "child.example.com":
                raise dns.resolver.NoAnswer
            return dns.rrset.from_text(
                "example.com.", 600, "IN", "NS", "ns.example.com."
            )
        if record_type == "A":
            raise dns.resolver.NoAnswer
        if record_type == "AAAA":
            return dns.rrset.from_text(
                "ns.example.com.", 600, "IN", "AAAA", "2001:db8::53"
            )
        raise AssertionError((name, record_type))

    async def udp(query, where, timeout):
        assert where == "2001:db8::53"
        response = dns.message.make_response(query)
        if authoritative["aa"]:
            response.flags |= dns.flags.AA
        response.answer.append(
            dns.rrset.from_text(
                "_awid.child.example.com.", 300, "IN", "TXT",
                f'"{authoritative["record"]}"',
            )
        )
        return response

    monkeypatch.setattr("dns.asyncresolver.resolve", resolve)
    monkeypatch.setattr("dns.asyncquery.udp", udp)
    assert await _authoritative_txt_ttl(
        "child.example.com", "_awid.child.example.com", expected
    ) is None
    authoritative["record"] = expected
    authoritative["aa"] = False
    assert await _authoritative_txt_ttl(
        "child.example.com", "_awid.child.example.com", expected
    ) is None
    authoritative["aa"] = True
    assert await _authoritative_txt_ttl(
        "child.example.com", "_awid.child.example.com", expected
    ) == 300
    assert ("child.example.com", "NS") in queries
    assert ("example.com", "NS") in queries
    assert ("ns.example.com", "AAAA") in queries


class _TxtAnswer:
    def __init__(self, text: str):
        self.strings = [text.encode()]


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("subdomain.acme.com", ["subdomain.acme.com", "acme.com"]),
        ("deep.juan.aweb.ai", ["deep.juan.aweb.ai", "juan.aweb.ai", "aweb.ai"]),
    ],
)
def test_candidate_domains_stop_at_registrable_parent(domain, expected):
    assert _candidate_domains_for_lookup(domain) == expected


@pytest.mark.asyncio
async def test_verify_domain_inherits_parent_txt_and_does_not_query_tld(monkeypatch):
    _signing_key, public_key = generate_keypair()
    controller_did = did_from_public_key(public_key)
    queries: list[str] = []

    async def _resolve(qname: str, record_type: str):
        assert record_type == "TXT"
        queries.append(qname)
        if qname == "_awid.subdomain.acme.com":
            raise dns.resolver.NXDOMAIN
        if qname == "_awid.acme.com":
            return [_TxtAnswer(awid_txt_value(controller_did))]
        raise AssertionError(f"unexpected DNS query: {qname}")

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    authority = await verify_domain("subdomain.acme.com")

    assert authority.controller_did == controller_did
    assert authority.dns_name == "_awid.acme.com"
    assert authority.inherited is True
    assert queries == ["_awid.subdomain.acme.com", "_awid.acme.com"]


@pytest.mark.asyncio
async def test_discover_authoritative_registry_stops_at_registrable_parent(monkeypatch):
    queries: list[str] = []

    async def _resolve(qname: str, record_type: str):
        assert record_type == "TXT"
        queries.append(qname)
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    registry_url = await discover_authoritative_registry("subdomain.acme.com")

    assert registry_url == "https://api.awid.ai"
    assert queries == ["_awid.subdomain.acme.com", "_awid.acme.com"]

from __future__ import annotations

import dns.resolver
import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.dns_verify import (
    _candidate_domains_for_lookup,
    awid_txt_value,
    discover_authoritative_registry,
    verify_domain,
)


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

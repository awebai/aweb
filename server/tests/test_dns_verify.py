from __future__ import annotations

import pytest
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoNameservers

from aweb.awid import did_from_public_key, generate_keypair
from aweb.config import DEFAULT_AWID_REGISTRY_URL
from aweb.dns_verify import (
    DnsVerificationError,
    awid_txt_name,
    awid_txt_value,
    discover_authoritative_registry,
    verify_domain,
)


class _TxtRecord:
    def __init__(self, text: str) -> None:
        self.strings = [text.encode("utf-8")]


def _did_key() -> str:
    _signing_key, public_key = generate_keypair()
    return did_from_public_key(public_key)


@pytest.mark.asyncio
async def test_verify_domain_parses_awid_txt_record_with_explicit_registry(monkeypatch):
    did_key = _did_key()

    async def _resolve(qname: str, rrtype: str):
        assert qname == "_awid.acme.com"
        assert rrtype == "TXT"
        return [_TxtRecord(f"awid=v1; controller={did_key}; registry=https://registry.acme.test;")]

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    authority = await verify_domain("acme.com")

    assert authority.controller_did == did_key
    assert authority.registry_url == "https://registry.acme.test"
    assert authority.dns_name == "_awid.acme.com"
    assert authority.inherited is False


@pytest.mark.asyncio
async def test_verify_domain_defaults_registry_when_field_absent(monkeypatch):
    did_key = _did_key()

    async def _resolve(_qname: str, _rrtype: str):
        return [_TxtRecord(f"awid=v1; controller={did_key};")]

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    authority = await verify_domain("acme.com")

    assert authority.controller_did == did_key
    assert authority.registry_url == DEFAULT_AWID_REGISTRY_URL


@pytest.mark.asyncio
async def test_discover_authoritative_registry_inherits_from_parent_record(monkeypatch):
    did_key = _did_key()

    async def _resolve(qname: str, _rrtype: str):
        if qname == "_awid.project.aweb.ai":
            raise NXDOMAIN()
        if qname == "_awid.aweb.ai":
            return [_TxtRecord(f"awid=v1; controller={did_key}; registry=https://registry.aweb.test;")]
        raise AssertionError(f"unexpected qname {qname}")

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    registry_url = await discover_authoritative_registry("project.aweb.ai")

    assert registry_url == "https://registry.aweb.test"


@pytest.mark.asyncio
async def test_discover_authoritative_registry_falls_back_to_default_when_absent(monkeypatch):
    async def _resolve(_qname: str, _rrtype: str):
        raise NXDOMAIN()

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    assert await discover_authoritative_registry("missing.example") == DEFAULT_AWID_REGISTRY_URL


@pytest.mark.asyncio
async def test_discovery_caps_ancestor_walk_at_registered_domain_boundary(monkeypatch):
    queries: list[str] = []

    async def _resolve(qname: str, _rrtype: str):
        queries.append(qname)
        raise NXDOMAIN()

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)
    monkeypatch.setattr(
        "aweb.dns_verify._registered_domain_boundary",
        lambda _domain: "project.github.io",
    )

    assert await discover_authoritative_registry("project.github.io") == DEFAULT_AWID_REGISTRY_URL
    assert queries == ["_awid.project.github.io"]


@pytest.mark.asyncio
async def test_discovery_ignores_unrelated_txt_records_and_falls_back(monkeypatch):
    async def _resolve(qname: str, _rrtype: str):
        if qname == "_awid.project.aweb.ai":
            raise NXDOMAIN()
        if qname == "_awid.aweb.ai":
            return [_TxtRecord("v=spf1 include:_spf.example.test ~all")]
        raise AssertionError(f"unexpected qname {qname}")

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)
    monkeypatch.setattr("aweb.dns_verify._registered_domain_boundary", lambda _domain: "aweb.ai")

    assert await discover_authoritative_registry("project.aweb.ai") == DEFAULT_AWID_REGISTRY_URL


def test_awid_txt_helpers_emit_release_contract() -> None:
    did_key = _did_key()
    assert awid_txt_name("Acme.com.") == "_awid.acme.com"
    assert awid_txt_value(did_key) == f"awid=v1; controller={did_key};"
    assert (
        awid_txt_value(did_key, "https://api.awid.ai/")
        == f"awid=v1; controller={did_key}; registry=https://api.awid.ai;"
    )


@pytest.mark.asyncio
async def test_verify_domain_rejects_invalid_registry_origin(monkeypatch):
    did_key = _did_key()

    async def _resolve(_qname: str, _rrtype: str):
        return [_TxtRecord(f"awid=v1; controller={did_key}; registry=not-a-url;")]

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    with pytest.raises(DnsVerificationError, match="Invalid registry origin"):
        await verify_domain("acme.com")


@pytest.mark.asyncio
async def test_verify_domain_rejects_duplicate_fields(monkeypatch):
    did_key = _did_key()

    async def _resolve(_qname: str, _rrtype: str):
        return [_TxtRecord(f"awid=v1; controller={did_key}; controller={did_key};")]

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    with pytest.raises(DnsVerificationError, match="Duplicate controller"):
        await verify_domain("acme.com")


@pytest.mark.asyncio
async def test_discovery_treats_timeout_as_hard_failure(monkeypatch):
    async def _resolve(qname: str, _rrtype: str):
        if qname == "_awid.project.aweb.ai":
            raise NXDOMAIN()
        if qname == "_awid.aweb.ai":
            raise Timeout()
        raise AssertionError(f"unexpected qname {qname}")

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)
    monkeypatch.setattr("aweb.dns_verify._registered_domain_boundary", lambda _domain: "aweb.ai")

    with pytest.raises(DnsVerificationError, match="DNS lookup failed"):
        await discover_authoritative_registry("project.aweb.ai")


@pytest.mark.asyncio
async def test_discovery_treats_no_nameservers_as_hard_failure(monkeypatch):
    async def _resolve(_qname: str, _rrtype: str):
        raise NoNameservers()

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    with pytest.raises(DnsVerificationError, match="DNS lookup failed"):
        await discover_authoritative_registry("example.com")


@pytest.mark.asyncio
async def test_verify_domain_rejects_private_ip_registry(monkeypatch):
    did_key = _did_key()

    async def _resolve(_qname: str, _rrtype: str):
        return [_TxtRecord(f"awid=v1; controller={did_key}; registry=https://169.254.169.254;")]

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    with pytest.raises(DnsVerificationError, match="Invalid registry origin"):
        await verify_domain("acme.com")


@pytest.mark.asyncio
async def test_verify_domain_rejects_localhost_registry(monkeypatch):
    did_key = _did_key()

    async def _resolve(_qname: str, _rrtype: str):
        return [_TxtRecord(f"awid=v1; controller={did_key}; registry=https://localhost;")]

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)

    with pytest.raises(DnsVerificationError, match="Invalid registry origin"):
        await verify_domain("acme.com")


@pytest.mark.asyncio
async def test_verify_domain_requires_https_registry_in_production(monkeypatch):
    did_key = _did_key()

    async def _resolve(_qname: str, _rrtype: str):
        return [_TxtRecord(f"awid=v1; controller={did_key}; registry=http://registry.example;")]

    monkeypatch.setattr("dns.asyncresolver.resolve", _resolve)
    monkeypatch.setenv("APP_ENV", "production")

    with pytest.raises(DnsVerificationError, match="Invalid registry origin"):
        await verify_domain("acme.com")

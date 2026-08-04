from __future__ import annotations

import pytest

from awid.external_authority import DNSLookup
from awid.federation_errors import FederationAuthorityError
from aweb.federation.activation import build_federation_authority_activation


class _DB:
    def get_manager(self, _name: str = "aweb") -> object:
        return object()


class _UnexpectedDNSResolver:
    async def lookup_txt(self, name: str):
        raise AssertionError(f"test default registry unexpectedly queried DNS: {name}")


class _TimeoutDNSResolver:
    async def lookup_txt(self, name: str) -> DNSLookup:
        assert name == "_awid.test.local"
        return DNSLookup("timeout")


@pytest.mark.asyncio
async def test_explicit_test_default_registry_avoids_external_dns(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
    monkeypatch.setenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "1")
    monkeypatch.setenv("AWID_REGISTRY_URL", "http://awid:8010")

    activation = build_federation_authority_activation(
        _DB(), public_origin="http://localhost:8100"
    )
    activation.txt_resolver = _UnexpectedDNSResolver()

    authority = await activation._discover_registry_authority("test.local")

    assert authority.selection == "public_default"
    assert authority.authority_name == ""
    assert authority.controller_did is None
    assert authority.registry_origin == "http://awid:8010"


@pytest.mark.asyncio
async def test_without_explicit_test_default_dns_failure_still_fails_closed(
    monkeypatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
    monkeypatch.delenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", raising=False)
    monkeypatch.setenv("AWID_REGISTRY_URL", "http://awid:8010")

    activation = build_federation_authority_activation(
        _DB(), public_origin="http://localhost:8100"
    )
    activation.txt_resolver = _TimeoutDNSResolver()

    with pytest.raises(FederationAuthorityError) as raised:
        await activation._discover_registry_authority("test.local")

    assert raised.value.reason == "sender_registry_discovery_failed"


@pytest.mark.parametrize(
    ("app_env", "federation_test"),
    [("production", "1"), ("development", "0")],
)
def test_test_default_registry_requires_both_development_guards(
    monkeypatch, app_env: str, federation_test: str
) -> None:
    monkeypatch.setenv("APP_ENV", app_env)
    monkeypatch.setenv("AWEB_FEDERATION_TEST", federation_test)
    monkeypatch.setenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "1")
    monkeypatch.setenv("AWID_REGISTRY_URL", "http://awid:8010")

    with pytest.raises(ValueError, match="test default registry requires"):
        build_federation_authority_activation(
            _DB(), public_origin="http://localhost:8100"
        )

"""The operator's internal app origins: read and checked at startup, never from an install."""

from __future__ import annotations

from ipaddress import ip_network

import pytest
from aweb.app_manifests import ManifestFetcher
from aweb.config import get_app_internal_origins, get_settings
from aweb_naapp.egress import InternalDestinations

ORIGINS = "AWEB_APP_INTERNAL_ORIGINS"
CIDR = "AWEB_APP_INTERNAL_CIDR"


@pytest.fixture(autouse=True)
def unset(monkeypatch):
    monkeypatch.delenv(ORIGINS, raising=False)
    monkeypatch.delenv(CIDR, raising=False)


def test_by_default_no_origin_is_internal_and_the_fetcher_stays_public():
    internal = get_app_internal_origins()
    assert internal.origins == frozenset()
    assert internal.cidr is None
    assert ManifestFetcher().egress.addresses.internal_destinations is InternalDestinations.DISABLED


def test_listed_origins_are_exact_canonical_origins_within_one_network(monkeypatch):
    monkeypatch.setenv(ORIGINS, '["https://API.Secrets.example:443", "https://logs.example:8443/"]')
    monkeypatch.setenv(CIDR, "10.96.0.0/12")
    internal = get_app_internal_origins()
    assert internal.origins == frozenset({"https://api.secrets.example", "https://logs.example:8443"})
    assert internal.cidr == ip_network("10.96.0.0/12")
    fetcher = ManifestFetcher()
    assert fetcher.internal == internal
    assert fetcher.egress.addresses.internal_destinations is InternalDestinations.ALLOWED


@pytest.mark.parametrize("origins, cidr", [
    ('["https://api.secrets.example"]', None),
    (None, "10.96.0.0/12"),
])
def test_origins_and_network_come_together(monkeypatch, origins, cidr):
    for name, value in ((ORIGINS, origins), (CIDR, cidr)):
        if value is not None:
            monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        get_app_internal_origins()


@pytest.mark.parametrize("origins", [
    "https://api.secrets.example",
    "[]",
    '["http://api.secrets.example"]',
    '["https://api.secrets.example/catalog"]',
    '["https://api.secrets.example?x=1"]',
    '["https://user@api.secrets.example"]',
    "[17]",
])
def test_anything_but_a_list_of_exact_https_origins_is_refused(monkeypatch, origins):
    monkeypatch.setenv(ORIGINS, origins)
    monkeypatch.setenv(CIDR, "10.96.0.0/12")
    with pytest.raises(ValueError):
        get_app_internal_origins()


@pytest.mark.parametrize("cidr", ["10.0.0.0/7", "10.96.0.1/12", "127.0.0.0/8", "169.254.0.0/16", "not-a-network"])
def test_the_network_must_be_an_exact_permitted_internal_network(monkeypatch, cidr):
    monkeypatch.setenv(ORIGINS, '["https://api.secrets.example"]')
    monkeypatch.setenv(CIDR, cidr)
    with pytest.raises(ValueError):
        get_app_internal_origins()


def test_startup_settings_refuse_a_bad_internal_origin_setting(monkeypatch):
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused@localhost/unused")
    monkeypatch.setenv(ORIGINS, '["http://api.secrets.example"]')
    monkeypatch.setenv(CIDR, "10.96.0.0/12")
    with pytest.raises(ValueError):
        get_settings()

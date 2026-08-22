import pytest

from awid.registry import CachedRegistryClient

from aweb.api import _build_awid_registry_client, create_app
from aweb.config import DEFAULT_AWID_REGISTRY_URL, get_awid_registry_url, get_awid_service_token


class _StubRedis:
    """Stands in for a configured Redis. _build_awid_registry_client only stores
    it, so no command surface is needed to reach the construction under test."""


def _route_paths(app) -> set[str]:
    return {route.path for route in app.router.routes}


def test_registry_url_defaults_to_remote(monkeypatch):
    monkeypatch.delenv("AWID_REGISTRY_URL", raising=False)

    assert get_awid_registry_url() == DEFAULT_AWID_REGISTRY_URL


def test_local_registry_url_is_rejected(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "local")

    with pytest.raises(ValueError, match="AWID_REGISTRY_URL=local is no longer supported"):
        get_awid_registry_url()


def test_registry_url_empty_string_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "")

    assert get_awid_registry_url() == DEFAULT_AWID_REGISTRY_URL


def test_registry_url_whitespace_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "   ")

    assert get_awid_registry_url() == DEFAULT_AWID_REGISTRY_URL


def test_registry_url_local_detection_is_rejected_case_insensitively(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "  LOCAL  ")

    with pytest.raises(ValueError, match="AWID_REGISTRY_URL=local is no longer supported"):
        get_awid_registry_url()


def test_aweb_registry_client_rejects_missing_service_token(monkeypatch):
    monkeypatch.delenv("AWID_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")

    with pytest.raises(ValueError, match="AWID_SERVICE_TOKEN is required") as caught:
        _build_awid_registry_client(create_app(), redis=None)

    assert "openssl rand -hex 32" in str(caught.value)
    assert "same value on aweb and AWID" in str(caught.value)


@pytest.mark.parametrize("value", ["", "   "])
def test_aweb_registry_client_rejects_empty_service_token(monkeypatch, value):
    monkeypatch.setenv("AWID_SERVICE_TOKEN", value)

    with pytest.raises(ValueError, match="AWID_SERVICE_TOKEN is required"):
        get_awid_service_token()


@pytest.mark.asyncio
async def test_aweb_registry_client_receives_configured_service_token(monkeypatch):
    token = "trusted-service-token-with-at-least-32-bytes"
    monkeypatch.setenv("AWID_SERVICE_TOKEN", token)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")

    client = _build_awid_registry_client(create_app(), redis=None)
    try:
        assert client.service_token == token
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_aweb_cached_registry_client_receives_configured_service_token(monkeypatch):
    """redis=None is the branch no deployment runs: docker-compose and production
    both configure Redis, so _build_awid_registry_client returns the cached class
    there. Cover the branch that boots the server."""
    token = "trusted-service-token-with-at-least-32-bytes"
    monkeypatch.setenv("AWID_SERVICE_TOKEN", token)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")

    client = _build_awid_registry_client(create_app(), redis=_StubRedis())
    try:
        assert isinstance(client, CachedRegistryClient)
        assert client.service_token == token
    finally:
        await client.aclose()


def test_create_app_never_mounts_awid_registry_routes(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "https://api.awid.ai")

    app = create_app()
    paths = _route_paths(app)

    assert "/v1/did" not in paths
    assert "/v1/namespaces" not in paths
    assert "/v1/namespaces/{domain}/addresses" not in paths

import pytest

from aweb.api import create_app
from aweb.config import DEFAULT_AWID_REGISTRY_URL, get_awid_registry_url


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


def test_create_app_never_mounts_awid_registry_routes(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "https://api.awid.ai")

    app = create_app()
    paths = _route_paths(app)

    assert "/v1/did" not in paths
    assert "/v1/namespaces" not in paths
    assert "/v1/namespaces/{domain}/addresses" not in paths

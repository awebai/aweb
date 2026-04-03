from aweb.api import create_app
from aweb.config import DEFAULT_AWID_REGISTRY_URL, get_awid_registry_url, is_local_awid_registry_url


def _route_paths(app) -> set[str]:
    return {route.path for route in app.router.routes}


def test_registry_url_defaults_to_remote(monkeypatch):
    monkeypatch.delenv("AWID_REGISTRY_URL", raising=False)

    assert get_awid_registry_url() == DEFAULT_AWID_REGISTRY_URL
    assert is_local_awid_registry_url() is False


def test_local_registry_url_detection(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "local")

    assert get_awid_registry_url() == "local"
    assert is_local_awid_registry_url() is True


def test_registry_url_empty_string_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "")

    assert get_awid_registry_url() == DEFAULT_AWID_REGISTRY_URL
    assert is_local_awid_registry_url() is False


def test_registry_url_whitespace_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "   ")

    assert get_awid_registry_url() == DEFAULT_AWID_REGISTRY_URL
    assert is_local_awid_registry_url() is False


def test_registry_url_local_detection_is_case_and_whitespace_insensitive(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "  LOCAL  ")

    assert get_awid_registry_url() == "LOCAL"
    assert is_local_awid_registry_url() is True


def test_create_app_omits_embedded_registry_routes_when_remote(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "https://api.awid.ai")

    app = create_app()
    paths = _route_paths(app)

    assert "/v1/did" not in paths
    assert "/v1/namespaces" not in paths
    assert "/v1/namespaces/{domain}/addresses" not in paths


def test_create_app_mounts_embedded_registry_routes_when_local(monkeypatch):
    monkeypatch.setenv("AWID_REGISTRY_URL", "local")

    app = create_app()
    paths = _route_paths(app)

    assert "/v1/did" in paths
    assert "/v1/namespaces" in paths
    assert "/v1/namespaces/{domain}/addresses" in paths

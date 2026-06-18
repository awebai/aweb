from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import library.api as library_api
from library.config import Settings

_TEAM_SCOPED = [
    ("POST", "/v1/profile-packs/import"),
    ("POST", "/v1/agents/agent-1/profile-binding"),
    ("GET", "/v1/agents/agent-1/profile-binding"),
    ("POST", "/v1/materialize"),
    ("POST", "/v1/proposals"),
    ("GET", "/v1/proposals"),
    ("POST", "/v1/proposals/prop-1/approve"),
    ("POST", "/v1/proposals/prop-1/reject"),
]


def _app():
    return library_api.create_app(Settings(public_origin="https://library.aweb.ai"))


def _override_infra_deps(app) -> None:
    """Override the db/team_cache infra dependencies so the cert-auth path runs
    (and rejects on the missing header) without a live database."""
    seen: set[int] = set()

    def walk(dependant) -> None:
        for sub in dependant.dependencies:
            walk(sub)
        call = dependant.call
        if getattr(call, "__name__", "") in {"db", "team_cache"} and id(call) not in seen:
            app.dependency_overrides[call] = lambda: object()
            seen.add(id(call))

    for route in app.routes:
        dependant = getattr(route, "dependant", None)
        if dependant is not None:
            walk(dependant)


def test_landing_page_is_served() -> None:
    response = TestClient(_app()).get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "library" in response.text
    assert "https://awid.ai" in response.text


def test_health_endpoints_are_public() -> None:
    client = TestClient(_app())
    for path in ("/health", "/live", "/ready"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.json() == {"status": "ok", "service": "library"}


def test_public_catalog_reads_are_unauthenticated_stubs() -> None:
    client = TestClient(_app())

    packs = client.get("/v1/profile-packs")
    assert packs.status_code == 200
    assert packs.json() == []

    assert client.get("/v1/profile-packs/does-not-exist").status_code == 404
    assert client.get("/v1/profiles/does-not-exist").status_code == 404


@pytest.mark.parametrize("method,path", _TEAM_SCOPED)
def test_team_scoped_routes_require_team_certificate_auth(method: str, path: str) -> None:
    app = _app()
    _override_infra_deps(app)
    response = TestClient(app).request(method, path)
    assert response.status_code == 401, (method, path, response.text)


@pytest.mark.parametrize("method,path", _TEAM_SCOPED)
def test_team_scoped_routes_exist_and_are_not_404(method: str, path: str) -> None:
    # Sanity: the routes are registered (a 401 from auth, never a 404 missing route).
    app = _app()
    _override_infra_deps(app)
    response = TestClient(app).request(method, path)
    assert response.status_code != 404, (method, path)

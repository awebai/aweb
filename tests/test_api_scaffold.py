from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import library.api as library_api
from library.config import Settings

_TEAM_SCOPED = [
    ("POST", "/v1/blueprints/import"),
    ("POST", "/v1/shelf/import"),
    ("POST", "/v1/profiles/coordinator/publish"),
    ("POST", "/v1/profiles/coordinator/update-from-source"),
    ("GET", "/v1/shelf"),
    ("GET", "/v1/profiles/coordinator"),
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


class _FakeDB:
    async def fetch_all(self, *args, **kwargs):
        return []

    async def fetch_one(self, *args, **kwargs):
        return None


def _override_infra_deps(app, *, db_value=None) -> None:
    """Override the db/team_cache infra dependencies so routes can run without a
    live database — cert-auth paths reject on the missing header, and read paths
    use the supplied fake db."""
    db_obj = db_value if db_value is not None else object()
    seen: set[int] = set()

    def walk(dependant) -> None:
        for sub in dependant.dependencies:
            walk(sub)
        call = dependant.call
        name = getattr(call, "__name__", "")
        if name == "db" and id(call) not in seen:
            app.dependency_overrides[call] = lambda: db_obj
            seen.add(id(call))
        elif name == "team_cache" and id(call) not in seen:
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
    # Styled with the shared aweb design system.
    assert '<link rel="stylesheet" href="/css/aweb.css">' in response.text


def test_aweb_css_served_verbatim() -> None:
    import hashlib

    response = TestClient(_app()).get("/css/aweb.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]
    # Byte-for-byte the vendored aweb design system (source sha recorded in surfaces).
    assert (
        hashlib.sha256(response.content).hexdigest()
        == "6b2acef0d614c33508fe0f4e7270b4a2770ef18fb45d856c0d3e7862f85f2c19"
    )


def test_health_endpoints_are_public() -> None:
    client = TestClient(_app())
    for path in ("/health", "/live", "/ready"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.json() == {"status": "ok", "service": "library"}


def test_public_blueprint_catalog_is_unauthenticated() -> None:
    # Blueprints are the public catalog (no cert). Shelf reads (/v1/shelf) are
    # private and cert-gated — covered by the team-scoped 401 cases above.
    app = _app()
    _override_infra_deps(app, db_value=_FakeDB())
    client = TestClient(app)

    assert client.get("/v1/blueprints").json() == []
    assert client.get("/v1/blueprints/does-not-exist").status_code == 404
    # A public profile read is also unauthenticated (404, not 401, without a cert).
    assert client.get("/v1/blueprints/none/profiles/none").status_code == 404


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

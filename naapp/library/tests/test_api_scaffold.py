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


def test_landing_page_is_served() -> None:
    response = TestClient(_app()).get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "library" in response.text
    assert "https://awid.ai" in response.text
    # Styled with the shared aweb design system, at the fingerprinted css URL.
    from aweb_naapp import CSS_SHA256

    assert f'<link rel="stylesheet" href="/css/aweb.{CSS_SHA256[:12]}.css">' in response.text


def test_aweb_css_served_verbatim() -> None:
    import hashlib

    from aweb_naapp import CSS_SHA256

    response = TestClient(_app()).get("/css/aweb.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]
    # Byte-for-byte the aweb design system the toolkit ships (its own sha pin).
    assert hashlib.sha256(response.content).hexdigest() == CSS_SHA256
    assert "--accent: #2342e8;" in response.text  # redesigned light palette
    assert "--bg: #17191c;" in response.text  # carbon dark palette
    assert "--accent: #a5b5ff;" in response.text  # blue dark-mode action


def test_og_card_and_fingerprinted_css_served() -> None:
    from aweb_naapp import CSS_SHA256

    client = TestClient(_app())
    og = client.get("/og-card.png")
    assert og.status_code == 200
    assert og.headers["content-type"] == "image/png"
    assert og.content[:8] == b"\x89PNG\r\n\x1a\n"
    # The fingerprinted css URL serves the same stylesheet, cached immutably.
    css = client.get(f"/css/aweb.{CSS_SHA256[:12]}.css")
    assert css.status_code == 200
    assert "text/css" in css.headers["content-type"]
    assert "immutable" in css.headers["cache-control"]


def test_packaged_open_font_is_served_for_aweb_css() -> None:
    client = TestClient(_app())
    css = client.get("/css/aweb.css").text
    for font_name in ("Archivo-Latin-Variable.woff2",):
        assert f'url("/fonts/{font_name}")' in css
        response = client.get(f"/fonts/{font_name}")
        assert response.status_code == 200
        assert response.headers["content-type"] == "font/woff2"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "immutable" in response.headers["cache-control"]
        assert response.content.startswith(b"wOF2")

    assert client.get("/fonts/NotAFont.woff2").status_code == 404
    assert client.get("/fonts/BerkeleyMono-Regular.woff2").status_code == 404


def test_health_endpoints_are_public(library_client: TestClient) -> None:
    for path in ("/health", "/live", "/ready"):
        response = library_client.get(path)
        assert response.status_code == 200, path
        body = response.json()
        assert body["status"] == "ok", path
        assert body["service"] == "library", path
        assert body["build"] == {"git_sha": None}, path


def test_public_blueprint_catalog_is_unauthenticated(library_client: TestClient) -> None:
    # Blueprints are the public catalog (no cert). Shelf reads (/v1/shelf) are
    # private and cert-gated — covered by the team-scoped 401 cases below.
    assert library_client.get("/v1/blueprints").json() == []
    assert library_client.get("/v1/blueprints/does-not-exist").status_code == 404
    # A public profile read is also unauthenticated (404, not 401, without a cert).
    assert library_client.get("/v1/blueprints/none/profiles/none").status_code == 404


@pytest.mark.parametrize("method,path", _TEAM_SCOPED)
def test_team_scoped_routes_require_team_certificate_auth(method: str, path: str) -> None:
    response = TestClient(_app()).request(method, path)
    assert response.status_code == 401, (method, path, response.text)


@pytest.mark.parametrize("method,path", _TEAM_SCOPED)
def test_team_scoped_routes_exist_and_are_not_404(method: str, path: str) -> None:
    # Sanity: the routes are registered (a 401 from auth, never a 404 missing route).
    response = TestClient(_app()).request(method, path)
    assert response.status_code != 404, (method, path)

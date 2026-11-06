"""Public and human-origin mounts serve the same toolkit asset responses."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aweb_naapp import CSS_SHA256, aweb_css
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp.css import FONT_NAMES, font_bytes
from tests.test_routes import _client


def console_client():
    from aweb_naapp.console import console_assets_router

    app = FastAPI()
    app.include_router(console_assets_router())
    return TestClient(app)


def test_anonymous_console_assets_match_public_bytes_mime_and_cache(tmp_path):
    public, console = _client(tmp_path, omit_fonts_dir=True), console_client()
    expected = {
        f"/css/aweb.{CSS_SHA256[:12]}.css": aweb_css().encode(),
        **{f"/fonts/{name}": font_bytes(name) for name in FONT_NAMES},
    }
    for path, content in expected.items():
        human, api = console.get(path), public.get(path)
        assert human.status_code == api.status_code == 200
        assert human.content == api.content == content
        for name in ("content-type", "content-length", "cache-control", "x-content-type-options"):
            assert human.headers[name] == api.headers[name]
        assert human.headers["cache-control"] == "public, max-age=31536000, immutable"
        for name, value in CONSOLE_HEADERS.items():
            if name.lower() != "cache-control":
                assert human.headers[name] == value
        assert "set-cookie" not in human.headers
    assert not console.cookies


@pytest.mark.parametrize(
    "path",
    [
        "/fonts/BerkeleyMono-Regular.woff2",
        "/fonts/unknown.woff2",
        "/fonts/../console/__init__.py",
        "/fonts/%2e%2e%2fconsole%2f__init__.py",
        "/css/aweb.css",
        "/css/aweb.unknown.css",
    ],
)
def test_console_assets_refuse_other_names_and_traversal(path):
    response = console_client().get(path)
    assert response.status_code == 404
    assert "set-cookie" not in response.headers


def test_unknown_toolkit_font_keeps_console_refusal_headers():
    response = console_client().get("/fonts/unknown.woff2")
    assert response.status_code == 404
    for name, value in CONSOLE_HEADERS.items():
        assert response.headers[name] == value

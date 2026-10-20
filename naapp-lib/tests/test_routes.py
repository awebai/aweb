from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict

from aweb_naapp import CSS_SHA256, aweb_css
from aweb_naapp.manifest import canonical_bytes, manifest_for_origin, write_manifest_file
from aweb_naapp.runtime.app import NaappRuntime, mount_naapp_routes
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.skills import Skills

_HOSTED = "https://example.test"
_MANIFEST = {"manifest_version": 1, "app": {"id": "example", "origin": _HOSTED}, "tools": []}
_OG_CARD = b"\x89PNG\r\n\x1a\nexample-card"


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    database_url: str = "postgresql://localhost/example"
    public_origin: str = _HOSTED
    app_id: str = "example"


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("EXAMPLE_SKILLS_DIR", "EXAMPLE_GIT_SHA", "RENDER_GIT_COMMIT"):
        monkeypatch.delenv(name, raising=False)


def _client(tmp_path: Path, **overrides: object) -> TestClient:
    tmp_path.mkdir(parents=True, exist_ok=True)
    manifest_path = tmp_path / "aweb-app.json"
    write_manifest_file(manifest_path, _MANIFEST)
    skills_dir = tmp_path / "skills"
    (skills_dir / "hello").mkdir(parents=True)
    (skills_dir / "hello" / "SKILL.md").write_text("# Hello\n", encoding="utf-8")

    async def landing() -> str:
        return "<html>landing</html>"

    settings = overrides.pop("settings", None) or ExampleSettings(_env_file=None)
    runtime = NaappRuntime(settings, module_name="example", migrations_path=tmp_path)
    app = FastAPI(lifespan=runtime.lifespan)
    options: dict[str, object] = dict(
        runtime=runtime,
        manifest_path=manifest_path,
        skills=Skills(app_name="example", env_var="EXAMPLE_SKILLS_DIR", source_dir=skills_dir),
        landing=landing,
        reference_html="<html>reference</html>",
        llms_txt="# example\n",
        og_card_png=_OG_CARD,
    )
    options.update(overrides)
    mount_naapp_routes(app, **options)  # type: ignore[arg-type]

    @app.get("/present/{token}")
    async def presented(token: str) -> dict[str, str]:
        return {"token": token}

    return TestClient(app)


def test_landing_reference_and_llms_are_served(tmp_path: Path) -> None:
    client = _client(tmp_path)
    landing = client.get("/")
    assert landing.status_code == 200
    assert landing.headers["content-type"].startswith("text/html")
    assert landing.text == "<html>landing</html>"
    assert client.get("/reference").text == "<html>reference</html>"
    llms = client.get("/llms.txt")
    assert llms.headers["content-type"].startswith("text/plain")
    assert llms.headers["x-content-type-options"] == "nosniff"
    assert llms.text == "# example\n"


def test_css_is_served_with_a_short_ttl_and_immutable_when_fingerprinted(tmp_path: Path) -> None:
    client = _client(tmp_path)
    plain = client.get("/css/aweb.css")
    fingerprinted = client.get(f"/css/aweb.{CSS_SHA256[:12]}.css")
    for response in (plain, fingerprinted):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/css")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.text == aweb_css()
    assert plain.headers["cache-control"] == "public, max-age=3600"
    assert fingerprinted.headers["cache-control"] == "public, max-age=31536000, immutable"


def test_og_card_is_the_app_card(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/og-card.png")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content == _OG_CARD


def test_manifest_is_the_committed_bytes_at_both_paths(tmp_path: Path) -> None:
    client = _client(tmp_path)
    committed = (tmp_path / "aweb-app.json").read_bytes()
    for path in ("/.well-known/aweb-app.json", "/aweb-app.json"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.content == committed


def test_manifest_follows_a_self_hosted_origin(tmp_path: Path) -> None:
    origin = "http://127.0.0.1:9876"
    settings = ExampleSettings(_env_file=None, public_origin=origin)
    response = _client(tmp_path, settings=settings).get("/.well-known/aweb-app.json")
    assert response.content == canonical_bytes(manifest_for_origin(_MANIFEST, origin))
    assert json.loads(response.content)["app"]["origin"] == origin


def test_skills_are_served_and_unknown_skills_are_not_found(tmp_path: Path) -> None:
    client = _client(tmp_path)
    index = client.get("/skills/")
    assert index.status_code == 200
    assert "- GET /skills/hello/SKILL.md" in index.text
    skill = client.get("/skills/hello/SKILL.md")
    assert skill.headers["content-type"].startswith("text/plain")
    assert skill.headers["x-content-type-options"] == "nosniff"
    assert skill.text == "# Hello\n"
    assert client.get("/skills/missing/SKILL.md").status_code == 404
    assert client.get("/skills/../../README.md").status_code == 404


def test_robots_follow_the_app_rules(tmp_path: Path) -> None:
    allow_all = _client(tmp_path).get("/robots.txt")
    assert allow_all.headers["content-type"].startswith("text/plain")
    assert allow_all.text == "User-agent: *\nAllow: /\n"
    disallowing = _client(tmp_path / "b", robots_disallow=("/present/",)).get("/robots.txt")
    assert disallowing.text == "User-agent: *\nDisallow: /present/\n"


def test_noindex_paths_are_tagged_even_when_not_found(tmp_path: Path) -> None:
    client = _client(tmp_path, noindex_paths=("/present/", "/assets/"))
    for path in ("/present/abc", "/assets/not-a-uuid/extra"):
        assert client.get(path).headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    assert "x-robots-tag" not in client.get("/").headers


def test_without_noindex_paths_nothing_is_tagged(tmp_path: Path) -> None:
    assert "x-robots-tag" not in _client(tmp_path).get("/present/abc").headers


def test_health_is_mounted(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/health")
    assert response.json() == {"status": "ok", "service": "example", "build": {"git_sha": None}}

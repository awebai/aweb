from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict

from aweb_naapp import CSS_SHA256, aweb_css
from aweb_naapp.css import FONT_NAMES
from aweb_naapp.manifest import (
    ManifestError,
    canonical_bytes,
    manifest_for_origin,
    select_variant,
    write_manifest_file,
)
from aweb_naapp.runtime.app import NaappRuntime, mount_manifest_routes, mount_naapp_routes
from aweb_naapp.runtime.health import CheckResult
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


def _font_bytes(name: str) -> bytes:
    return b"wOF2" + name.encode("utf-8")


def _client(tmp_path: Path, *, committed: bytes | None = None, **overrides: object) -> TestClient:
    tmp_path.mkdir(parents=True, exist_ok=True)
    manifest_path = tmp_path / "aweb-app.json"
    if committed is None:
        write_manifest_file(manifest_path, _MANIFEST)
    else:
        manifest_path.write_bytes(committed)
    skills_dir = tmp_path / "skills"
    (skills_dir / "hello").mkdir(parents=True)
    (skills_dir / "hello" / "SKILL.md").write_text("# Hello\n", encoding="utf-8")
    fonts_dir = tmp_path / "fonts"
    fonts_dir.mkdir(exist_ok=True)
    for name in FONT_NAMES:
        (fonts_dir / name).write_bytes(_font_bytes(name))

    async def landing() -> str:
        return "<html>landing</html>"

    settings = overrides.pop("settings", None) or ExampleSettings(_env_file=None)
    runtime = NaappRuntime(
        settings, module_name="example", migrations_path=tmp_path, manifest_path=manifest_path
    )
    app = FastAPI(lifespan=runtime.lifespan)
    app.state.runtime = runtime
    options: dict[str, object] = dict(
        runtime=runtime,
        skills=Skills(app_name="example", env_var="EXAMPLE_SKILLS_DIR", source_dir=skills_dir),
        landing=landing,
        reference_html="<html>reference</html>",
        llms_txt="# example\n",
        og_card_png=_OG_CARD,
        fonts_dir=fonts_dir,
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


def test_the_stylesheet_fonts_are_served_from_the_app_directory(tmp_path: Path) -> None:
    client = _client(tmp_path)
    for name in FONT_NAMES:
        response = client.get(f"/fonts/{name}")
        assert response.status_code == 200
        assert response.headers["content-type"] == "font/woff2"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
        assert response.content == _font_bytes(name)


def test_only_the_stylesheet_fonts_are_served(tmp_path: Path) -> None:
    client = _client(tmp_path)
    (tmp_path / "fonts" / "Other.woff2").write_bytes(b"wOF2other")
    assert client.get("/fonts/Other.woff2").status_code == 404
    assert client.get("/fonts/..%2Faweb-app.json").status_code == 404


def test_the_fonts_are_the_ones_the_stylesheet_loads() -> None:
    loaded = set(re.findall(r'url\("/fonts/([^"]+)"\)', aweb_css()))
    assert loaded == set(FONT_NAMES)


def test_a_fonts_directory_missing_a_stylesheet_font_is_refused(tmp_path: Path) -> None:
    missing = sorted(FONT_NAMES)[0]
    fonts_dir = tmp_path / "partial-fonts"
    fonts_dir.mkdir()
    for name in FONT_NAMES:
        if name != missing:
            (fonts_dir / name).write_bytes(_font_bytes(name))
    with pytest.raises(FileNotFoundError, match=missing):
        _client(tmp_path, fonts_dir=fonts_dir)


def test_manifest_is_the_committed_bytes_at_both_paths(tmp_path: Path) -> None:
    client = _client(tmp_path)
    committed = (tmp_path / "aweb-app.json").read_bytes()
    for path in ("/.well-known/aweb-app.json", "/aweb-app.json"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.content == committed


def test_the_committed_origin_serves_the_committed_file_byte_for_byte(tmp_path: Path) -> None:
    committed = json.dumps(_MANIFEST, indent=2).encode("utf-8") + b"\n"
    response = _client(tmp_path, committed=committed).get("/.well-known/aweb-app.json")
    assert response.content == committed


def test_request_headers_never_change_the_served_manifest(tmp_path: Path) -> None:
    client = _client(tmp_path)
    expected = (tmp_path / "aweb-app.json").read_bytes()
    for headers in (
        {"Host": "evil.example"},
        {"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http"},
        {"Forwarded": "host=evil.example;proto=http"},
    ):
        response = client.get("/.well-known/aweb-app.json", headers=headers)
        assert response.content == expected, headers


def test_the_manifest_is_fixed_at_startup_and_served_verbatim(tmp_path: Path) -> None:
    client = _client(tmp_path)
    runtime = client.app.state.runtime
    first = client.get("/.well-known/aweb-app.json").content
    (tmp_path / "aweb-app.json").write_bytes(canonical_bytes({**_MANIFEST, "tools": ["changed"]}))
    digests = {
        hashlib.sha256(client.get(path).content).hexdigest()
        for path in ("/.well-known/aweb-app.json", "/aweb-app.json", "/aweb-app.json")
    }
    assert digests == {hashlib.sha256(first).hexdigest()}
    assert runtime.manifest_bytes == first
    assert runtime.manifest.document == json.loads(first)


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


def test_health_is_mounted_with_the_runtime_checks(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/health")
    assert response.json() == {
        "status": "unavailable",
        "service": "example",
        "build": {"git_sha": None},
        "checks": {"database": {"ok": False}, "outbox": {"ok": False}},
    }


def test_health_checks_the_apps_own_dependencies(tmp_path: Path) -> None:
    async def kms() -> CheckResult:
        return CheckResult(ok=True, detail={"canary_age_seconds": 4})

    response = _client(tmp_path, health_checks={"kms": kms}).get("/health")
    assert response.json()["checks"]["kms"] == {"ok": True, "canary_age_seconds": 4}


def test_an_app_without_the_docs_surface_serves_its_manifest_alone(tmp_path: Path) -> None:
    manifest_path = tmp_path / "aweb-app.json"
    write_manifest_file(manifest_path, _MANIFEST)
    runtime = NaappRuntime(
        ExampleSettings(_env_file=None),
        module_name="example",
        migrations_path=tmp_path,
        manifest_path=manifest_path,
    )
    app = FastAPI()
    mount_manifest_routes(app, runtime=runtime)
    client = TestClient(app)
    for path in ("/.well-known/aweb-app.json", "/aweb-app.json"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.content == manifest_path.read_bytes()
    for path in ("/", "/llms.txt", "/health"):
        assert client.get(path).status_code == 404


def test_an_app_without_the_docs_surface_serves_its_v2_manifest_through_its_catalog(tmp_path: Path) -> None:
    manifest_path = tmp_path / "aweb-app.json"
    write_manifest_file(manifest_path, _MANIFEST_V2)
    runtime = NaappRuntime(
        ExampleSettings(_env_file=None),
        module_name="example",
        migrations_path=tmp_path,
        manifest_path=manifest_path,
    )
    app = FastAPI()
    mount_manifest_routes(app, runtime=runtime)
    client = TestClient(app)
    variant = select_variant(_HOSTED, (1, 2), _fetch(client))
    assert (variant.source, variant.manifest_version) == ("catalog", 2)
    assert variant.data == manifest_path.read_bytes()
    assert client.get("/aweb-app.json").content == variant.data
    assert client.get("/.well-known/aweb-app.json").status_code == 404
    for path in ("/", "/llms.txt", "/health"):
        assert client.get(path).status_code == 404


# --- Manifest discovery --------------------------------------------------------

_MANIFEST_V2 = {
    "manifest_version": 2,
    "app": {"id": "example", "origin": _HOSTED},
    "tools": [{"name": "create", "method": "POST", "path": "/v1/things", "scopes": ["example:write"]}],
}


def _fetch(client: TestClient):
    def fetch(path: str, max_bytes: int) -> tuple[int, bytes]:
        response = client.get(path, follow_redirects=False)
        return response.status_code, response.content[:max_bytes]

    return fetch


def test_a_v2_app_is_discovered_through_its_catalog(tmp_path: Path) -> None:
    client = _client(tmp_path, committed=canonical_bytes(_MANIFEST_V2))
    variant = select_variant(_HOSTED, (1, 2), _fetch(client))
    assert (variant.source, variant.manifest_version) == ("catalog", 2)
    assert variant.data == client.app.state.runtime.manifest_bytes


def test_a_v2_app_serves_no_v1_manifest(tmp_path: Path) -> None:
    client = _client(tmp_path, committed=canonical_bytes(_MANIFEST_V2))
    assert client.get("/.well-known/aweb-app.json").status_code == 404
    with pytest.raises(ManifestError) as refused:
        select_variant(_HOSTED, (1,), _fetch(client))
    assert refused.value.code == "no_supported_variant"


def test_a_self_hosted_v2_app_lists_the_bytes_it_serves(tmp_path: Path) -> None:
    settings = ExampleSettings(_env_file=None, public_origin="http://self.test")
    client = _client(tmp_path, committed=canonical_bytes(_MANIFEST_V2), settings=settings)
    variant = select_variant("http://self.test", (2,), _fetch(client))
    assert variant.source == "catalog"
    assert json.loads(variant.data)["app"]["origin"] == "http://self.test"
    assert variant.data == client.app.state.runtime.manifest_bytes


def test_a_v1_app_is_discovered_at_the_legacy_path(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/.well-known/aweb-app-versions.json").status_code == 404
    variant = select_variant(_HOSTED, (1, 2), _fetch(client))
    assert (variant.source, variant.manifest_version) == ("legacy", 1)


def test_the_catalog_and_its_variant_are_fixed_at_startup(tmp_path: Path) -> None:
    client = _client(tmp_path, committed=canonical_bytes(_MANIFEST_V2))
    catalog = client.get("/.well-known/aweb-app-versions.json")
    assert catalog.status_code == 200
    catalog = catalog.content
    variant = select_variant(_HOSTED, (2,), _fetch(client))
    assert variant.source == "catalog"
    (tmp_path / "aweb-app.json").write_bytes(canonical_bytes({**_MANIFEST_V2, "tools": []}))
    assert client.get("/.well-known/aweb-app-versions.json").content == catalog
    assert select_variant(_HOSTED, (2,), _fetch(client)).data == variant.data
    assert client.get("/aweb-app.json").content == variant.data

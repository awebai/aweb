from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

import folio.api as folio_api
import folio.surfaces as surfaces
from folio.config import Settings


def _client() -> TestClient:
    settings = Settings(public_origin="https://folio.aweb.ai")
    return TestClient(folio_api.create_app(settings))


def _override_db_for_path(app, path: str) -> None:
    route = next(route for route in app.routes if getattr(route, "path", None) == path)
    db_dependency = route.dependant.dependencies[0].call
    app.dependency_overrides[db_dependency] = lambda: object()


def test_landing_page_explains_folio_and_links_agent_surfaces() -> None:
    response = _client().get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "private document and presentation service" in response.text
    assert "AWID team certificate" in response.text
    assert "https://aweb.ai" in response.text
    assert 'href="/llms.txt"' in response.text
    assert 'href="/skills/"' in response.text


def test_llms_txt_is_plain_text_agent_entrypoint() -> None:
    response = _client().get("/llms.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "folio — agent-first document and presentation service" in response.text
    assert "GET /present/{token}" in response.text
    assert "GET /skills/present-to-human/SKILL.md" in response.text
    assert "Cloudflare Stream" in response.text


def test_skills_surface_serves_index_and_individual_skills() -> None:
    client = _client()

    index = client.get("/skills/")
    assert index.status_code == 200
    assert "present-to-human" in index.text
    assert "set-theme" in index.text

    skill = client.get("/skills/present-to-human/SKILL.md")
    assert skill.status_code == 200
    assert skill.headers["content-type"].startswith("text/plain")
    assert "# Present" in skill.text
    assert "POST /v1/present" in skill.text

    missing = client.get("/skills/../../README.md")
    assert missing.status_code == 404


def test_skill_surface_rejects_symlink_escapes(monkeypatch, tmp_path) -> None:
    skills_dir = tmp_path / "skills"
    leak_dir = skills_dir / "leak"
    leak_dir.mkdir(parents=True)
    outside = tmp_path / "outside-secret.md"
    outside.write_text("secret outside skill root", encoding="utf-8")
    (leak_dir / "SKILL.md").symlink_to(outside)
    monkeypatch.setattr(surfaces, "_SKILLS_DIR", skills_dir)

    assert "leak" not in surfaces.skill_names()
    assert surfaces.read_skill("leak") is None

    response = _client().get("/skills/leak/SKILL.md")

    assert response.status_code == 404
    assert "secret outside skill root" not in response.text


def test_static_skill_surface_mirrors_repo_skills() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    for source in sorted((repo_root / "skills").glob("*/SKILL.md")):
        mirrored = repo_root / "site" / "static" / "skills" / source.parent.name / "SKILL.md"
        assert mirrored.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")


def test_robots_txt_blocks_user_content_paths() -> None:
    response = _client().get("/robots.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "User-agent: *" in response.text
    assert "Disallow: /present/" in response.text
    assert "Disallow: /assets/" in response.text


def test_user_content_paths_are_noindex_even_when_not_found() -> None:
    response = _client().get("/assets/not-a-uuid/extra")

    assert response.status_code == 404
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"


def test_user_content_asset_route_is_noindex(monkeypatch) -> None:
    app = folio_api.create_app(Settings(public_origin="https://folio.aweb.ai"))
    _override_db_for_path(app, "/assets/{asset_id}")
    asset_id = UUID("11111111-1111-4111-8111-111111111111")

    async def fake_get_public_asset(_database, *, asset_id: UUID) -> dict:
        return {"bytes": b"fake-png", "content_type": "image/png"}

    monkeypatch.setattr(folio_api, "get_public_asset", fake_get_public_asset)

    response = TestClient(app).get(f"/assets/{asset_id}")

    assert response.status_code == 200
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_present_route_keeps_noindex_header(monkeypatch) -> None:
    app = folio_api.create_app(Settings(public_origin="https://folio.aweb.ai"))
    _override_db_for_path(app, "/present/{token}")

    async def fake_get_presented_document(_database, *, token: str) -> dict:
        return {"body": "# Private", "theme": None, "allowed_assets": {}}

    monkeypatch.setattr(folio_api, "get_presented_document", fake_get_presented_document)

    response = TestClient(app).get("/present/private-token")

    assert response.status_code == 200
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    assert '<meta name="robots" content="noindex,nofollow,noarchive">' in response.text

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import library.api as library_api
import library.surfaces as surfaces
from library.config import Settings


def _client() -> TestClient:
    return TestClient(library_api.create_app(Settings(public_origin="https://library.aweb.ai")))


def test_llms_txt_is_plain_text_agent_entrypoint() -> None:
    response = _client().get("/llms.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "library — agent-first profiles for AWID teams" in response.text
    assert "GET /v1/profile-packs" in response.text
    assert "aw id request --team-auth" in response.text
    assert "https://aweb.ai" in response.text
    assert "https://awid.ai" in response.text
    # Native Agentic App framing: canonical plugin install + native aw library verbs.
    assert "Native Agentic App" in response.text
    assert "aw plugin install" in response.text
    assert "aw library" in response.text


def test_skills_surface_serves_index_and_individual_skills() -> None:
    client = _client()

    index = client.get("/skills/")
    assert index.status_code == 200
    assert "library agent skills" in index.text
    assert "team-cert-verification" in index.text

    skill = client.get("/skills/team-cert-verification/SKILL.md")
    assert skill.status_code == 200
    assert skill.headers["content-type"].startswith("text/plain")
    assert "AWID team certificate" in skill.text

    assert client.get("/skills/../../README.md").status_code == 404


def test_static_skills_match_served_skills() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    on_disk = sorted(p.parent.name for p in (repo_root / "skills").glob("*/SKILL.md"))
    assert surfaces.skill_names() == on_disk
    assert "team-cert-verification" in on_disk


def test_robots_allows_crawling_public_catalog() -> None:
    response = _client().get("/robots.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "User-agent: *" in response.text
    assert "Allow: /" in response.text

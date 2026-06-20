from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import library.api as library_api
import library.surfaces as surfaces
from library.aweb_manifest import MANIFEST
from library.config import Settings

_PUBLIC_TOOLS = [t for t in MANIFEST["tools"] if t.get("auth") == "none"]


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


def test_llms_txt_is_complete_operator_guide() -> None:
    """An LLM reading only llms.txt can operate library end to end: it must cover
    the team-certificate auth model, the full getting-started journey, and the
    raw-HTTP signing headers for callers not using the aw plugin."""
    text = _client().get("/llms.txt").text
    assert "team certificate" in text.lower()
    assert "X-AWID-Team-Certificate" in text
    assert "X-AWEB-Signed-Payload" in text
    assert "X-AWEB-Timestamp" in text
    # Getting-started journey, install-first, mirroring the landing (no run step).
    assert "npm install -g @awebai/aw" in text
    assert "aw team create" in text
    assert "aw team add" in text
    assert "import-to-shelf" in text
    # Points at the dual aw/curl reference for the full raw-HTTP recipe.
    assert "/reference" in text


def test_llms_txt_documents_every_manifest_operation() -> None:
    """The operations list is derived from the canonical manifest, so every verb
    and its endpoint is present and the two can never drift."""
    text = _client().get("/llms.txt").text
    for tool in MANIFEST["tools"]:
        assert f"aw library {tool['name']}" in text, tool["name"]
        assert tool["path"] in text, tool["path"]


def test_landing_offers_copiable_llms() -> None:
    """The landing presents llms.txt for one-click copy: the URL in a copy
    affordance and a button that copies the full llms.txt contents."""
    html = _client().get("/").text
    assert "id=\"copy-llms\"" in html
    assert "https://library.aweb.ai/llms.txt" in html


def test_reference_page_documents_every_operation_dual() -> None:
    """The reference page documents every manifest operation in parallel: the aw
    library verb and the raw HTTP wire form, styled with aweb.css."""
    response = _client().get("/reference")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert '<link rel="stylesheet" href="/css/aweb.css">' in response.text
    text = response.text
    for tool in MANIFEST["tools"]:
        assert f"aw library {tool['name']}" in text, tool["name"]
        assert tool["method"] in text
        assert tool["path"] in text, tool["path"]


def test_reference_page_documents_signing_envelope_once() -> None:
    """The cert-auth wire format names the four headers and the v2 signed-payload
    envelope fields, and offers the aw id request signed hand-runnable path."""
    text = _client().get("/reference").text
    for header in (
        "Authorization",
        "X-AWEB-Timestamp",
        "X-AWEB-Signed-Payload",
        "X-AWID-Team-Certificate",
    ):
        assert header in text, header
    for field in ("body_sha256", "team_id", "aud"):
        assert field in text, field
    assert "aw id request --team-auth" in text


def test_reference_public_reads_have_literal_curl() -> None:
    """The three auth:none reads are shown as literal, copy-paste-runnable curl
    with no auth headers required."""
    text = _client().get("/reference").text
    for tool in _PUBLIC_TOOLS:
        assert f"curl https://library.aweb.ai{tool['path']}" in text or (
            f"curl -s https://library.aweb.ai{tool['path']}" in text
        ), tool["name"]


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

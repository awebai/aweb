from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import library.api as library_api
import library.surfaces as surfaces
from library.aweb_manifest import MANIFEST
from library.config import Settings


def _client() -> TestClient:
    return TestClient(library_api.create_app(Settings(public_origin="https://library.aweb.ai")))


def test_llms_txt_is_plain_text_agent_entrypoint() -> None:
    response = _client().get("/llms.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "library — agent-first profiles for AWID teams" in response.text
    assert "GET /v1/blueprints" in response.text
    assert "aw id request --team-auth" in response.text
    assert "https://aweb.ai" in response.text
    assert "https://awid.ai" in response.text
    # Native Agentic App framing: core aw onboarding plus opt-in shelf verbs.
    assert "Native Agentic App" in response.text
    assert "aw team add alice@aweb.team/developer=claude-code" in response.text
    assert "claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace" in response.text
    assert "pi install npm:@awebai/pi@latest" in response.text
    assert "aw agent start" not in response.text
    assert "aw run" not in response.text
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
    # Getting-started journey mirrors the reconciled SOT canonical block.
    assert "npm install -g @awebai/aw" in text
    assert "aw init" in text
    assert "aw team add alice@aweb.team/developer=claude-code" in text
    assert "aw team add bob@aweb.team/reviewer=claude-code" in text
    assert "/plugin marketplace add awebai/claude-plugins" in text
    assert "/plugin install aweb-channel@awebai-marketplace" in text
    assert "cd agents/instances/alice" in text
    assert "claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace" in text
    assert "pi install npm:@awebai/pi@latest" in text
    assert "\npi\n" in text
    assert "aw agent start" not in text
    assert "aw run" not in text
    assert "AWEB_API_KEY=<key> AWEB_URL=<url> aw team add alice@aweb.team/developer --runtime claude-code" in text
    assert "--blueprint" in text
    assert "AWEB_BLUEPRINT" in text
    assert "--library-url" in text
    assert "AWEB_LIBRARY_URL" in text
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
    # Path params show as required in the operations list, not optional.
    assert "required: blueprint_ref" in text
    assert "required: blueprint_ref, profile_ref" in text


def test_landing_offers_llms_control_and_model_diagram() -> None:
    """The header carries the standard llms.txt split control (the dedicated
    For-LLMs section is gone), and the hero shows the model diagram."""
    html = _client().get("/").text
    assert 'class="split-btn"' in html
    assert "data-llms-copy" in html
    assert "For LLMs and agents" not in html
    # The hero model diagram replaces the prose lede.
    assert 'class="model-fig"' in html
    assert "Browse the catalog, build your shelf, run your team." in html
    assert "aw team add alice@aweb.team/developer=claude-code" in html
    assert "aw team add bob@aweb.team/reviewer=claude-code" in html
    assert "/plugin marketplace add awebai/claude-plugins" in html
    assert "/plugin install aweb-channel@awebai-marketplace" in html
    assert "claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace" in html
    assert "pi install npm:@awebai/pi@latest" in html
    assert "aw agent start" not in html
    assert "aw run" not in html
    assert "AWEB_API_KEY=&lt;key&gt; AWEB_URL=&lt;url&gt; aw team add alice@aweb.team/developer --runtime claude-code" in html
    assert 'href="https://awid.ai" class="brand-word"' in html
    assert 'href="https://aweb.ai" class="brand-word"' in html


def test_landing_get_started_links_blueprint_and_quoted_profiles() -> None:
    """Get-started hyperlinks what its commands quote — the aweb.team blueprint and
    the developer/reviewer profiles named in the commands — so a reader can see what
    they are adopting. The links live in prose, never inside the copy-paste <pre>."""
    html = _client().get("/").text
    assert 'href="/blueprints/aweb.team"' in html
    assert 'href="/blueprints/aweb.team/profiles/developer"' in html
    assert 'href="/blueprints/aweb.team/profiles/reviewer"' in html
    # the command block itself stays copy-paste clean — no anchor tags inside <pre>.
    pre_blocks = html.split("<pre>")[1:]
    for block in pre_blocks:
        assert "</a>" not in block.split("</pre>")[0]


def test_llms_txt_lists_browse_page_urls_for_agent_discovery() -> None:
    text = _client().get("/llms.txt").text
    assert "/blueprints" in text
    assert "/blueprints/aweb.team/profiles/developer" in text


def test_landing_catalog_teaser_renders_from_blueprints() -> None:
    """The landing presents the live catalog — each blueprint's name, summary, and a
    link into its page — from the catalog summary data, so a visitor discovers what
    is on the shelf. Rendered from data, not hardcoded, so new blueprints appear."""
    from library.surfaces import render_landing_page

    html = render_landing_page(
        public_origin="https://library.aweb.ai",
        blueprints=[
            {
                "blueprint_ref": "aweb.team",
                "name": "aweb AI Team",
                "summary": "A complete AI team — coordinator, developers, reviewer.",
            }
        ],
    )
    assert 'id="catalog"' in html
    assert "aweb AI Team" in html
    assert "A complete AI team" in html
    assert 'href="/blueprints/aweb.team"' in html
    # a link into the full catalog, and the ref shown in mono.
    assert 'href="/blueprints"' in html


def test_landing_catalog_teaser_absent_when_catalog_empty() -> None:
    """With no catalog data (e.g. the DB is unavailable) the landing still renders,
    simply without the teaser."""
    from library.surfaces import render_landing_page

    html = render_landing_page(public_origin="https://library.aweb.ai", blueprints=[])
    assert 'id="catalog"' not in html
    assert "Where teams choose, keep, and improve" in html  # the rest of the page renders


def test_rendered_pages_use_brand_word_not_legacy_brand_mark() -> None:
    landing = _client().get("/").text
    reference = _client().get("/reference").text
    for html in (landing, reference):
        assert "brand-mark" not in html
        assert (
            'library is a Native Agentic App on the <span class="brand-word">aweb</span>.ai hub. '
            '<span class="brand-word">awid</span> is the identity authority.'
        ) in html
        assert "Public blueprints and private team shelves for " in html
        assert '<span class="brand-word">awid</span> teams' in html

    assert '<span class="brand-word">aweb</span> protocol' in landing
    assert '<a href="https://awid.ai" class="brand-word">awid</a> identity' in landing


def test_reference_page_documents_every_operation_dual() -> None:
    """The reference page documents every manifest operation in parallel: the aw
    library verb and the raw HTTP wire form, styled with aweb.css."""
    response = _client().get("/reference")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    from aweb_naapp import CSS_SHA256

    assert f'<link rel="stylesheet" href="/css/aweb.{CSS_SHA256[:12]}.css">' in response.text
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
    # Tracks the canonical conformance vector, with the easy-to-miss encodings spelled out.
    assert "team-auth-envelope-v2" in text
    assert "base64url" in text
    assert "without padding" in text
    # The SOT vector is a real hyperlink to the stable repo URL, not just a code span.
    assert (
        'href="https://github.com/awebai/aweb/blob/main/cli/go/internal/conformance/'
        'vectors/team-auth-envelope-v2.json"'
    ) in text
    # The envelope example must be in canonical (sorted) key order — a copied signer
    # that follows v-first order would sign the wrong bytes.
    assert text.index('"aud"') < text.index('"body_sha256"') < text.index('"v": 2')


def test_reference_public_reads_have_literal_runnable_curl() -> None:
    """The three auth:none reads are shown as literal, copy-paste-runnable curl with
    live values — nothing labelled runnable may carry a brace placeholder."""
    text = _client().get("/reference").text
    assert "curl -s https://library.aweb.ai/v1/blueprints" in text
    assert "curl -s https://library.aweb.ai/v1/blueprints/aweb.team" in text
    assert "curl -s https://library.aweb.ai/v1/blueprints/aweb.team/profiles/developer" in text
    # get-blueprint / get-profile path params appear in the runnable verb examples.
    assert "aw library get-blueprint --blueprint_ref aweb.team" in text
    assert "aw library get-profile --blueprint_ref aweb.team --profile_ref developer" in text
    # No runnable curl line carries a brace placeholder.
    for line in text.splitlines():
        if "curl -s" in line:
            assert "{" not in line and "}" not in line, line


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

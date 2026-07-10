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
    assert "Create from the catalog, adopt onto your shelf, improve under review." in html
    assert 'href="https://awid.ai" class="brand-word"' in html
    assert 'href="https://aweb.ai" class="brand-word"' in html


def test_landing_hero_copy_is_the_teams_of_ai_agents_phrasing() -> None:
    html = _client().get("/").text
    assert "Where teams of AI agents choose, keep and improve the profiles they run." in html


def test_landing_is_one_getting_started_zero_to_self_improving_team() -> None:
    """A single getting-started, zero to a shelf-based self-improving team, in the
    executed 1.32.3 command order. Every panel is a runnable human command; the
    proposal step is actor-neutral (the autonomous 'your agents propose' claim is
    not true of the published profiles yet). There is no separate evolve section."""
    from library.surfaces import render_landing_page

    html = render_landing_page(
        public_origin="https://library.aweb.ai",
        blueprints=[{"blueprint_ref": "aweb.team", "name": "aweb AI Team", "summary": "A team."}],
    )
    # one getting-started, first content section; no separate evolve section.
    assert 'id="use"' in html
    assert 'id="evolve"' not in html
    assert html.index('id="use"') < html.index('id="catalog"')
    assert html.index('id="use"') < html.index("Agents need evolving job descriptions")

    # the executed command sequence, byte-exact and IN ORDER, all as panels.
    ordered = [
        "npm install -g @awebai/aw",
        "aw team create eng --username &lt;you&gt; "
        "--agent alice@aweb.team/developer=claude-code "
        "--agent bob@aweb.team/reviewer=pi",
        "aw team up",
        "aw plugin install https://library.aweb.ai/.well-known/aweb-app.json",
        "aw team adopt alice",
        "aw library approve --proposal_id &lt;id&gt;",
        "aw team refresh alice",
    ]
    positions = [html.index(f"<pre>{c}</pre>") if f"<pre>{c}</pre>" in html else html.index(c) for c in ordered]
    assert positions == sorted(positions), "get-started commands are out of order"
    # aw team up appears twice: start (step 3) and the idempotent reconcile (last step).
    assert html.count("<pre>aw team up</pre>") == 2
    # step 4's what-line notes the plugin is required for the adopt step next.
    assert "required for the adopt step" in html

    # the proposal step names the agents as the proposers, and approval is the
    # team's review gate — approved by its reviewing authority (typically the
    # coordinator, or you, per your policy), not the human by default. The
    # aw library approve panel is unchanged: the command is identical whoever runs it.
    assert "your agents propose" in html.lower()
    assert "your team reviews and approves" in html.lower()
    assert "your coordinator, or you" in html.lower()
    # the old human-as-default-approver claims are gone.
    assert "a human approves" not in html
    assert "you review and approve" not in html.lower()
    assert "under your review" not in html.lower()
    # broken syntax never appears anywhere on the page.
    assert "--body-file" not in html
    # neither propose nor update-from-source appears as a runnable command panel in
    # get-started (update-from-source may still be named as a concept in Invariants).
    assert "<pre>aw library propose" not in html
    assert "<pre>aw library update-from-source" not in html
    assert "<pre>aw library list-blueprints" not in html  # the old generic "use it" step is gone


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


def test_landing_presents_the_blueprint_with_its_roles() -> None:
    """The landing presents the first-party blueprint itself — name, real summary,
    and its roles at a glance — from the live catalog (not a generic carousel), and
    links to its page. Rendered from data, so it grows if the catalog does."""
    from library.surfaces import render_landing_page

    html = render_landing_page(
        public_origin="https://library.aweb.ai",
        blueprints=[
            {
                "blueprint_ref": "aweb.team",
                "name": "aweb AI Team",
                "summary": "A complete AI team — a coordinator who plans and routes, ...",
                "profiles": [
                    {"profile_ref": "coordinator"},
                    {"profile_ref": "developer"},
                    {"profile_ref": "reviewer"},
                    {"profile_ref": "agent-resources"},
                ],
            }
        ],
    )
    assert 'id="catalog"' in html
    assert "The team you're adopting" in html  # presents THE team, not "shop the catalog"
    assert "aweb AI Team" in html
    assert "A complete AI team" in html
    assert 'href="/blueprints/aweb.team"' in html
    # the roles are shown at a glance (from the blueprint's profiles).
    for role in ("coordinator", "developer", "reviewer", "agent-resources"):
        assert role in html, role
    # no generic "shop the catalog" framing that implies variety we do not have.
    assert "Teams you can adopt today" not in html
    assert "On the shelf" not in html


def test_landing_catalog_teaser_absent_when_catalog_empty() -> None:
    """With no catalog data (e.g. the DB is unavailable) the landing still renders,
    simply without the teaser."""
    from library.surfaces import render_landing_page

    html = render_landing_page(public_origin="https://library.aweb.ai", blueprints=[])
    assert 'id="catalog"' not in html
    assert "Where teams of AI agents choose, keep and improve" in html  # the rest of the page renders


class _FakeLibraryDatabase:
    def __init__(self, _settings: Settings) -> None:
        self.db = object()

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass


def test_landing_route_teaser_degrades_when_catalog_read_fails(monkeypatch) -> None:
    """Route-level guard: with a DB present but the catalog read failing, the front
    door stays up and omits only the best-effort catalog teaser."""

    async def broken_catalog_view(_db):
        raise RuntimeError("catalog unavailable")

    monkeypatch.setattr(library_api, "LibraryDatabase", _FakeLibraryDatabase)
    monkeypatch.setattr(library_api.browse_views, "catalog_view", broken_catalog_view)

    with TestClient(library_api.create_app(Settings(public_origin="https://library.aweb.ai"))) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert 'id="catalog"' not in response.text
    assert "Where teams of AI agents choose, keep and improve" in response.text


def test_landing_route_teaser_renders_catalog_read_success(monkeypatch) -> None:
    """Route-level success counterpart: catalog summaries from the live-read path
    are passed into the teaser renderer."""

    async def fake_catalog_view(_db):
        return [
            {
                "blueprint_ref": "aweb.team",
                "name": "aweb AI Team",
                "summary": "A complete AI team — coordinator, developers, reviewer.",
                "profiles": [{"profile_ref": "coordinator"}, {"profile_ref": "developer"}],
            }
        ]

    monkeypatch.setattr(library_api, "LibraryDatabase", _FakeLibraryDatabase)
    monkeypatch.setattr(library_api.browse_views, "catalog_view", fake_catalog_view)

    with TestClient(library_api.create_app(Settings(public_origin="https://library.aweb.ai"))) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert 'id="catalog"' in response.text
    assert "aweb AI Team" in response.text
    assert "A complete AI team" in response.text
    assert 'href="/blueprints/aweb.team"' in response.text


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

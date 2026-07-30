from __future__ import annotations

from pathlib import Path
from uuid import UUID

from aweb_layout import (
    aweb_candidate_roots,
    aweb_naapp_local_source_candidates,
    existing_local_sources,
    is_aweb_root,
    searched_roots,
    shadowing_local_source,
)
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


def test_aweb_naapp_import_resolves_from_the_pinned_package_not_a_local_source_tree() -> None:
    import aweb_naapp

    candidates = aweb_naapp_local_source_candidates()
    local_sources = existing_local_sources(candidates)

    # A guard whose subject does not exist cannot fail, and this one nearly stopped being
    # able to. It named only the sibling aweb-naapp checkout, so once the naapp move puts
    # folio at aweb/naapp/folio the path it looks for can never exist and the assertion
    # below passes without testing anything - at the same moment aweb-naapp's source
    # arrives in the tree at aweb/naapp-lib and makes the hazard real. So require that a
    # local source tree was actually found: no subject means this test reports that it
    # cannot do its job, rather than reporting success.
    assert local_sources, (
        "no local aweb-naapp source tree exists, so an import from one could not be "
        "detected and this guard would pass vacuously. Looked in: "
        + ", ".join(str(candidate) for candidate in candidates)
    )

    shadowing = shadowing_local_source(aweb_naapp.__file__, local_sources)
    assert shadowing is None, (
        f"aweb_naapp was imported from the local source tree at {shadowing} rather than "
        f"from the pinned package ({Path(aweb_naapp.__file__).resolve()})"
    )


def test_the_local_source_guard_can_detect_a_shadowing_import(tmp_path: Path) -> None:
    """Negative control for the guard above, which cannot fail on its own inputs.

    The real import resolves from the pinned package, so the guard's failing case never
    occurs while everything is correct - which is how it went unnoticed that the guard had
    stopped being able to fail at all. Both directions are constructed here instead.
    """
    local_source = tmp_path / "naapp-lib" / "src"
    shadowed = local_source / "aweb_naapp" / "__init__.py"
    shadowed.parent.mkdir(parents=True)
    shadowed.write_text("")

    assert shadowing_local_source(shadowed, [local_source]) == local_source

    pinned = tmp_path / "site-packages" / "aweb_naapp" / "__init__.py"
    pinned.parent.mkdir(parents=True)
    pinned.write_text("")

    assert shadowing_local_source(pinned, [local_source]) is None

    # A candidate that does not exist must never be reported, or the guard would claim to
    # have checked a location it could not have looked at.
    assert shadowing_local_source(shadowed, [tmp_path / "absent" / "src"]) is None


def test_aweb_is_identified_by_its_marker_not_by_containing_the_wanted_file(tmp_path: Path) -> None:
    """A directory that merely holds the requested path is not aweb.

    Accepting the first candidate that contained the file was wrong in the quietest
    possible way: a decoy directory above folio would be accepted and its bytes returned,
    so a conformance test would agree with the wrong reference instead of failing. This
    reconstructs that decoy and requires it to be rejected.
    """
    decoy = tmp_path / "decoy_root"
    (decoy / "docs" / "vectors").mkdir(parents=True)
    (decoy / "docs" / "vectors" / "team-auth-envelope-v2.json").write_text('{"decoy": true}')

    assert not is_aweb_root(decoy)

    # A server/pyproject.toml alone is not enough either - it has to declare aweb.
    other_repo = tmp_path / "other_repo"
    (other_repo / "server").mkdir(parents=True)
    (other_repo / "server" / "pyproject.toml").write_text('[project]\nname = "something-else"\n')

    assert not is_aweb_root(other_repo)

    # And the real shape is accepted, so the check is not simply always false.
    real = tmp_path / "aweb"
    (real / "server").mkdir(parents=True)
    (real / "server" / "pyproject.toml").write_text('[project]\nname = "aweb"\n')

    assert is_aweb_root(real)


def test_a_decoy_at_the_sibling_position_does_not_beat_a_real_aweb_above(tmp_path: Path) -> None:
    """The sibling position is searched first, so it is where a wrong bind would win.

    A directory literally NAMED aweb sitting beside folio is the one candidate that
    outranks a genuine aweb further up, and it is the case the ancestor decoy does not
    exercise. Filtering the roots rather than checking where the wanted file happens to
    exist is what makes this come out right.
    """
    real_aweb = tmp_path / "real_aweb"
    (real_aweb / "server").mkdir(parents=True)
    (real_aweb / "server" / "pyproject.toml").write_text('[project]\nname = "aweb"\n')

    folio_root = real_aweb / "naapp" / "folio"
    folio_root.mkdir(parents=True)

    # Named aweb, positioned to be found first, and not aweb.
    impostor = real_aweb / "naapp" / "aweb"
    (impostor / "docs" / "vectors").mkdir(parents=True)
    (impostor / "docs" / "vectors" / "team-auth-envelope-v2.json").write_text('{"decoy": true}')

    # It is searched, and searched FIRST - so the ordering claim is not vacuous.
    assert searched_roots(folio_root)[0] == impostor

    # And it is not accepted, leaving the real aweb above it as the only candidate.
    assert aweb_candidate_roots(folio_root) == [real_aweb]


def test_landing_page_explains_folio_and_links_agent_surfaces() -> None:
    response = _client().get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    # Adopted the shared aweb design system, at the fingerprinted css URL.
    from aweb_naapp import CSS_SHA256

    assert f'<link rel="stylesheet" href="/css/aweb.{CSS_SHA256[:12]}.css">' in response.text
    assert "Native Agentic App" in response.text
    assert "anapp" not in response.text
    assert "documents and presentations" in response.text
    assert "https://aweb.ai" in response.text
    assert "https://awid.ai" in response.text
    # Open source: a GitHub source link in the header and the MIT footer line.
    assert "https://github.com/awebai/folio" in response.text
    assert 'class="gh-link"' in response.text
    assert "MIT-licensed" in response.text
    assert 'href="/llms.txt"' in response.text
    assert 'href="/reference"' in response.text
    assert 'href="/skills/"' in response.text


def test_landing_brand_words_and_nav_cleanup() -> None:
    text = _client().get("/").text
    # aweb / awid wordmarks carry the brand-word — in the nav and in body copy.
    assert '<a href="https://aweb.ai" class="brand-word">aweb</a>' in text
    assert '<a href="https://awid.ai" class="brand-word">awid</a>' in text
    assert '<span class="brand-word">aweb</span>' in text
    # Nav cleanup: the broken "Model" link is gone (no #model section to reach).
    assert 'href="/#model"' not in text
    # The open-source / MIT line is prominent in the hero, linking the repo.
    assert "Open source, MIT-licensed" in text
    assert "github.com/awebai/folio" in text


def test_seo_meta_social_card_and_design_assets() -> None:
    client = _client()
    text = client.get("/").text
    # SEO + social-card meta for link previews (WhatsApp, Slack, X).
    assert '<link rel="canonical" href="https://folio.aweb.ai/">' in text
    assert '<meta property="og:title"' in text
    assert '<meta name="twitter:card" content="summary_large_image">' in text
    assert '<meta property="og:image" content="https://folio.aweb.ai/og-card.png">' in text
    # The social card image is served as a real PNG.
    og = client.get("/og-card.png")
    assert og.status_code == 200
    assert og.headers["content-type"] == "image/png"
    assert og.content[:8] == b"\x89PNG\r\n\x1a\n"

    css = client.get("/css/aweb.css")
    assert css.status_code == 200
    assert '/fonts/BerkeleyMono-Regular.woff2' in css.text
    font = client.get("/fonts/BerkeleyMono-Regular.woff2")
    assert font.status_code == 200
    assert font.headers["content-type"] == "font/woff2"
    assert font.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert font.content.startswith(b"wOF2")


def test_llms_txt_is_plain_text_agent_entrypoint() -> None:
    response = _client().get("/llms.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "folio — agent-first documents and presentations for AWID teams" in response.text
    # Native Agentic App framing: canonical plugin install + native aw folio verbs.
    assert "Native Agentic App" in response.text
    assert "anapp" not in response.text
    assert "aw plugin install" in response.text
    assert "aw folio create" in response.text
    assert "aw folio present" in response.text
    # Events are documented (folio is the first naapp with events).
    assert "folio/doc.changed" in response.text
    # folio domain prose preserved.
    assert "Cloudflare Stream" in response.text
    assert "pitch slots: cover, metrics, sections, ask" in response.text
    assert "cover fields: title (required), subtitle, eyebrow" in response.text
    assert "metrics item fields: label (required), value (required), caption" in response.text
    assert "https://aweb.ai" in response.text
    assert "https://awid.ai" in response.text
    assert "https://github.com/awebai/folio" not in response.text


def test_landing_getting_started_is_the_verified_folio_spine() -> None:
    html = _client().get("/").text
    # One getting-started, rendered as single-box numbered steps (the shared aweb
    # step pattern), never the elevated-panel-around-a-command double box.
    assert 'class="gs-steps"' in html
    assert "cmd-panel" not in html
    # The verified spine shows folio's whole point — two agents on one document:
    # a two-agent team, then a draft (create) and a revision (append) that both
    # land on the same append-only document, then the present link.
    spine = [
        "npm install -g @awebai/aw",
        "aw team create my-team --username YOUR_USERNAME --agent writer@aweb.team/developer=pi --agent editor@aweb.team/reviewer=pi",
        "aw team up",
        "aw plugin install https://folio.aweb.ai/.well-known/aweb-app.json",
        'aw folio create --slug pitch --title "Pitch" --body "# Pitch"',
        "aw folio append --slug pitch",
        "aw folio present --slug pitch --ttl_seconds 86400",
    ]
    positions = [html.find(step) for step in spine]
    assert all(pos != -1 for pos in positions), positions
    assert positions == sorted(positions), "steps must render in executed order"


def test_llms_txt_getting_started_teaches_the_verified_spine() -> None:
    text = _client().get("/llms.txt").text
    assert (
        "aw team create my-team --username YOUR_USERNAME --agent writer@aweb.team/developer=pi --agent editor@aweb.team/reviewer=pi"
        in text
    )
    order = [
        "aw team create my-team",
        "aw team up",
        "aw plugin install",
        "aw folio create",
        "aw folio append",
        "aw folio present",
    ]
    positions = [text.find(step) for step in order]
    assert all(pos != -1 for pos in positions), positions
    assert positions == sorted(positions), "llms.txt steps must render in executed order"


def test_linked_manifest_paths_serve_committed_bytes() -> None:
    from folio.aweb_manifest import read_manifest_bytes

    client = _client()
    committed = read_manifest_bytes()
    # The docs surface links the canonical manifest at /aweb-app.json; the
    # dispatcher fetches /.well-known/aweb-app.json. Both must serve the exact
    # committed bytes — nothing the surface links may 404.
    for path in ("/aweb-app.json", "/.well-known/aweb-app.json"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "application/json" in response.headers["content-type"], path
        assert response.headers.get("X-Content-Type-Options") == "nosniff", path
        assert response.content == committed, path
    # Guard against drift: the surfaces actually link /aweb-app.json.
    assert "/aweb-app.json" in client.get("/reference").text
    assert "/aweb-app.json" in client.get("/").text


def test_skills_surface_serves_index_and_individual_skills() -> None:
    client = _client()

    index = client.get("/skills/")
    assert index.status_code == 200
    assert "folio is a Native Agentic App (naapp)" in index.text
    assert "https://aweb.ai" in index.text
    assert "https://awid.ai" in index.text
    assert "fetch the relevant skill before acting" in index.text
    assert "present-to-human" in index.text
    assert "set-theme" in index.text
    assert "create-from-template" in index.text

    skill = client.get("/skills/present-to-human/SKILL.md")
    assert skill.status_code == 200
    assert skill.headers["content-type"].startswith("text/plain")
    assert "# Present" in skill.text
    assert "POST /v1/present" in skill.text

    template_skill = client.get("/skills/create-from-template/SKILL.md")
    assert template_skill.status_code == 200
    assert "# Create a folio document from a built-in template" in template_skill.text
    assert '"name":"pitch"' in template_skill.text
    assert "cover/metrics/sections/ask" in template_skill.text

    missing = client.get("/skills/../../README.md")
    assert missing.status_code == 404


def test_served_skills_do_not_reference_removed_python_cli() -> None:
    client = _client()
    forbidden = ("folio create", "folio version", "folio upload", "folio theme", "folio show", "folio revoke", "aw-folio")
    for name in surfaces.skill_names():
        response = client.get(f"/skills/{name}/SKILL.md")
        assert response.status_code == 200
        for needle in forbidden:
            assert needle not in response.text


def test_skill_index_falls_back_to_container_skills_for_installed_package_layout(monkeypatch, tmp_path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    fake_site_packages = tmp_path / "site-packages" / "folio"
    fake_site_packages.mkdir(parents=True)
    monkeypatch.delenv("FOLIO_SKILLS_DIR", raising=False)
    monkeypatch.setattr(surfaces, "_SKILLS_DIR", fake_site_packages / "skills")
    monkeypatch.setattr(surfaces, "_CONTAINER_SKILLS_DIR", repo_root / "skills")

    assert surfaces.skill_names() == [
        "agent-first-app",
        "byot-e2e-validation",
        "create-from-template",
        "present-to-human",
        "set-theme",
        "team-cert-verification",
    ]
    index = surfaces.skills_index()
    assert "GET /skills/agent-first-app/SKILL.md" in index
    assert "GET /skills/team-cert-verification/SKILL.md" in index


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

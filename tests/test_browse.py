from __future__ import annotations

from aweb_naapp import CSS_SHA256

from library import browse

ORIGIN = "https://library.aweb.ai"


def _css_link() -> str:
    return f'<link rel="stylesheet" href="/css/aweb.{CSS_SHA256[:12]}.css">'


# --------------------------------------------------------------------- catalog
def test_catalog_lists_blueprints_with_links_counts_and_roles() -> None:
    html = browse.render_catalog_page(
        public_origin=ORIGIN,
        blueprints=[
            {
                "blueprint_ref": "aweb.team",
                "name": "aweb.team",
                "summary": "The reference agent team.",
                "profile_count": 4,
                "roster": [{"profile_ref": r} for r in ("coordinator", "developer")],
            }
        ],
    )
    assert _css_link() in html  # shared chrome + fingerprinted css
    assert 'class="browse-blueprint-card" href="/blueprints/aweb.team"' in html
    assert "4 profiles" in html
    assert "coordinator, developer" in html
    assert "The reference agent team." in html


def test_catalog_empty_states_when_no_blueprints() -> None:
    html = browse.render_catalog_page(public_origin=ORIGIN, blueprints=[])
    assert "No blueprints published yet." in html
    assert 'class="browse-blueprint-card"' not in html


# ------------------------------------------------------------------- blueprint
def _blueprint() -> dict:
    return {
        "blueprint_ref": "aweb.team",
        "name": "aweb.team",
        "summary": "The reference agent team.",
        "version": "0.1.0",
        "digest": "sha256:9f21ac",
        "tags": ["starter", "team"],
        "first_mission_examples": ["Stand up a three-role team."],
        "roster": [
            {
                "profile_ref": "coordinator",
                "mission": "Owns the process.",
                "default_count": 1,
                "count_min": 1,
                "count_max": 1,
                "runtime_hints": ["claude-code"],
            },
            {
                "profile_ref": "developer",
                "mission": "Ships tested changes.",
                "default_count": 2,
                "count_min": 1,
                "count_max": 4,
                "runtime_hints": ["claude-code", "pi"],
            },
        ],
    }


def test_blueprint_roster_table_has_rows_counts_ranges_and_profile_links() -> None:
    html = browse.render_blueprint_page(public_origin=ORIGIN, blueprint=_blueprint())
    assert 'class="browse-roster"' in html
    assert '<a href="/blueprints/aweb.team/profiles/coordinator">coordinator</a>' in html
    assert '<a href="/blueprints/aweb.team/profiles/developer">developer</a>' in html
    # default with a range renders the range; default == range collapses to a bare number.
    assert "(1&ndash;4)" in html
    assert "claude-code · pi" in html
    # tags, meta, first missions all present.
    assert "browse-tag" in html
    assert "Stand up a three-role team." in html
    assert "browse-profile-card" in html


def test_blueprint_hero_uses_mono_identity_title_and_breadcrumb() -> None:
    html = browse.render_blueprint_page(public_origin=ORIGIN, blueprint=_blueprint())
    assert '<h1 class="browse-title is-id">aweb.team</h1>' in html
    assert 'class="browse-crumbs"' in html
    assert '<a href="/blueprints">Blueprints</a>' in html


def test_blueprint_without_recommendation_renders_dash_not_error() -> None:
    bp = _blueprint()
    bp["roster"] = [{"profile_ref": "loner", "mission": "Solo."}]
    html = browse.render_blueprint_page(public_origin=ORIGIN, blueprint=bp)
    assert "&mdash;" in html  # null default and null runtime both fall back to a dash
    assert "loner" in html


# --------------------------------------------------------------------- profile
def _profile() -> dict:
    return {
        "blueprint_ref": "aweb.team",
        "profile_ref": "coordinator",
        "name": "coordinator",
        "mission": "Owns the team process and outcome.",
        "version": "0.1.0",
        "digest": "sha256:4c7be1",
        "runtime_hints": ["claude-code"],
        "accepted_work": ["Breaking work into tasks"],
        "runtime_assumptions": ["Runs in its home"],
        "memory_policy": "Records durable decisions in shared state.",
        "approval_required": ["Merging to main"],
        "skills": [
            {
                "name": "spawn-instance",
                "description": "Add a teammate.",
                "href": "/blueprints/aweb.team/profiles/coordinator/skills/spawn-instance",
            }
        ],
        "instructions_html": "<h1>Coordinator</h1>\n<p>You own the process.</p>",
    }


def test_profile_leads_with_mission_and_shows_how_it_works_specs() -> None:
    html = browse.render_profile_page(public_origin=ORIGIN, profile=_profile())
    assert '<h1 class="browse-title is-id">coordinator</h1>' in html
    # mission is the hero summary — legible first, before the mechanics.
    assert "Owns the team process and outcome." in html
    assert html.index("Owns the team process") < html.index("How it works")
    assert 'class="browse-specs"' in html
    for label in ("accepted work", "runtime assumptions", "memory policy", "needs approval"):
        assert f"<dt>{label}</dt>" in html
    assert "Breaking work into tasks" in html
    assert "Merging to main" in html


def test_profile_skills_link_to_skill_pages_and_instructions_render_verbatim() -> None:
    html = browse.render_profile_page(public_origin=ORIGIN, profile=_profile())
    assert 'class="browse-skill-card" href="/blueprints/aweb.team/profiles/coordinator/skills/spawn-instance"' in html
    assert "spawn-instance" in html
    # the sanitized instructions HTML is inserted verbatim in the markdown body.
    assert 'class="markdown-body"' in html
    assert "<h1>Coordinator</h1>\n<p>You own the process.</p>" in html


def test_profile_omits_empty_sections() -> None:
    p = _profile()
    p["skills"] = []
    p["instructions_html"] = ""
    html = browse.render_profile_page(public_origin=ORIGIN, profile=p)
    assert 'class="browse-skill-card"' not in html
    assert 'class="markdown-body"' not in html
    # the how-it-works specs always render, even when the lists are empty.
    assert 'class="browse-specs"' in html


def test_profile_memory_policy_accepts_string_or_mapping() -> None:
    p = _profile()
    p["memory_policy"] = {"scope": "shared-only", "retention": "durable"}
    html = browse.render_profile_page(public_origin=ORIGIN, profile=p)
    assert "scope" in html and "shared-only" in html


# ----------------------------------------------------------------------- skill
def _skill() -> dict:
    return {
        "blueprint_ref": "aweb.team",
        "profile_ref": "coordinator",
        "skill_name": "spawn-instance",
        "frontmatter": {
            "name": "spawn-instance",
            "description": "Add a teammate.",
            "allowed-tools": "Bash, Read, Write",
        },
        "body_html": "<h1>spawn-instance</h1>\n<pre><code>aw agents spawn</code></pre>",
    }


def test_skill_renders_body_verbatim_and_frontmatter_extras_only() -> None:
    html = browse.render_skill_page(public_origin=ORIGIN, skill=_skill())
    assert '<h1 class="browse-title is-id">spawn-instance</h1>' in html
    assert "Add a teammate." in html  # description in the hero
    assert 'class="markdown-body"' in html
    assert "<pre><code>aw agents spawn</code></pre>" in html
    # frontmatter strip shows only extra keys, not the name/description already in the hero.
    assert "allowed-tools" in html
    assert "<dt>name</dt>" not in html
    assert "<dt>description</dt>" not in html


def test_skill_without_extra_frontmatter_omits_the_strip() -> None:
    s = _skill()
    s["frontmatter"] = {"name": "spawn-instance", "description": "Add a teammate."}
    html = browse.render_skill_page(public_origin=ORIGIN, skill=s)
    assert 'class="browse-frontmatter"' not in html


# ------------------------------------------------------------------- integrity
def test_data_fields_are_escaped_but_sanitized_bodies_are_verbatim() -> None:
    p = _profile()
    p["mission"] = 'Owns <script>alert("x")</script> the process'
    p["instructions_html"] = "<p>trusted, already sanitized</p>"
    html = browse.render_profile_page(public_origin=ORIGIN, profile=p)
    assert "<script>alert" not in html  # data escaped
    assert "&lt;script&gt;" in html
    assert "<p>trusted, already sanitized</p>" in html  # pre-sanitized body verbatim


def test_browse_classes_never_collide_with_design_system_roster_or_tag() -> None:
    """aweb.css already defines .roster (display:grid) and .tag; every browse
    class must carry the browse- prefix so it can never inherit those rules."""
    pages = [
        browse.render_catalog_page(public_origin=ORIGIN, blueprints=[]),
        browse.render_blueprint_page(public_origin=ORIGIN, blueprint=_blueprint()),
        browse.render_profile_page(public_origin=ORIGIN, profile=_profile()),
        browse.render_skill_page(public_origin=ORIGIN, skill=_skill()),
    ]
    for html in pages:
        assert 'class="roster"' not in html
        assert 'class="roster ' not in html
        assert 'class="tag"' not in html
        assert 'class="tag ' not in html

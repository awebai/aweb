from __future__ import annotations

import os
import re
from html import escape
from pathlib import Path

import aweb_naapp as naapp
from aweb_naapp import FooterColumn, NavLink, SiteConfig, aweb_css

from folio.aweb_manifest import MANIFEST

__all__ = [
    "USER_CONTENT_ROBOTS_HEADER",
    "aweb_css",
    "render_landing_page",
    "render_reference_page",
    "llms_txt",
    "robots_txt",
    "skills_index",
    "read_skill",
    "skill_names",
]

USER_CONTENT_ROBOTS_HEADER = "noindex, nofollow, noarchive"

_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_DIR = _REPO_ROOT / "skills"
_CONTAINER_SKILLS_DIR = Path("/app/skills")

# folio's identity in the shared naapp chrome. The aweb design system, the chrome,
# the manifest-driven llms.txt blocks, and the /reference page come from aweb_naapp;
# folio supplies its manifest, this site config, and its own landing body and
# llms.txt prose. folio has no public reads — every tool is team-cert — and it
# emits events, so the toolkit omits the public section and renders an Events one.
_VERB = "folio"
_NAV_LINKS = (
    NavLink("Model", "/#model"),
    NavLink("llms.txt", "/llms.txt"),
    NavLink("Reference", "/reference"),
    NavLink("Skills", "/skills/"),
    NavLink("AWID", "https://awid.ai"),
)
_FOOTER_BLURB = (
    "Private, append-only documents and presentations for AWID teams — "
    "authored by agents, branded with a team theme, shared by capability link."
)
_FOOTER_COLUMNS = (
    FooterColumn(
        "Agents",
        (
            NavLink("llms.txt", "/llms.txt"),
            NavLink("API reference", "/reference"),
            NavLink("Skills", "/skills/"),
            NavLink("App manifest", "/aweb-app.json"),
        ),
    ),
    FooterColumn(
        "aweb",
        (
            NavLink("aweb.ai", "https://aweb.ai"),
            NavLink("AWID", "https://awid.ai"),
        ),
    ),
)
_FOOTER_BOTTOM = (
    "folio is a Native Agentic App on the aweb.ai hub. AWID is the identity authority. "
    "Team documents, media assets, and present pages are not indexed."
)
_REFERENCE_COPY = naapp.ReferenceCopy(
    rejects_subject="folio",
    envelope_path_example="/v1/documents/pitch/versions or /v1/present",
    team_kicker="Operations",
    team_heading="Documents, presentations, media, themes — AWID team certificate",
    team_blurb=(
        "Each shows the canonical verb, the signed hand-runnable "
        "<code>aw id request</code> form, and the raw wire format aw produces."
    ),
    events_kicker="Events",
    events_heading="Events folio emits",
    events_blurb=(
        "Subscribe an agent to be woken when a document changes. The payload is "
        "metadata only — never the document body — and each event is signed by the "
        "emit key declared in the manifest."
    ),
)


def _site(*, public_origin: str, title: str, description: str) -> SiteConfig:
    return SiteConfig(
        origin=public_origin.rstrip("/"),
        brand="folio",
        title=title,
        description=description,
        nav_links=_NAV_LINKS,
        footer_blurb=_FOOTER_BLURB,
        footer_columns=_FOOTER_COLUMNS,
        footer_bottom=_FOOTER_BOTTOM,
    )


def _skills_dir() -> Path:
    configured = os.environ.get("FOLIO_SKILLS_DIR")
    if configured:
        return Path(configured)
    if _SKILLS_DIR.is_dir():
        return _SKILLS_DIR
    if _CONTAINER_SKILLS_DIR.is_dir():
        return _CONTAINER_SKILLS_DIR
    return _SKILLS_DIR


def render_landing_page(*, public_origin: str) -> str:
    origin = escape(public_origin.rstrip("/"), quote=True)
    copy = naapp.COPY_BTN
    site = _site(
        public_origin=public_origin,
        title="folio — agent documents and presentations for AWID teams",
        description=(
            "folio is the Native Agentic App for agent-authored documents and "
            "presentations: append-only Markdown, team themes, safe media, and "
            "no-login presentation links for AWID teams."
        ),
    )
    body = f"""    <section class="hero-center">
      <div class="wrap">
        <p class="kicker">Native Agentic App · folio.aweb.ai</p>
        <h1>Where agents write the documents and mint the links humans open.</h1>
        <p class="lede">folio.aweb.ai is the Native Agentic App for documents and presentations: agents author append-only Markdown, brand it with a team theme, embed safe media, and mint revocable no-login links for the human moments. No app accounts — the team's AWID certificate is the login.</p>
        <div class="cta-row">
          <a class="btn primary btn--lg" href="#use">Get started</a>
          <a class="btn secondary btn--lg" href="/llms.txt">Read llms.txt</a>
        </div>
      </div>
    </section>

    <section class="section" id="llms">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">For LLMs and agents</p>
          <h2>Point your agent at one file</h2>
          <p>llms.txt is the complete, plain-text guide to operating folio: what it is, how to install it in <code>aw</code>, how team-certificate auth works, every operation with its parameters, the events it emits, and the getting-started journey. An agent that reads it can drive folio end to end.</p>
        </div>
        <div class="cmd-panel">
          <p class="cmd-label">Copy the URL, or grab the whole file</p>
          <div class="cmd-list"><div class="cmd"><pre>{origin}/llms.txt</pre>{copy}</div></div>
          <div class="cta-row">
            <button class="btn primary" type="button" id="copy-llms" data-llms-url="/llms.txt">Copy llms.txt contents</button>
            <a class="btn secondary" href="/llms.txt">Open llms.txt</a>
            <a class="btn secondary" href="/reference">API reference</a>
          </div>
        </div>
      </div>
    </section>

    <section class="section section--tint">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">What it is</p>
          <h2>A Native Agentic App</h2>
          <p>A Native Agentic App (naapp) is an aweb app designed for agents to operate directly: it publishes a canonical manifest that turns its API into native <code>aw</code> verbs, can declare event emitters that wake subscribed agents, and ships agent-readable llms.txt and skills. The manifest is public; what is signed is each verb call, with your team certificate.</p>
        </div>
        <p class="prose-outro">In practice: you do not write an integration or click around a console. You install folio into <code>aw</code> once (below), and from then on an agent runs the same <code>aw folio</code> commands — create a document, append a version, mint a present link — with no custom code.</p>
      </div>
    </section>

    <section class="section" id="model">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">What folio does</p>
          <h2>Documents, presentations, and the links between them</h2>
          <p>Agents author content; folio versions it, renders it safely, and hands humans a link — without ever accepting team-supplied HTML or JavaScript.</p>
        </div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Documents</h3><p>Create a document from raw Markdown or a declarative template. Each one is private to your team and addressed by a slug.</p></article>
          <article class="card"><h3>Append-only versions</h3><p>Every edit is a new version; history is never rewritten. Present links pin a specific version.</p></article>
          <article class="card"><h3>Declarative templates</h3><p>Schema-validated slots (pitch, memo, metrics) render to ordinary Markdown before storage — structure without hand-written HTML.</p></article>
          <article class="card"><h3>Presentation links</h3><p>Mint opaque, revocable capability URLs for the human moment. Present pages and assets are <code>noindex</code> and need no login.</p></article>
          <article class="card"><h3>Safe media</h3><p>Raster images and Cloudflare Stream video render inside themed pages; team-supplied HTML and scripts are stripped.</p></article>
          <article class="card"><h3>Team themes</h3><p>Brand every presentation with the team's tokens, logo, header, and footer — set once, applied everywhere.</p></article>
        </div>
      </div>
    </section>

    <section class="section section--tint" id="use">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">Get started</p>
          <h2>Install aw, create a team, author a document, present it</h2>
          <p><code>aw</code> is the only thing to install; folio plugs into it. Creating your team mints the certificate that every later command signs with.</p>
        </div>
        <div class="cmd-panel">
          <p class="cmd-label">1 · Install aw, the aweb command-line tool</p>
          <div class="cmd-list"><div class="cmd"><pre>npm install -g @awebai/aw</pre>{copy}</div></div>
          <p class="cmd-label">2 · Add the folio naapp — its operations become native aw folio verbs</p>
          <div class="cmd-list"><div class="cmd"><pre>aw plugin install {origin}/.well-known/aweb-app.json</pre>{copy}</div></div>
          <p class="cmd-label">3 · Create your team — mints your identity and team certificate</p>
          <div class="cmd-list"><div class="cmd"><pre>aw team create my-team</pre>{copy}</div></div>
          <p class="cmd-label">4 · Author a document from Markdown</p>
          <div class="cmd-list"><div class="cmd"><pre>aw folio create --slug pitch --title "Pitch" --body "# Pitch"</pre>{copy}</div></div>
          <p class="cmd-label">5 · Mint a no-login present link for a human</p>
          <div class="cmd-list"><div class="cmd"><pre>aw folio present --slug pitch --ttl_seconds 86400</pre>{copy}</div></div>
        </div>
        <p class="prose-outro">Every folio operation is a native <code>aw folio</code> verb. Agents read the whole surface at <a href="/llms.txt">llms.txt</a> and the per-operation <a href="/reference">reference</a>; the dispatcher reads the <a href="/aweb-app.json">canonical manifest</a>.</p>
      </div>
    </section>

    <section class="section" id="engineers">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">For engineers</p>
          <h2>What's actually real</h2>
          <p>No magic words — concrete, versioned, signed behavior you can reproduce.</p>
        </div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Append-only history</h3><p>Versions are immutable and append-only; an edit creates a new version and a present link pins the one you chose.</p></article>
          <article class="card"><h3>Signed, no accounts</h3><p>There are no app accounts or API keys. Every write is a request signed by your team's AWID identity, scoped to the verified team.</p></article>
          <article class="card"><h3>Capability links</h3><p>Present links are opaque, revocable URLs. Present pages and assets are <code>noindex</code> and reachable only from a link you minted.</p></article>
          <article class="card"><h3>No team HTML or JS</h3><p>Team Markdown is sanitized; raw iframes are stripped. Only the server generates Cloudflare Stream embeds for ready videos.</p></article>
          <article class="card"><h3>Honest boundary</h3><p>folio stores server-readable text and media metadata — it is not end-to-end encrypted. It emits <code>folio/doc.changed</code> (metadata only) to wake subscribed agents.</p></article>
        </div>
      </div>
    </section>"""
    return naapp.page(site, body, include_copy_llms=True)


def render_reference_page(*, public_origin: str) -> str:
    site = _site(
        public_origin=public_origin,
        title="folio — API reference",
        description=(
            "Every folio operation in parallel: the canonical aw folio verb and the "
            "raw HTTP wire format with AWID team-certificate signing."
        ),
    )
    return naapp.render_reference(MANIFEST, site, verb=_VERB, copy=_REFERENCE_COPY)


def llms_txt(*, public_origin: str) -> str:
    origin = public_origin.rstrip("/")
    operations = naapp.llms.cert_operations(MANIFEST, _VERB)
    auth = naapp.llms.auth_section(MANIFEST, origin)
    events = naapp.llms.events_section(MANIFEST)
    return f"""# folio — agent-first documents and presentations for AWID teams

folio is the app that owns agent-authored documents, their append-only versions,
declarative templates, team themes, safe media assets, and revocable presentation
links. This is a Native Agentic App (naapp): an aweb app agents operate directly
via its canonical manifest, published for the aweb.ai hub index. There are no
app-local accounts, passwords, OAuth sessions, public document listings, or
user-content feeds.

AWID is the identity authority: https://awid.ai
aweb hub: https://aweb.ai

Origin:
- Production: {origin}
- Local development: http://127.0.0.1:8765


## Getting started

Install aw, install folio, create a team, author a document, present it.

1. npm install -g @awebai/aw
2. aw plugin install {origin}/.well-known/aweb-app.json
3. aw team create my-team
4. aw folio create --slug pitch --title "Pitch" --body "# Pitch"
5. aw folio present --slug pitch --ttl_seconds 86400


## How to call it

The canonical form is the native plugin verbs: after
aw plugin install {origin}/.well-known/aweb-app.json, every operation below is
aw folio <verb> (e.g. aw folio create, aw folio append, aw folio present). The
HTTP endpoints below are the same surface; call them directly with
aw id request --team-auth (the low-level escape hatch) if you are not using the
plugin.


## Authentication

{auth}


## Operations

{operations}


## Events

{events}


## Declarative templates

Template slots are schema-validated and rendered to ordinary Markdown before
storage; presentation falls back to the same themed Markdown renderer.
- pitch slots: cover, metrics, sections, ask
- memo slots: cover, sections
- metrics slots: cover, metrics
- cover fields: title (required), subtitle, eyebrow
- metrics item fields: label (required), value (required), caption
- sections item fields: heading (required), body
- ask fields: headline, body, items (array of strings)
- Append template versions with aw folio append-template --slug deck --name memo --slots '...'


## Privacy and noindex

- All user content is capability-link private and noindex: /present/* and /assets/* responses include X-Robots-Tag: noindex, nofollow, noarchive.
- /present/* pages also include a robots noindex meta tag.
- robots.txt disallows /present/ and /assets/.


## Invariants

- AWID is authority for team keys, certificates, and revocation.
- Every document, asset, theme, and present-link mutation is scoped to the verified certificate team_id.
- Versions are append-only; edits create new versions.
- Team-supplied Markdown is sanitized. Raw iframes are stripped; Cloudflare Stream iframes are generated only by the server for ready video assets.
- folio stores server-readable text and media metadata. Do not call it end-to-end encrypted.
"""


def robots_txt() -> str:
    return """User-agent: *
Disallow: /present/
Disallow: /assets/
"""


def _skill_path_if_safe(name: str) -> Path | None:
    if _SKILL_NAME.fullmatch(name) is None:
        return None
    skills_dir = _skills_dir()
    root = skills_dir.resolve()
    candidate = skills_dir / name / "SKILL.md"
    path = candidate.resolve()
    if (
        candidate.is_symlink()
        or candidate.parent.is_symlink()
        or path.is_symlink()
        or not path.is_relative_to(root)
        or not path.is_file()
    ):
        return None
    return path


def skill_names() -> list[str]:
    root = _skills_dir().resolve()
    if not root.is_dir():
        return []
    names = []
    for entry in root.iterdir():
        if entry.is_symlink() or not entry.is_dir() or _SKILL_NAME.fullmatch(entry.name) is None:
            continue
        if _skill_path_if_safe(entry.name) is not None:
            names.append(entry.name)
    return sorted(names)


def skills_index() -> str:
    lines = [
        "# folio agent skills",
        "",
        "folio is a Native Agentic App (naapp) on the aweb.ai hub.",
        "Agents should fetch the relevant skill before acting so requests match the folio API contract.",
        "",
        "- aweb.ai hub: https://aweb.ai",
        "- AWID identity authority: https://awid.ai",
        "",
        "Available skills:",
        "",
    ]
    for name in skill_names():
        lines.append(f"- GET /skills/{name}/SKILL.md")
    lines.append("")
    return "\n".join(lines)


def read_skill(name: str) -> str | None:
    if name not in skill_names():
        return None
    path = _skill_path_if_safe(name)
    if path is None:
        return None
    return path.read_text(encoding="utf-8")

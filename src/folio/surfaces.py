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


# Hero model: a team of agents drafts a shared, versioned document; a minted link
# (the one terracotta accent) hands it to a human to read or edit. A straight
# author->share pipeline, not a loop. Self-contained <style>, desktop + mobile SVG.
_FOLIO_DIAGRAM = """<style>
  .ff-fig { margin: var(--s5) auto 0; max-width: 780px; }
  .ff-fig svg { width: 100%; height: auto; display: block; }
  .ff-fig .ff-mobile { display: none; }
  .ff-fig figcaption { text-align: center; color: var(--muted); font-size: var(--step--1); margin-top: var(--s3); }
  @media (max-width: 620px) {
    .ff-fig .ff-desktop { display: none; }
    .ff-fig .ff-mobile { display: block; max-width: 320px; margin: 0 auto; }
  }
</style>
<figure class="ff-fig" role="img" aria-label="A team of agents drafts a shared document in folio, which keeps it as append-only versions; an agent mints a no-login link, and a human opens it to read or edit the team-themed page.">
  <svg class="ff-desktop" viewBox="0 0 760 200" fill="none" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <marker id="ffa" markerWidth="9" markerHeight="9" refX="6" refY="4.5" orient="auto"><path d="M1 1 L6 4.5 L1 8" stroke="currentColor" stroke-width="1.4" fill="none"/></marker>
      <marker id="ffaa" markerWidth="9" markerHeight="9" refX="6" refY="4.5" orient="auto"><path d="M1 1 L6 4.5 L1 8" stroke="var(--accent)" stroke-width="1.6" fill="none"/></marker>
    </defs>
    <rect x="18" y="50" width="168" height="84" rx="12" fill="var(--surface)" stroke="currentColor" stroke-opacity="0.22"/>
    <rect x="26" y="58" width="168" height="84" rx="12" fill="var(--surface)" stroke="currentColor" stroke-opacity="0.45"/>
    <rect x="34" y="66" width="168" height="84" rx="12" fill="var(--surface)" stroke="currentColor"/>
    <text x="118" y="104" text-anchor="middle" font-family="var(--font-sans)" font-weight="650" font-size="16" fill="currentColor">Agents</text>
    <text x="118" y="124" text-anchor="middle" font-family="var(--font-sans)" font-size="12.5" fill="var(--muted)">your team</text>
    <path d="M210 108 H292" stroke="currentColor" stroke-width="1.4" marker-end="url(#ffa)"/>
    <text x="251" y="98" text-anchor="middle" font-family="var(--font-sans)" font-size="12" fill="var(--muted)">draft &amp; revise</text>
    <rect x="300" y="60" width="216" height="96" rx="12" fill="var(--surface)" stroke="currentColor"/>
    <text x="408" y="102" text-anchor="middle" font-family="var(--font-sans)" font-weight="650" font-size="16" fill="currentColor">Shared document</text>
    <text x="408" y="124" text-anchor="middle" font-family="var(--font-mono)" font-size="12" fill="var(--muted)">append-only versions</text>
    <path d="M524 108 H600" stroke="var(--accent)" stroke-width="1.8" marker-end="url(#ffaa)"/>
    <text x="562" y="98" text-anchor="middle" font-family="var(--font-sans)" font-weight="600" font-size="12" fill="var(--accent)">mint link</text>
    <rect x="608" y="66" width="134" height="84" rx="12" fill="var(--surface)" stroke="currentColor"/>
    <circle cx="675" cy="92" r="9" stroke="currentColor" stroke-width="1.5"/>
    <path d="M661 116 a14 12 0 0 1 28 0" stroke="currentColor" stroke-width="1.5"/>
    <text x="675" y="138" text-anchor="middle" font-family="var(--font-sans)" font-size="12.5" fill="var(--muted)">reads or edits</text>
  </svg>
  <svg class="ff-mobile" viewBox="0 0 300 360" fill="none" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <marker id="ffm" markerWidth="9" markerHeight="9" refX="6" refY="4.5" orient="auto"><path d="M1 1 L6 4.5 L1 8" stroke="currentColor" stroke-width="1.4" fill="none"/></marker>
      <marker id="ffma" markerWidth="9" markerHeight="9" refX="6" refY="4.5" orient="auto"><path d="M1 1 L6 4.5 L1 8" stroke="var(--accent)" stroke-width="1.6" fill="none"/></marker>
    </defs>
    <rect x="64" y="6" width="172" height="74" rx="12" fill="var(--surface)" stroke="currentColor"/>
    <text x="150" y="40" text-anchor="middle" font-family="var(--font-sans)" font-weight="650" font-size="15" fill="currentColor">Agents</text>
    <text x="150" y="59" text-anchor="middle" font-family="var(--font-sans)" font-size="12" fill="var(--muted)">your team</text>
    <path d="M150 84 V120" stroke="currentColor" stroke-width="1.4" marker-end="url(#ffm)"/>
    <text x="160" y="106" text-anchor="start" font-family="var(--font-sans)" font-size="11.5" fill="var(--muted)">draft &amp; revise</text>
    <rect x="54" y="126" width="192" height="80" rx="12" fill="var(--surface)" stroke="currentColor"/>
    <text x="150" y="162" text-anchor="middle" font-family="var(--font-sans)" font-weight="650" font-size="15" fill="currentColor">Shared document</text>
    <text x="150" y="182" text-anchor="middle" font-family="var(--font-mono)" font-size="11" fill="var(--muted)">append-only versions</text>
    <path d="M150 210 V246" stroke="var(--accent)" stroke-width="1.8" marker-end="url(#ffma)"/>
    <text x="160" y="232" text-anchor="start" font-family="var(--font-sans)" font-weight="600" font-size="11.5" fill="var(--accent)">mint link</text>
    <rect x="74" y="252" width="152" height="80" rx="12" fill="var(--surface)" stroke="currentColor"/>
    <circle cx="150" cy="282" r="9" stroke="currentColor" stroke-width="1.5"/>
    <path d="M136 306 a14 12 0 0 1 28 0" stroke="currentColor" stroke-width="1.5"/>
    <text x="150" y="326" text-anchor="middle" font-family="var(--font-sans)" font-size="12" fill="var(--muted)">human reads or edits</text>
  </svg>
  <figcaption>Agents draft and revise together; a minted link lets a human read or edit — no account, team-branded.</figcaption>
</figure>"""

# "Why this exists" — left lead (the need) + right column of three things folio
# gives, over thin rules (first accented). Mirrors the home-page skill's split.
_WHY_SECTION = """    <section class="section section--tint">
      <div class="wrap">
        <style>
          .why-split { display: grid; grid-template-columns: 1fr 1fr; gap: var(--s6); align-items: start; }
          .why-lead h2 { font-size: var(--step-3); margin-top: var(--s3); }
          .why-need { color: var(--muted); font-size: var(--step-1); margin-top: var(--s3); max-width: 34ch; }
          .why-answer { color: var(--muted); margin-top: var(--s4); max-width: 42ch; }
          .why-points { list-style: none; margin: var(--s3) 0 0; padding: 0; }
          .why-points li { border-top: 2px solid var(--line-strong); padding: var(--s3) 0; }
          .why-points li:first-child { border-top-color: var(--accent); }
          .why-points li:last-child { padding-bottom: 0; }
          .why-points strong { display: block; margin-bottom: 0.25rem; }
          .why-points span { color: var(--muted); }
          @media (max-width: 880px) { .why-split { grid-template-columns: 1fr; gap: var(--s5); } }
        </style>
        <div class="why-split">
          <div class="why-lead">
            <p class="kicker">Why this exists</p>
            <h2>A team's documents now come from its agents</h2>
            <p class="why-need">Briefs, specs, reports, decks — the outputs a team hands off. When the team is agents, the documents come from agents. folio is where they write them together and hand them to a human.</p>
            <p class="why-answer">Identity is the team's <a href="https://awid.ai">AWID</a> certificate — no usernames, no API keys, nothing for the human to install.</p>
          </div>
          <div>
            <p class="kicker" style="color:var(--faint)">What folio gives you</p>
            <ul class="why-points">
              <li><strong>A shared, versioned record</strong><span>Many agents append to one document; every edit is a new version and history is never rewritten.</span></li>
              <li><strong>A branded page</strong><span>The human opens a themed page — logo, colors, clean type — with nothing to install.</span></li>
              <li><strong>Access the team controls</strong><span>Hand out revocable no-login links to read or edit; the team mints them and the team revokes them.</span></li>
            </ul>
          </div>
        </div>
      </div>
    </section>"""

# "What folio does" — the six capabilities as a mono-label strip grid (label + one
# line over thin rules), not cards, so it doesn't twin with the naapp card grid.
_WHATFOLIO_SECTION = """    <section class="section section--tint">
      <div class="wrap">
        <style>
          .ff-do-grid { margin: var(--s5) 0 0; display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--s4) var(--s6); }
          .ff-do-grid > div { border-top: 1px solid var(--line-strong); padding-top: var(--s3); }
          .ff-do-grid > div:first-child { border-top-color: var(--accent); }
          .ff-do-grid dt { font: 650 var(--step--1)/1 var(--font-mono); letter-spacing: 0.02em; color: var(--ink); }
          .ff-do-grid dd { margin: var(--s2) 0 0; color: var(--muted); font-size: var(--step--1); }
          @media (max-width: 760px) { .ff-do-grid { grid-template-columns: 1fr 1fr; } }
          @media (max-width: 480px) { .ff-do-grid { grid-template-columns: 1fr; } }
        </style>
        <p class="kicker">What folio does</p>
        <h2 style="font-size:var(--step-3);margin-top:var(--s3)">Documents, versions, and the links between them</h2>
        <dl class="ff-do-grid">
          <div><dt>documents</dt><dd>Markdown, or schema-validated template slots; team-private, addressed by a slug.</dd></div>
          <div><dt>append-only</dt><dd>Each edit is a new version; present links pin a version — nothing is overwritten.</dd></div>
          <div><dt>templates</dt><dd>Declarative slots in a schema; the server validates and renders to Markdown.</dd></div>
          <div><dt>present links</dt><dd>Opaque, revocable, no-login, noindex — a capability URL, not a share link.</dd></div>
          <div><dt>safe media</dt><dd>Images and Cloudflare Stream video; team-supplied HTML and JS are stripped.</dd></div>
          <div><dt>team themes</dt><dd>CSS tokens, logo, header, footer — applied server-side on every page.</dd></div>
        </dl>
      </div>
    </section>"""

# "What it is" — the generic naapp definition: a plain lead + a 2x2 capability card
# grid + an in-practice callout. Distinct (cards) from the strip grid above it.
_WHATIS_SECTION = """    <section class="section">
      <div class="wrap">
        <style>
          .whatis-h2 { font-size: var(--step-3); margin-top: var(--s3); }
          .whatis-lead { color: var(--muted); font-size: var(--step-1); margin-top: var(--s3); max-width: 60ch; }
          .whatis-grid { list-style: none; margin: var(--s5) 0 0; padding: 0; display: grid; grid-template-columns: 1fr 1fr; gap: var(--s3); }
          .whatis-grid li { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); padding: var(--s4); }
          .whatis-grid .kicker { color: var(--muted); }
          .whatis-grid p { margin-top: var(--s2); font-size: var(--step-0); }
          .whatis-practice { margin-top: var(--s5); border-left: 2px solid var(--accent); padding-left: var(--s3); color: var(--muted); max-width: 72ch; }
          @media (max-width: 720px) { .whatis-grid { grid-template-columns: 1fr; } }
        </style>
        <p class="kicker">What it is</p>
        <h2 class="whatis-h2">A Native Agentic App</h2>
        <p class="whatis-lead">folio is built for agents from the ground up: its whole API is part of the aweb protocol, so any agent — or person — can drive it without writing custom code.</p>
        <ul class="whatis-grid">
          <li>
            <p class="kicker">CLI-native API</p>
            <p>A public manifest maps folio's whole API to <code>aw</code> commands. No integration to write, no SDK — you just run <code>aw folio</code>.</p>
          </li>
          <li>
            <p class="kicker">Events that wake agents</p>
            <p>folio emits a <code>doc.changed</code> event that wakes subscribed agents — a workflow that reacts to a new version needs no polling loop.</p>
          </li>
          <li>
            <p class="kicker">Ships agent docs</p>
            <p>An <code>llms.txt</code> and a set of skills ship with folio, so any agent that finds it gets readable docs and ready-to-run operations.</p>
          </li>
          <li>
            <p class="kicker">Verified by identity</p>
            <p>Every call is signed with your team's <a href="https://awid.ai">AWID</a> certificate; the manifest is public and pinned by a digest — auditable and tamper-evident.</p>
          </li>
        </ul>
        <p class="whatis-practice">In practice: a person and an agent run the exact same <code>aw folio</code> commands — create a document, append a version, mint a present link — with no custom code.</p>
      </div>
    </section>"""

# "Invariants" — the engineering guarantees as a spec/definition list with mono
# labels (no cards); the scope/limits line set apart below.
_INVARIANTS_SECTION = """    <section class="section section--tint" id="engineers">
      <div class="wrap">
        <style>
          .eng-h2 { font-size: var(--step-3); margin-top: var(--s3); }
          .eng-lede { color: var(--muted); font-size: var(--step-1); margin-top: var(--s3); max-width: 52ch; }
          .eng-specs { margin: var(--s5) 0 0; display: grid; grid-template-columns: 1fr 1fr; gap: var(--s4) var(--s6); }
          .eng-specs > div { border-top: 1px solid var(--line-strong); padding-top: var(--s3); }
          .eng-specs > div:first-child { border-top-color: var(--accent); }
          .eng-specs dt { font: 650 var(--step--1)/1 var(--font-mono); letter-spacing: 0.02em; color: var(--ink); }
          .eng-specs dd { margin: var(--s2) 0 0; color: var(--muted); font-size: var(--step-0); }
          .eng-scope { margin-top: var(--s5); color: var(--muted); font-size: var(--step--1); max-width: 72ch; }
          .eng-scope .kicker { color: var(--faint); margin-right: 0.6rem; }
          @media (max-width: 640px) { .eng-specs { grid-template-columns: 1fr; } }
        </style>
        <p class="kicker">For engineers</p>
        <h2 class="eng-h2">Invariants</h2>
        <p class="eng-lede">These hold at every version, for every team.</p>
        <dl class="eng-specs">
          <div>
            <dt>append-only</dt>
            <dd>A document version, once written, is never modified — the version number is its identity.</dd>
          </div>
          <div>
            <dt>awid-signed</dt>
            <dd>Every write is signed by the team's <a href="https://awid.ai">AWID</a> certificate, and the signer is recorded with each version.</dd>
          </div>
          <div>
            <dt>capability-links</dt>
            <dd>Present URLs are opaque tokens granting access to exactly one version, revocable by the team that minted them.</dd>
          </div>
          <div>
            <dt>sanitized-output</dt>
            <dd>The server generates all rendered HTML; team-supplied HTML and JavaScript are stripped before storage.</dd>
          </div>
        </dl>
        <p class="eng-scope"><span class="kicker">Scope</span>folio stores and presents documents — it does not run agents, route messages, or manage compute. Content is server-readable, not end-to-end encrypted. A <code>folio/doc.changed</code> metadata event (no content) can wake subscribed agents.</p>
      </div>
    </section>"""


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
        <h1>Where teams of agents work on shared documents</h1>
{_FOLIO_DIAGRAM}
        <div class="cta-row">
          <a class="btn primary btn--lg" href="#use">Get started</a>
          <a class="btn secondary btn--lg" href="/llms.txt">Read llms.txt</a>
        </div>
      </div>
    </section>

{_WHY_SECTION}

    <section class="section" id="use">
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

{_WHATFOLIO_SECTION}

{_WHATIS_SECTION}

{_INVARIANTS_SECTION}

    <section class="section">
      <div class="wrap" style="text-align:center">
        <p style="font-size:var(--step-2);font-weight:650;letter-spacing:-0.02em;max-width:28ch;margin:0 auto var(--s4)">Give your agent team a place to write.</p>
        <div class="cta-row" style="justify-content:center">
          <a class="btn primary btn--lg" href="#use">Get started</a>
          <a class="btn secondary btn--lg" href="/reference">API reference</a>
        </div>
      </div>
    </section>"""
    return naapp.page(site, body)


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

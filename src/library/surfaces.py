from __future__ import annotations

import os
import re
from html import escape
from pathlib import Path

import aweb_naapp as naapp
from aweb_naapp import FooterColumn, NavLink, SiteConfig, aweb_css

from library.aweb_manifest import MANIFEST

__all__ = [
    "aweb_css",
    "render_landing_page",
    "render_reference_page",
    "llms_txt",
    "robots_txt",
    "skills_index",
    "read_skill",
    "skill_names",
]

_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_DIR = _REPO_ROOT / "skills"
_CONTAINER_SKILLS_DIR = Path("/app/skills")

# library's identity in the shared naapp chrome. The aweb design system, the
# chrome, the manifest-driven llms.txt blocks, and the /reference page all come
# from aweb_naapp; library supplies its manifest, this site config, and its own
# landing body and llms.txt prose.
_VERB = "library"
_NAV_LINKS = (
    NavLink("Model", "/#model"),
    NavLink("llms.txt", "/llms.txt"),
    NavLink("Reference", "/reference"),
    NavLink("Skills", "/skills/"),
    NavLink("AWID", "https://awid.ai"),
)
_FOOTER_BLURB = (
    "Public profile packs and private team shelves for AWID teams — "
    "adopt, bind, materialize, and evolve your agents' profiles."
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
    "library is a Native Agentic App on the aweb.ai hub. AWID is the identity authority."
)
# library's domain values for the shared docs generators: live path-param values
# that make the public catalog reads genuinely runnable, the public-reads phrase,
# and the /reference section copy in library's own nouns.
_EXAMPLE_PATH_VALUES = {"pack_ref": "aweb.engineering-pack", "profile_ref": "coordinator"}
_READS_PHRASE = "catalog reads"
_REFERENCE_COPY = naapp.ReferenceCopy(
    reads_phrase=_READS_PHRASE,
    rejects_subject="Library",
    envelope_path_example="/v1/shelf/import or /v1/profile-packs?tags=starter",
    public_kicker="Public operations",
    public_heading="Catalog reads — no auth",
    public_blurb="Browse the public profile-pack catalog. These are literal and copy-paste-runnable.",
    team_kicker="Team operations",
    team_heading="Shelf, bindings, materialize, proposals — AWID team certificate",
    team_blurb=(
        "Each shows the canonical verb, the signed hand-runnable "
        "<code>aw id request</code> form, and the raw wire format aw produces."
    ),
)


def _site(*, public_origin: str, title: str, description: str) -> SiteConfig:
    return SiteConfig(
        origin=public_origin.rstrip("/"),
        brand="library",
        title=title,
        description=description,
        nav_links=_NAV_LINKS,
        footer_blurb=_FOOTER_BLURB,
        footer_columns=_FOOTER_COLUMNS,
        footer_bottom=_FOOTER_BOTTOM,
    )


def _skills_dir() -> Path:
    configured = os.environ.get("LIBRARY_SKILLS_DIR")
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
        title="library — agent profiles for AWID teams",
        description=(
            "library is the agent-first service for public profile packs, private team "
            "shelves, bindings, materialization, and learning for AWID teams."
        ),
    )
    body = f"""    <section class="hero-center">
      <div class="wrap">
        <p class="kicker">Native Agentic App · library.aweb.ai</p>
        <h1>Where teams choose, keep, and improve the profiles their agents run.</h1>
        <p class="lede">library.aweb.ai is the Native Agentic App for agent profiles: a public catalog of profile packs, a private team shelf of adopted profiles, and an approval loop that lets teams evolve how their agents work. A profile is an agent's job description — its mission, its instructions, the tools it may use, and what needs a human's sign-off.</p>
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
          <p>llms.txt is the complete, plain-text guide to operating library: what it is, how to install it in <code>aw</code>, how team-certificate auth works, every operation with its parameters, and the getting-started journey. An agent that reads it can drive library end to end.</p>
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
          <p class="kicker">Why this exists</p>
          <h2>AI agents are starting to do real work — as teams</h2>
          <p>A coordinator that routes the work, a developer that writes the code, a reviewer that checks it. Each one needs a clear account of its job: its mission, its instructions, the tools it may use, and what needs a human's sign-off.</p>
        </div>
        <p class="prose-intro">Today that account is usually a prompt pasted into a box — no versions, nothing shared between teams, no identity behind it, no record of what changed. That does not hold up once you are trusting agents with real work.</p>
        <p class="prose-outro"><strong>aweb</strong> is the system that makes agent teams workable: it gives every agent and team a verifiable identity — an <a href="https://awid.ai">AWID</a>, a cryptographic passport instead of accounts and API keys — and a single command-line tool, <code>aw</code>, to drive it. <strong>library</strong> is the part of aweb that holds the agents' job descriptions. That is what this is.</p>
      </div>
    </section>

    <section class="section">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">What it is</p>
          <h2>A Native Agentic App</h2>
          <p>A Native Agentic App (naapp) is an aweb app designed for agents to operate directly: it publishes a canonical manifest (a public byte artifact, identified by its digest) that turns its API into native <code>aw</code> verbs, can declare event emitters that wake subscribed agents, and ships agent-readable llms.txt and skills. The manifest is public; what is signed is each verb call, with your team certificate.</p>
        </div>
        <p class="prose-outro">In practice: you do not write an integration or click around a console. You install library into <code>aw</code> once (below), and from then on a person or an agent runs the same <code>aw library</code> commands. Because the manifest is machine-readable, an agent can discover and operate library with no custom code.</p>
      </div>
    </section>

    <section class="section section--tint" id="model">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">The model</p>
          <h2>A catalog, a shelf, and an approval loop</h2>
          <p>Public packs are the versioned catalog anyone can adopt from; your shelf is your team's private working set. From there you bind profiles to agents, materialize them into runnable homes, and improve them under review.</p>
        </div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Profiles</h3><p>An agent's job description as a file: mission, instructions, the tools it may use, the actions that need a human's sign-off, and its skills. Versioned by content digest.</p></article>
          <article class="card"><h3>Public packs</h3><p>First-party, versioned collections of profiles any team can browse and adopt — proven roles like coordinator, developer, and reviewer.</p></article>
          <article class="card"><h3>Private shelf</h3><p>Your team's own copies — adopted from a pack or authored fresh — the working set you edit and own.</p></article>
          <article class="card"><h3>Bind &amp; materialize</h3><p>Assign a shelf profile to an agent identity, then materialize it: library produces the runnable home — a composed AGENTS.md, installed skills, and the full profile under <code>.aw/profile/</code>.</p></article>
          <article class="card"><h3>Proposals &amp; minting</h3><p>An agent proposes a new version from what it learned; a human approves, and library mints it — immutably versioned by digest, with the signer recorded.</p></article>
          <article class="card"><h3>Update from source</h3><p>Pull a newer pack version's improvements into the parts you have not edited — a per-part merge that never clobbers local work.</p></article>
        </div>
      </div>
    </section>

    <section class="section" id="use">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">Get started</p>
          <h2>Install aw, create a team, run agents from profiles</h2>
          <p><code>aw</code> is the only thing to install; library plugs into it. Browsing the catalog needs no identity; creating your team mints the certificate that every later command signs with.</p>
        </div>
        <div class="cmd-panel">
          <p class="cmd-label">1 · Install aw, the aweb command-line tool</p>
          <div class="cmd-list"><div class="cmd"><pre>npm install -g @awebai/aw</pre>{copy}</div></div>
          <p class="cmd-label">2 · Add the library naapp — its operations become native aw library verbs</p>
          <div class="cmd-list"><div class="cmd"><pre>aw plugin install {origin}/.well-known/aweb-app.json</pre>{copy}</div></div>
          <p class="cmd-label">3 · Browse the public catalog — no identity needed</p>
          <div class="cmd-list"><div class="cmd"><pre>aw library list-packs</pre>{copy}</div></div>
          <p class="cmd-label">4 · Create your team — mints your identity and team certificate</p>
          <div class="cmd-list"><div class="cmd"><pre>aw team create my-team</pre>{copy}</div></div>
          <p class="cmd-label">5 · Adopt one profile from the pack onto your shelf</p>
          <div class="cmd-list"><div class="cmd"><pre>aw library import-to-shelf \\
  --source_profile_pack_ref aweb.engineering-pack \\
  --source_profile_pack_version 0.1.0 \\
  --profile_ref coordinator</pre>{copy}</div></div>
          <p class="cmd-label">6 · Add an agent from your shelf — binds it and materializes its home, and prints the path</p>
          <div class="cmd-list"><div class="cmd"><pre>aw team add alice@coordinator</pre>{copy}</div></div>
        </div>
        <p class="prose-intro">That is the whole path — from an empty machine to a materialized home for an agent named <code>alice</code> running the coordinator profile. The <code>aw team add</code> command prints the home directory it wrote, ready for you to launch your harness in.</p>
        <p class="prose-outro"><strong>Shortcut:</strong> name a pack profile directly and <code>aw team add</code> adopts and adds in one, skipping step 5:</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>aw team add alice@aweb.engineering-pack/coordinator</pre>{copy}</div></div>
        </div>
        <p class="prose-outro">Every library operation is a native <code>aw library</code> verb — <code>aw library shelf</code> shows your working set and which profiles have upstream updates. Agents read the whole surface at <a href="/llms.txt">llms.txt</a>; the dispatcher reads the <a href="/aweb-app.json">canonical manifest</a>.</p>
      </div>
    </section>

    <section class="section section--tint" id="engineers">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">For engineers</p>
          <h2>What's actually real</h2>
          <p>No magic words — concrete, versioned, signed behavior you can reproduce.</p>
        </div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Immutable versions</h3><p>Every profile version is identified by a content digest. Reference a digest and you get exactly that content — there is no "latest" pointer that silently moves.</p></article>
          <article class="card"><h3>Signed, no accounts</h3><p>There are no app accounts or API keys. Every write is a request signed by your team's AWID identity, and the signer is recorded with each change.</p></article>
          <article class="card"><h3>Per-part updates</h3><p>update-from-source merges a newer pack version part by part: it takes upstream changes only where you have not edited, and an existing version is never overwritten.</p></article>
          <article class="card"><h3>Reproducible homes</h3><p>Materializing a profile by digest produces the same files every time — an agent's starting behavior is set by the profile, not by hidden state.</p></article>
          <article class="card"><h3>Honest boundary</h3><p>library defines how agents behave. It does not run them, route messages, or manage compute — those are separate aweb concerns. v0 has no dashboard and emits no events.</p></article>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">The bigger bet</p>
          <h2>Agent behavior as a first-class artifact</h2>
          <p>Today an agent's behavior is a pasted prompt: unversioned, unshared, no identity, no audit. library treats it the way software treats code — authored, versioned, shared, reviewed, and signed. The public catalog compounds as teams adopt and improve profiles; an agent that proposes a good change contributes it back.</p>
        </div>
        <div class="cta-row">
          <a class="btn primary btn--lg" href="#use">Get started</a>
          <a class="btn secondary btn--lg" href="/aweb-app.json">Read the manifest</a>
        </div>
      </div>
    </section>"""
    return naapp.page(site, body, include_copy_llms=True)


def render_reference_page(*, public_origin: str) -> str:
    site = _site(
        public_origin=public_origin,
        title="library — API reference",
        description=(
            "Every library operation in parallel: the canonical aw library verb and the "
            "raw HTTP wire format with AWID team-certificate signing."
        ),
    )
    return naapp.render_reference(
        MANIFEST,
        site,
        verb=_VERB,
        example_path_values=_EXAMPLE_PATH_VALUES,
        copy=_REFERENCE_COPY,
    )


def llms_txt(*, public_origin: str) -> str:
    origin = public_origin.rstrip("/")
    public_ops = naapp.llms.public_operations(MANIFEST, _VERB)
    team_ops = naapp.llms.cert_operations(MANIFEST, _VERB)
    auth = naapp.llms.auth_section(MANIFEST, origin, reads_phrase=_READS_PHRASE)
    return f"""# library — agent-first profiles for AWID teams

library is the app that owns agent profiles, profile packs, profile versions and
digests, agent-profile bindings, materialization payloads, and profile learning.
This is a Native Agentic App (naapp): an aweb app agents operate directly via its
canonical manifest (a public byte artifact identified by its digest), published for
the aweb.ai hub index. There are no app-local accounts, passwords, or OAuth sessions.

AWID is the identity authority: https://awid.ai
aweb hub: https://aweb.ai

Origin:
- Production: {origin}
- Local development: http://127.0.0.1:8765

The model is structural: profile packs are the public, versioned catalog; a team's
shelf holds its private working copies. A team adopts a pack profile onto its shelf,
evolves it (new versions, proposals), binds agents to shelf profiles, and
materializes them. "Public" is a publish, not a flag.


## Getting started

Install aw, install library, adopt a profile, add an agent. Each step is a real
command; nothing here needs a browser or an account.

1. npm install -g @awebai/aw
2. aw plugin install {origin}/.well-known/aweb-app.json
3. aw library list-packs
4. aw team create my-team
5. aw library import-to-shelf --source_profile_pack_ref aweb.engineering-pack --source_profile_pack_version 0.1.0 --profile_ref coordinator
6. aw team add alice@coordinator

Step 6 binds the profile, materializes the agent's home, and prints the home
directory path it wrote. Shortcut: aw team add alice@aweb.engineering-pack/coordinator
adopts the pack profile onto your shelf and adds the agent in one command.


## How to call it

The canonical form is the native plugin verbs: after
aw plugin install {origin}/.well-known/aweb-app.json, every operation below is
aw library <verb> (e.g. aw library list-packs, aw library import-to-shelf,
aw library shelf, aw library materialize). The HTTP endpoints below are the same
surface; call them directly with aw id request --team-auth (the low-level escape
hatch) if you are not using the plugin.


## Authentication

{auth}


## Operations

Public operations (no auth):

{public_ops}

Team operations (AWID team certificate):

{team_ops}


## Invariants

- AWID is authority for team keys, certificates, and revocation.
- Every team-scoped read/write is keyed by the verified certificate team_id.
- Public catalog reads are unauthenticated; profiles do not grant app access.
- Shelf versions are immutable: a version's digest is its identity, never overwritten.
- library owns its own binding, materialization, and proposal state.
"""


def robots_txt() -> str:
    return """User-agent: *
Allow: /
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
        "# library agent skills",
        "",
        "library is a Native Agentic App (naapp) on the aweb.ai hub.",
        "Agents should fetch the relevant skill before acting so requests match the library API contract.",
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

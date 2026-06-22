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
    "Public blueprints and private team shelves for AWID teams — "
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
_EXAMPLE_PATH_VALUES = {"blueprint_ref": "aweb.engineering", "profile_ref": "coordinator"}
_READS_PHRASE = "catalog reads"
_REFERENCE_COPY = naapp.ReferenceCopy(
    reads_phrase=_READS_PHRASE,
    rejects_subject="Library",
    envelope_path_example="/v1/shelf/import or /v1/blueprints?tags=starter",
    public_kicker="Public operations",
    public_heading="Catalog reads — no auth",
    public_blurb="Browse the public blueprint catalog. These are literal and copy-paste-runnable.",
    team_kicker="Team operations",
    team_heading="Shelf, bindings, materialize, proposals — AWID team certificate",
    team_blurb=(
        "Each shows the canonical verb, the signed hand-runnable "
        "<code>aw id request</code> form, and the raw wire format aw produces."
    ),
)

# The hero model diagram: Catalog -> Shelf -> Agent with the human-gated approval
# loop (the one terracotta accent). Self-contained (its own <style> + two SVG
# variants swapped at the 600px breakpoint), themeable via currentColor + tokens,
# with a full text alternative on the figure. library-specific hero content.
_MODEL_DIAGRAM = """<style>
  .model-fig { max-width: 760px; margin: 1.6rem auto 0; color: var(--ink); }
  .model-fig svg { width: 100%; height: auto; display: block; font-family: var(--font-sans); }
  .model-fig figcaption { text-align: center; color: var(--muted); margin-top: .7rem; font-size: var(--step--1); }
  .model-fig .mf-mobile { display: none; }
  @media (max-width: 600px) {
    .model-fig { max-width: 360px; }
    .model-fig .mf-desktop { display: none; }
    .model-fig .mf-mobile { display: block; }
  }
</style>
<figure class="model-fig" role="img" aria-label="Flow: a public Catalog of blueprints is adopted onto a team's private Shelf; a Shelf profile is bound to create a running Agent; the Agent proposes changes, a human reviews and approves, and library mints a new version back onto the Shelf.">
  <svg class="mf-desktop" viewBox="0 0 760 230" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <defs>
      <marker id="mfd" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="currentColor"/></marker>
      <marker id="mfda" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" style="fill:var(--accent)"/></marker>
    </defs>
    <rect x="8" y="18" width="212" height="68" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <rect x="274" y="18" width="212" height="68" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <rect x="540" y="18" width="212" height="68" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <text x="114" y="49" text-anchor="middle" font-size="17" font-weight="600" fill="currentColor">Catalog</text>
    <text x="114" y="69" text-anchor="middle" font-size="12.5" style="fill:var(--muted)">Public blueprints</text>
    <text x="380" y="43" text-anchor="middle" font-size="17" font-weight="600" fill="currentColor">Shelf</text>
    <text x="380" y="61" text-anchor="middle" font-size="12.5" style="fill:var(--muted)">Team's private profiles</text>
    <text x="380" y="79" text-anchor="middle" font-size="10.5" style="fill:var(--muted);opacity:.8">mission &#183; instructions &#183; tools &#183; sign-off</text>
    <text x="646" y="49" text-anchor="middle" font-size="17" font-weight="600" fill="currentColor">Agent</text>
    <text x="646" y="69" text-anchor="middle" font-size="12.5" style="fill:var(--muted)">Bound &amp; running</text>
    <path d="M222,52 H270" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfd)"/>
    <path d="M488,52 H536" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfd)"/>
    <text x="246" y="42" text-anchor="middle" font-size="12" style="fill:var(--muted)">adopt</text>
    <text x="512" y="42" text-anchor="middle" font-size="12" style="fill:var(--muted)">bind</text>
    <ellipse cx="513" cy="182" rx="72" ry="23" fill="none" style="stroke:var(--line)"/>
    <circle cx="471" cy="178" r="3.6" fill="none" stroke="currentColor" stroke-width="1.4"/>
    <path d="M464,190 q7,-9 14,0" fill="none" stroke="currentColor" stroke-width="1.4"/>
    <text x="487" y="186" font-size="12" style="fill:var(--muted)">human review</text>
    <path d="M646,86 V182 H586" fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfd)"/>
    <text x="616" y="171" text-anchor="middle" font-size="12" style="fill:var(--muted)">propose</text>
    <path d="M441,182 H330 V86" fill="none" stroke-width="1.5" style="stroke:var(--accent)" marker-end="url(#mfda)"/>
    <text x="383" y="171" text-anchor="middle" font-size="12" font-weight="600" style="fill:var(--accent)">approve &amp; mint</text>
  </svg>
  <svg class="mf-mobile" viewBox="0 0 360 470" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <defs>
      <marker id="mfm" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="currentColor"/></marker>
      <marker id="mfma" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" style="fill:var(--accent)"/></marker>
    </defs>
    <rect x="140" y="12" width="210" height="60" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <rect x="140" y="150" width="210" height="76" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <rect x="140" y="330" width="210" height="60" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <text x="245" y="40" text-anchor="middle" font-size="16" font-weight="600" fill="currentColor">Catalog</text>
    <text x="245" y="59" text-anchor="middle" font-size="12" style="fill:var(--muted)">Public blueprints</text>
    <text x="245" y="176" text-anchor="middle" font-size="16" font-weight="600" fill="currentColor">Shelf</text>
    <text x="245" y="194" text-anchor="middle" font-size="12" style="fill:var(--muted)">Team's private profiles</text>
    <text x="245" y="212" text-anchor="middle" font-size="10" style="fill:var(--muted);opacity:.8">mission &#183; instructions &#183; tools &#183; sign-off</text>
    <text x="245" y="358" text-anchor="middle" font-size="16" font-weight="600" fill="currentColor">Agent</text>
    <text x="245" y="377" text-anchor="middle" font-size="12" style="fill:var(--muted)">Bound &amp; running</text>
    <path d="M245,72 V148" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfm)"/>
    <path d="M245,226 V328" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfm)"/>
    <text x="257" y="114" font-size="12" style="fill:var(--muted)">adopt</text>
    <text x="257" y="282" font-size="12" style="fill:var(--muted)">bind</text>
    <ellipse cx="66" cy="270" rx="58" ry="22" fill="none" style="stroke:var(--line)"/>
    <circle cx="44" cy="266" r="3.4" fill="none" stroke="currentColor" stroke-width="1.4"/>
    <path d="M38,277 q6,-8 12,0" fill="none" stroke="currentColor" stroke-width="1.4"/>
    <text x="57" y="274" font-size="11" style="fill:var(--muted)">human review</text>
    <path d="M140,360 H66 V292" fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfm)"/>
    <text x="100" y="350" text-anchor="middle" font-size="12" style="fill:var(--muted)">propose</text>
    <path d="M66,248 V200 H140" fill="none" stroke-width="1.5" style="stroke:var(--accent)" marker-end="url(#mfma)"/>
    <text x="74" y="192" font-size="11" font-weight="600" style="fill:var(--accent)">approve &amp; mint</text>
  </svg>
  <figcaption>Browse the catalog, build your shelf, run your team.</figcaption>
</figure>"""


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
            "library is the agent-first service for public blueprints, private team "
            "shelves, bindings, materialization, and learning for AWID teams."
        ),
    )
    body = f"""    <section class="hero-center">
      <div class="wrap">
        <p class="kicker">Native Agentic App · library.aweb.ai</p>
        <h1>Where teams choose, keep, and improve the profiles their agents run.</h1>
        {_MODEL_DIAGRAM}
        <div class="cta-row">
          <a class="btn primary btn--lg" href="#use">Get started</a>
          <a class="btn secondary btn--lg" href="/llms.txt">Read llms.txt</a>
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
          <p>Public blueprints are the versioned catalog anyone can adopt from; your shelf is your team's private working set. From there you bind profiles to agents, materialize them into runnable homes, and improve them under review.</p>
        </div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Profiles</h3><p>An agent's job description as a file: mission, instructions, the tools it may use, the actions that need a human's sign-off, and its skills. Versioned by content digest.</p></article>
          <article class="card"><h3>Public blueprints</h3><p>First-party, versioned collections of profiles any team can browse and adopt — proven roles like coordinator, developer, and reviewer.</p></article>
          <article class="card"><h3>Private shelf</h3><p>Your team's own copies — adopted from a blueprint or authored fresh — the working set you edit and own.</p></article>
          <article class="card"><h3>Bind &amp; materialize</h3><p>Assign a shelf profile to an agent identity, then materialize it: library produces the runnable home — a composed AGENTS.md, installed skills, and the full profile under <code>.aw/profile/</code>.</p></article>
          <article class="card"><h3>Proposals &amp; minting</h3><p>An agent proposes a new version from what it learned; a human approves, and library mints it — immutably versioned by digest, with the signer recorded.</p></article>
          <article class="card"><h3>Update from source</h3><p>Pull a newer blueprint version's improvements into the parts you have not edited — a per-part merge that never clobbers local work.</p></article>
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
          <div class="cmd-list"><div class="cmd"><pre>aw library list-blueprints</pre>{copy}</div></div>
          <p class="cmd-label">4 · Create your team — mints your identity and team certificate</p>
          <div class="cmd-list"><div class="cmd"><pre>aw team create my-team</pre>{copy}</div></div>
          <p class="cmd-label">5 · Add an agent — adopt the profile, choose its runtime, and materialize its home, in one</p>
          <div class="cmd-list"><div class="cmd"><pre>aw team add alice@aweb.engineering/coordinator --runtime claude-code</pre>{copy}</div></div>
        </div>
        <p class="prose-intro">That is the whole path — from an empty machine to a materialized home for an agent named <code>alice</code> running the coordinator profile. The selector is <code>NAME@BLUEPRINT/PROFILE</code>: it adopts the blueprint profile onto your shelf and adds the agent in one. The runtime is your explicit choice: omitting <code>--runtime</code> defaults to <code>claude-code</code> (a CLI default, not read from the profile). The command prints the home directory it wrote.</p>
        <p class="prose-outro"><strong>Whole roster at once:</strong> create the team and its agents in one command, each profile's runtime after an <code>=</code>:</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>aw team create my-team \\
  --profile aweb.engineering/coordinator=claude-code \\
  --profile aweb.engineering/reviewer=pi</pre>{copy}</div></div>
        </div>
        <p class="prose-outro">A blueprint's <code>runtime_hints</code> and <code>runtime_assumptions</code> are advisory metadata you read to choose the runtime — query them with <code>aw blueprint inspect</code> or <code>aw library get-profile</code>; they are not auto-applied.</p>
        <p class="prose-outro"><strong>Adopt without adding an agent:</strong> to copy a blueprint profile onto your shelf and evolve it before binding, use <code>import-to-shelf</code>:</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>aw library import-to-shelf \\
  --source_blueprint_ref aweb.engineering \\
  --source_blueprint_version 0.1.0 \\
  --profile_ref coordinator</pre>{copy}</div></div>
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
          <article class="card"><h3>Per-part updates</h3><p>update-from-source merges a newer blueprint version part by part: it takes upstream changes only where you have not edited, and an existing version is never overwritten.</p></article>
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
    return naapp.page(site, body)


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

library is the app that owns agent profiles, blueprints, profile versions and
digests, agent-profile bindings, materialization payloads, and profile learning.
This is a Native Agentic App (naapp): an aweb app agents operate directly via its
canonical manifest (a public byte artifact identified by its digest), published for
the aweb.ai hub index. There are no app-local accounts, passwords, or OAuth sessions.

AWID is the identity authority: https://awid.ai
aweb hub: https://aweb.ai

Origin:
- Production: {origin}
- Local development: http://127.0.0.1:8765

The model is structural: blueprints are the public, versioned catalog; a team's
shelf holds its private working copies. A team adopts a blueprint profile onto its shelf,
evolves it (new versions, proposals), binds agents to shelf profiles, and
materializes them. "Public" is a publish, not a flag.


## Getting started

Install aw, install library, adopt a profile, add an agent. Each step is a real
command; nothing here needs a browser or an account.

1. npm install -g @awebai/aw
2. aw plugin install {origin}/.well-known/aweb-app.json
3. aw library list-blueprints
4. aw team create my-team
5. aw team add alice@aweb.engineering/coordinator --runtime claude-code

Step 5 uses the NAME@BLUEPRINT/PROFILE selector: it adopts the blueprint profile
onto your shelf, adds the agent, chooses its runtime, materializes its home, and
prints the home directory path it wrote. The runtime is an explicit choice:
omitting --runtime defaults to claude-code (a CLI default, not read from the
profile). Whole roster at once, each profile's runtime after an =:
aw team create my-team --profile aweb.engineering/coordinator=claude-code --profile aweb.engineering/reviewer=pi

To adopt a profile onto your shelf without adding an agent (e.g. to evolve it
before binding), use import-to-shelf:
aw library import-to-shelf --source_blueprint_ref aweb.engineering --source_blueprint_version 0.1.0 --profile_ref coordinator

A blueprint's runtime_hints and runtime_assumptions are advisory metadata you read
to choose the runtime (query them with aw blueprint inspect or aw library
get-profile); they are not auto-applied.


## How to call it

The canonical form is the native plugin verbs: after
aw plugin install {origin}/.well-known/aweb-app.json, every operation below is
aw library <verb> (e.g. aw library list-blueprints, aw library import-to-shelf,
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

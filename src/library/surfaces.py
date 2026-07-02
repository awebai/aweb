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
    NavLink("Reference", "/reference"),
    NavLink("Skills", "/skills/"),
    NavLink("awid", "https://awid.ai"),
    NavLink("aweb", "https://aweb.ai"),
)
_FOOTER_BLURB = (
    "Public blueprints and private team shelves for <span class=\"brand-word\">awid</span> teams — "
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
            NavLink("awid", "https://awid.ai"),
        ),
    ),
)
_FOOTER_BOTTOM = (
    'library is a Native Agentic App on the <span class="brand-word">aweb</span>.ai hub. <span class="brand-word">awid</span> is the identity authority.'
)
# library's domain values for the shared docs generators: live path-param values
# that make the public catalog reads genuinely runnable, the public-reads phrase,
# and the /reference section copy in library's own nouns.
_EXAMPLE_PATH_VALUES = {"blueprint_ref": "aweb.team", "profile_ref": "developer"}
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

# "Why this exists" — a full-width problem statement: a left lead + a right column
# naming what a pasted prompt lacks (one terracotta accent on the first beat), then
# a one-line answer. Self-contained <style> for the responsive split; tokens for
# light/dark.
_WHY_SECTION = """    <section class="section section--tint">
      <div class="wrap">
        <style>
          .why-split { display: grid; grid-template-columns: 1fr 1fr; gap: var(--s6); align-items: start; }
          .why-lead h2 { font-size: var(--step-3); margin-top: var(--s3); }
          .why-need { color: var(--muted); font-size: var(--step-1); margin-top: var(--s3); max-width: 32ch; }
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
            <h2>Agents need evolving job descriptions to work as a team</h2>
            <p class="why-need">A coordinator routes the work, a developer writes the code, a reviewer checks it. Each role needs a clear, stable account of its job.</p>
            <p class="why-answer">Every profile is versioned by digest and every change is signed with your team's <a href="https://awid.ai" class="brand-word">awid</a> identity — so what you adopt and evolve is reproducible and trusted.</p>
          </div>
          <div>
            <p class="kicker" style="color:var(--faint)">What library gives you</p>
            <ul class="why-points">
              <li><strong>Proven profiles to start from</strong><span>A first-party catalog of high-quality profiles — coordinator, developer, reviewer — ready to adopt.</span></li>
              <li><strong>Build and share your own</strong><span>Author a profile and publish it; any team can adopt it and build on it.</span></li>
              <li><strong>Start shared, evolve private</strong><span>Adopt a profile onto your team's private shelf and evolve it there, under review.</span></li>
            </ul>
          </div>
        </div>
      </div>
    </section>"""

# "What it is" — a plain-language definition lead + a 2x2 grid of the four naapp
# capabilities (distinct from the why-section's beats), with the in-practice
# punchline as a terracotta-bordered callout. Self-contained <style>; tokens.
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
        <p class="whatis-lead">library is built for agents from the ground up: its whole API is part of the <span class="brand-word">aweb</span> protocol, so any agent — or person — can discover and drive it without writing custom code.</p>
        <ul class="whatis-grid">
          <li>
            <p class="kicker">CLI-native API</p>
            <p>A public manifest maps library's whole API to <code>aw</code> commands. No integration to write, no SDK to wire up — you just run <code>aw library</code>.</p>
          </li>
          <li>
            <p class="kicker">Events that wake agents</p>
            <p>library emits events that wake subscribed agents automatically — a workflow that reacts to new content needs no polling loop.</p>
          </li>
          <li>
            <p class="kicker">Ships agent docs</p>
            <p>An <code>llms.txt</code> and a set of skills ship with library, so any agent that finds it gets readable docs and ready-to-run operations.</p>
          </li>
          <li>
            <p class="kicker">Verified by identity</p>
            <p>The manifest is public and pinned by a digest; every call is signed with your team's <a href="https://awid.ai" class="brand-word">awid</a> — auditable and tamper-evident.</p>
          </li>
        </ul>
        <p class="whatis-practice">In practice: a person and an agent run the exact same <code>aw library</code> commands. Because the manifest is machine-readable, an agent discovers and operates library with no custom code.</p>
      </div>
    </section>"""

# "For engineers" — the concrete guarantees as a spec/definition list: mono term
# labels, horizontal rules (first one terracotta), no card surfaces (distinct from
# the why-beats and the what-it-is cards). The scope/limits line sits apart below.
_ENGINEERS_SECTION = """    <section class="section section--tint" id="engineers">
      <div class="wrap">
        <style>
          .eng-h2 { font-size: var(--step-3); margin-top: var(--s3); }
          .eng-lede { color: var(--muted); font-size: var(--step-1); margin-top: var(--s3); max-width: 52ch; }
          .eng-specs { margin: var(--s5) 0 0; display: grid; grid-template-columns: 1fr 1fr; gap: var(--s4) var(--s6); }
          .eng-specs > div { border-top: 1px solid var(--line-strong); padding-top: var(--s3); }
          .eng-specs > div:first-child { border-top-color: var(--accent); }
          .eng-specs dt { font: 650 var(--step--1)/1 var(--font-mono); letter-spacing: 0.02em; color: var(--ink); }
          .eng-specs dd { margin: var(--s2) 0 0; color: var(--muted); font-size: var(--step-0); }
          .eng-scope { margin-top: var(--s5); color: var(--muted); font-size: var(--step--1); max-width: 70ch; }
          .eng-scope .kicker { color: var(--faint); margin-right: 0.6rem; }
          @media (max-width: 640px) { .eng-specs { grid-template-columns: 1fr; } }
        </style>
        <p class="kicker">For engineers</p>
        <h2 class="eng-h2">Invariants</h2>
        <p class="eng-lede">These four properties hold at every version, for every team.</p>
        <dl class="eng-specs">
          <div>
            <dt>content-addressed</dt>
            <dd>Every profile version is identified by its content digest. Reference a digest and you get exactly that content — no "latest" pointer that can silently move.</dd>
          </div>
          <div>
            <dt>awid-signed</dt>
            <dd>No app accounts or API keys. Every write is signed by your team's <a href="https://awid.ai" class="brand-word">awid</a> identity, and the signer is recorded with each change.</dd>
          </div>
          <div>
            <dt>non-destructive merge</dt>
            <dd><code>update-from-source</code> takes upstream blueprint changes only where you haven't edited locally — an existing version is never overwritten.</dd>
          </div>
          <div>
            <dt>byte-reproducible</dt>
            <dd>Materializing a profile by digest produces the same files every time. Starting behavior is set by the profile, not by hidden runtime state.</dd>
          </div>
        </dl>
        <p class="eng-scope"><span class="kicker">Scope</span>library defines how agents behave — it does not run agents, route messages, or manage compute. v0 has no dashboard and emits no events.</p>
      </div>
    </section>"""


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
        header_actions=(),
        source_url="https://github.com/awebai/library",
        og_image="/og-card.png",
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
        <p style="margin-top:var(--s3);font-size:var(--step-0);color:var(--muted)">Open source, MIT-licensed — <a href="https://github.com/awebai/library" style="color:var(--accent);font-weight:550">github.com/awebai/library</a></p>
      </div>
    </section>

{_WHY_SECTION}

{_WHATIS_SECTION}

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
          <h2>Install aw, add agents, run one interactively</h2>
          <p>The minimal do-this-now onboarding. This is the single canonical shape landing pages and naapp sites quote verbatim.</p>
        </div>
        <p class="prose-intro"><code>aw init</code> creates the account, workspace, and first team; <code>aw team add</code> materializes starter agents from the <code>aweb.team</code> blueprint over a public read (no Library plugin on aw 1.30+); then you run each agent <strong>interactively in its home</strong> with its runtime.</p>
        <div class="cmd-panel">
          <p class="cmd-label">Install the aw CLI, create your account + first team, then add starter agents from aweb.team</p>
          <div class="cmd-list"><div class="cmd"><pre># Install the aw CLI, create your account + first team
npm install -g @awebai/aw
aw init

# Add starter agents from the aweb.team blueprint
aw team add alice@aweb.team/developer=claude-code
aw team add bob@aweb.team/reviewer=claude-code</pre>{copy}</div></div>
        </div>
        <p class="prose-outro">Then run an agent. <strong>Two runtimes work — Claude Code or pi.</strong> Materialize the agent for the runtime you will run (<code>=claude-code</code> or <code>=pi</code>), then launch it directly in the agent home.</p>
        <p class="prose-outro"><strong>Claude Code</strong> — install the channel plugin once, inside Claude Code:</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>/plugin marketplace add awebai/claude-plugins
/plugin install aweb-channel@awebai-marketplace</pre>{copy}</div></div>
        </div>
        <p class="prose-outro">Then launch it in the agent home:</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>cd agents/instances/alice
claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace</pre>{copy}</div></div>
        </div>
        <p class="prose-outro"><strong>pi</strong> — install the extension once, then launch it in the agent home:</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>pi install npm:@awebai/pi@latest
cd agents/instances/alice
pi</pre>{copy}</div></div>
        </div>
        <p class="prose-outro"><strong>Add an agent to an existing hosted team</strong> with a team API key (no dashboard session; the key is the whole credential):</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>AWEB_API_KEY=&lt;key&gt; AWEB_URL=&lt;url&gt; aw team add alice@aweb.team/developer --runtime claude-code</pre>{copy}</div></div>
        </div>
        <p class="prose-outro">The blueprint is always <code>aweb.team</code>; override it with <code>--blueprint</code> (or <code>AWEB_BLUEPRINT</code>) and the catalog provider with <code>--library-url</code> (or <code>AWEB_LIBRARY_URL</code>).</p>
        <p class="prose-outro"><strong>Optional evolution loop:</strong> install the library plugin only when you want the authenticated shelf surface — private copies, proposals, approvals, and updates from source:</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>aw plugin install {origin}/.well-known/aweb-app.json</pre>{copy}</div></div>
        </div>
        <p class="prose-outro">Then copy a blueprint profile onto your team's shelf and evolve it before binding:</p>
        <div class="cmd-panel">
          <div class="cmd-list"><div class="cmd"><pre>aw library import-to-shelf \\
  --source_blueprint_ref aweb.team \\
  --source_blueprint_version 0.1.0 \\
  --profile_ref developer</pre>{copy}</div></div>
        </div>
        <p class="prose-outro">The <code>aw library</code> verbs are the authenticated shelf surface, not the starting path. <code>aw library shelf</code> shows your working set and which profiles have upstream updates. Agents read the whole surface at <a href="/llms.txt">llms.txt</a>; the dispatcher reads the <a href="/aweb-app.json">canonical manifest</a>.</p>
      </div>
    </section>

{_ENGINEERS_SECTION}

    <section class="section">
      <div class="wrap" style="text-align:center">
        <p style="font-size:var(--step-2);font-weight:650;letter-spacing:-0.02em;max-width:24ch;margin:0 auto var(--s4)">Start from a proven profile, evolve it your way.</p>
        <div class="cta-row" style="justify-content:center">
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

The minimal do-this-now onboarding. This is the single canonical shape landing
pages and naapp sites quote verbatim. `aw init` creates the account, workspace,
and first team; `aw team add` materializes starter agents from the `aweb.team`
blueprint over a public read (no Library plugin on aw 1.30+); then you run each
agent **interactively in its home** with its runtime.

```bash
# Install the aw CLI, create your account + first team
npm install -g @awebai/aw
aw init

# Add starter agents from the aweb.team blueprint
aw team add alice@aweb.team/developer=claude-code
aw team add bob@aweb.team/reviewer=claude-code
```

Then run an agent. **Two runtimes work — Claude Code or pi.** Materialize the
agent for the runtime you will run (`=claude-code` or `=pi`), then launch it
directly in the agent home.

**Claude Code** — install the channel plugin once, inside Claude Code:

```
/plugin marketplace add awebai/claude-plugins
/plugin install aweb-channel@awebai-marketplace
```

then launch it in the agent home:

```bash
cd agents/instances/alice
claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
```

**pi** — install the extension once, then launch it in the agent home:

```bash
pi install npm:@awebai/pi@latest
cd agents/instances/alice
pi
```

Add an agent to an existing hosted team with a team API key (no dashboard
session; the key is the whole credential):

```bash
AWEB_API_KEY=<key> AWEB_URL=<url> aw team add alice@aweb.team/developer --runtime claude-code
```

The blueprint is always `aweb.team`; override it with `--blueprint` (or
`AWEB_BLUEPRINT`) and the catalog provider with `--library-url` (or
`AWEB_LIBRARY_URL`).

The authenticated shelf/evolution loop is opt-in. Install the library plugin only
when you want private shelf copies, proposals, approvals, or updates from source:
aw plugin install {origin}/.well-known/aweb-app.json
aw library import-to-shelf --source_blueprint_ref aweb.team --source_blueprint_version 0.1.0 --profile_ref developer

A blueprint's runtime_hints and runtime_assumptions are advisory metadata you read
to choose the runtime; they are not auto-applied.


## How to call it

The start path is core aw: aw init, aw team add NAME@aweb.team/PROFILE=RUNTIME,
then cd agents/instances/NAME and launch Claude Code or pi directly. The aw library plugin verbs are the authenticated shelf surface for teams that
want to evolve profiles after onboarding (e.g. aw library import-to-shelf,
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

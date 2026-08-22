from __future__ import annotations

import os
import re
from html import escape
from pathlib import Path
from typing import Any

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
    NavLink("Blueprints", "/blueprints"),
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
            NavLink("Blueprints", "/blueprints"),
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
<figure class="model-fig" role="img" aria-label="Flow: you create a team from the public Catalog — its agents run a catalog profile; you adopt each agent onto your team's private Shelf; then the agents propose improvements, your team reviews and approves to mint a new version on the Shelf, and refresh applies it — an improvement loop your team governs.">
  <svg class="mf-desktop" viewBox="0 0 760 205" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <defs>
      <marker id="mfd" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="currentColor"/></marker>
      <marker id="mfda" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" style="fill:var(--accent)"/></marker>
    </defs>
    <rect x="8" y="16" width="212" height="66" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <rect x="274" y="16" width="212" height="66" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <rect x="540" y="16" width="212" height="66" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <text x="114" y="45" text-anchor="middle" font-size="17" font-weight="600" fill="currentColor">Catalog</text>
    <text x="114" y="65" text-anchor="middle" font-size="12.5" style="fill:var(--muted)">Public blueprints</text>
    <text x="380" y="45" text-anchor="middle" font-size="17" font-weight="600" fill="currentColor">Agent</text>
    <text x="380" y="65" text-anchor="middle" font-size="12.5" style="fill:var(--muted)">Runs your team's profile</text>
    <text x="646" y="45" text-anchor="middle" font-size="17" font-weight="600" fill="currentColor">Shelf</text>
    <text x="646" y="65" text-anchor="middle" font-size="12.5" style="fill:var(--muted)">Your team's private copies</text>
    <path d="M222,49 H270" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfd)"/>
    <path d="M488,49 H536" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfd)"/>
    <text x="246" y="39" text-anchor="middle" font-size="12" style="fill:var(--muted)">create</text>
    <text x="512" y="39" text-anchor="middle" font-size="12" style="fill:var(--muted)">adopt</text>
    <path d="M646,82 V150 H380 V85" fill="none" style="stroke:var(--accent)" stroke-width="1.5" marker-end="url(#mfda)"/>
    <text x="513" y="170" text-anchor="middle" font-size="12" font-weight="600" style="fill:var(--accent)">propose &#183; approve &#183; refresh</text>
  </svg>
  <svg class="mf-mobile" viewBox="0 0 360 430" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <defs>
      <marker id="mfm" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="currentColor"/></marker>
      <marker id="mfma" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" style="fill:var(--accent)"/></marker>
    </defs>
    <rect x="132" y="12" width="216" height="60" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <rect x="132" y="176" width="216" height="60" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <rect x="132" y="340" width="216" height="60" rx="11" style="fill:var(--surface);stroke:var(--line)"/>
    <text x="240" y="38" text-anchor="middle" font-size="16" font-weight="600" fill="currentColor">Catalog</text>
    <text x="240" y="57" text-anchor="middle" font-size="12" style="fill:var(--muted)">Public blueprints</text>
    <text x="240" y="202" text-anchor="middle" font-size="16" font-weight="600" fill="currentColor">Agent</text>
    <text x="240" y="221" text-anchor="middle" font-size="12" style="fill:var(--muted)">Runs your team's profile</text>
    <text x="240" y="366" text-anchor="middle" font-size="16" font-weight="600" fill="currentColor">Shelf</text>
    <text x="240" y="385" text-anchor="middle" font-size="12" style="fill:var(--muted)">Your team's private copies</text>
    <path d="M240,72 V174" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfm)"/>
    <path d="M240,236 V338" stroke="currentColor" stroke-width="1.5" marker-end="url(#mfm)"/>
    <text x="252" y="128" font-size="12" style="fill:var(--muted)">create</text>
    <text x="252" y="292" font-size="12" style="fill:var(--muted)">adopt</text>
    <path d="M132,370 H66 V206 H128" fill="none" style="stroke:var(--accent)" stroke-width="1.5" marker-end="url(#mfma)"/>
    <circle cx="66" cy="292" r="3.4" fill="none" style="stroke:var(--accent)" stroke-width="1.4"/>
    <path d="M59,303 q7,-9 14,0" fill="none" style="stroke:var(--accent)" stroke-width="1.4"/>
    <text x="52" y="288" text-anchor="end" font-size="11" font-weight="600" style="fill:var(--accent)">propose ·</text>
    <text x="52" y="304" text-anchor="end" font-size="11" font-weight="600" style="fill:var(--accent)">approve ·</text>
    <text x="52" y="320" text-anchor="end" font-size="11" font-weight="600" style="fill:var(--accent)">refresh</text>
  </svg>
  <figcaption>Create from the catalog, adopt onto your shelf, improve under review.</figcaption>
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
            <p class="why-answer">Every profile is versioned by digest and every change is signed with your team's <a href="https://awid.ai" class="brand-word">awid</a> identity — so what you start from and evolve is reproducible and trusted.</p>
          </div>
          <div>
            <p class="kicker" style="color:var(--faint)">What library gives you</p>
            <ul class="why-points">
              <li><strong>Proven profiles to start from</strong><span>A first-party set of high-quality profiles — coordinator, developer, reviewer, and more — ready to build a team from.</span></li>
              <li><strong>Build and share your own</strong><span>Author a profile and publish it into the catalog; any team can start from it and build on it.</span></li>
              <li><strong>Start shared, evolve private</strong><span>Start from public profiles, then adopt your agents onto your team's private shelf and evolve there, under review.</span></li>
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
          .whatis-grid { list-style: none; margin: var(--s5) 0 0; padding: 0; display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--s3); }
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


def _catalog_teaser(blueprints: Any) -> str:
    """Presents the first-party blueprint(s) the getting-started builds from — each
    one's name, real summary, roles at a glance, and a link into its page — rendered
    from the live catalog (catalog_view). Today there is one blueprint, so this reads
    as "here is the team you are adopting"; it grows naturally if the catalog does.
    Renders nothing when the catalog is empty."""
    cards = []
    for bp in list(blueprints or ())[:6]:
        ref = bp.get("blueprint_ref")
        if not ref:
            continue
        name = bp.get("name") or ref
        summary = bp.get("summary") or bp.get("description") or ""
        profiles = bp.get("profiles") or bp.get("roster") or []
        roles = [
            str(p.get("profile_ref") or p.get("name") or "")
            for p in profiles
            if isinstance(p, dict)
        ]
        roles = [r for r in roles if r]
        roles_html = ""
        if roles:
            roles_html = (
                '            <p style="margin-top:var(--s3);font:500 var(--step--1)/1.7 '
                'var(--font-mono);color:var(--muted)">'
                + " &middot; ".join(escape(r) for r in roles)
                + "</p>\n"
            )
        cards.append(
            f'          <a class="card" href="/blueprints/{escape(str(ref), quote=True)}"'
            ' style="text-decoration:none;color:inherit;display:block">\n'
            f"            <h3>{escape(str(name))}</h3>\n"
            f"            <p>{escape(str(summary))}</p>\n"
            f"{roles_html}"
            '            <p style="margin-top:var(--s3);font:600 var(--step--1)/1 var(--font-mono);'
            f'color:var(--accent)">{escape(str(ref))} &rarr;</p>\n'
            "          </a>"
        )
    if not cards:
        return ""
    grid = "\n".join(cards)
    return f"""    <section class="section section--tint" id="catalog">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">The blueprint</p>
          <h2>The team you're adopting</h2>
          <p>The commands above build your team from a first-party blueprint — a versioned set of proven roles you own and evolve on your own shelf.</p>
        </div>
        <div class="card-grid card-grid--auto">
{grid}
        </div>
      </div>
    </section>"""


# The single getting-started: the minimum path from nothing to a shelf-based,
# self-improving team — this IS library's value, not a generic hub onboarding.
# Every panel is a byte-exact command a human runs; the agents' own action
# (proposing) is described in step 6, never shown as a copiable command, because
# an agent proposes autonomously with the team cert (and the propose CLI verb is
# not a runnable one-liner). This numbered-step section is the naapp invariant:
# one getting-started, zero to the app's core value, minimum steps.
_ACCENT_LINK = 'style="color:var(--accent);font-weight:550"'
_GET_STARTED_STEPS = (
    (
        "Install aw",
        "Installs the aw CLI globally — needs Node/npm, and tmux (aw uses it to run your agents).",
        "npm install -g @awebai/aw",
    ),
    (
        "Create your team",
        "Creates your hosted team and materializes its starter agents from the "
        f'<a href="/blueprints/aweb.team" {_ACCENT_LINK}>aweb.team</a> blueprint. Add as many '
        "<code>--agent NAME@aweb.team/PROFILE=RUNTIME</code> as you want roles — the example adds "
        f'<a href="/blueprints/aweb.team/profiles/developer" {_ACCENT_LINK}>developer</a> and '
        f'<a href="/blueprints/aweb.team/profiles/reviewer" {_ACCENT_LINK}>reviewer</a>.',
        "aw team admin create eng --username <you> "
        "--agent alice@aweb.team/developer=claude-code "
        "--agent bob@aweb.team/reviewer=pi",
    ),
    (
        "Start the team",
        "Launches all your team's agents in tmux, ready to work.",
        "aw team admin up",
    ),
    (
        "Install library for your team",
        "Installs library.aweb.ai as an app your team can use — required for the adopt step next, "
        "and how your team keeps its own evolving copies of its profiles.",
        "aw plugin install https://library.aweb.ai/.well-known/aweb-app.json",
    ),
    (
        "Adopt a profile onto your shelf",
        "Re-points alice onto your team's private shelf, so she follows your team's own version of "
        "her profile instead of the public catalog — this is what makes the profile yours to evolve. "
        "New in aw 1.32.3.",
        "aw team admin adopt alice",
    ),
    (
        "Approve what your agents propose",
        "As they work, your agents propose improvements they have learned — a scoped changeset signed "
        'with your team\'s <a href="https://awid.ai" class="brand-word">awid</a>. Your team reviews and '
        "approves — your coordinator, or you; your policy — and library mints an immutable, versioned "
        "copy on your shelf.",
        "aw library approve --proposal_id <id>",
    ),
    (
        "Apply the new version",
        "<code>aw team admin refresh</code> re-materializes the agent from your team's newly minted version.",
        "aw team admin refresh alice",
    ),
    (
        "Reconcile your running agents",
        "<code>aw team admin up</code> again — it is idempotent — brings the running agents onto the "
        "refreshed home. Your team is now improving on its own shelf — proposing and approving "
        "under the policy you set.",
        "aw team admin up",
    ),
)

_GET_STARTED_STYLE = """<style>
          .gs-steps { list-style: none; margin: var(--s5) 0 0; padding: 0; display: grid; gap: var(--s5); }
          .gs-step { display: grid; grid-template-columns: auto 1fr; gap: var(--s3); align-items: start; }
          .gs-step__n { display: inline-grid; place-items: center; width: 32px; height: 32px; border-radius: 50%;
            background: var(--accent-soft); color: var(--accent); font: 700 0.95rem/1 var(--font-mono); }
          .gs-step__body { min-width: 0; }
          .gs-step__title { font: 650 var(--step-1)/1.2 var(--font-sans); margin: 0.25rem 0 0; letter-spacing: -0.01em; }
          .gs-step__what { color: var(--muted); margin: var(--s1) 0 var(--s2); max-width: 70ch; }
          .gs-step__what a { color: var(--accent); font-weight: 550; }
          .gs-step__what code { font: 500 0.88em/1.4 var(--font-mono); background: var(--surface-2);
            border: 1px solid var(--line); border-radius: 5px; padding: 0.08em 0.34em; }
          .gs-step .cmd { margin-top: var(--s2); }
          @media (max-width: 520px) { .gs-step { grid-template-columns: 1fr; gap: var(--s2); } }
        </style>"""


def _cmd(cmd: str, copy: str) -> str:
    """A single copiable command as one bordered box (no elevated cmd-panel
    wrapper — that is for labeled multi-command groups and double-boxes a lone
    command)."""
    return f'<div class="cmd"><pre>{escape(cmd)}</pre>{copy}</div>'


def _get_started_section(copy: str) -> str:
    steps = "\n".join(
        f"""        <li class="gs-step">
          <div class="gs-step__n">{i}</div>
          <div class="gs-step__body">
            <h3 class="gs-step__title">{escape(title)}</h3>
            <p class="gs-step__what">{what}</p>
            {_cmd(cmd, copy)}
          </div>
        </li>"""
        for i, (title, what, cmd) in enumerate(_GET_STARTED_STEPS, start=1)
    )
    return f"""    <section class="section" id="use">
      <div class="wrap">
        {_GET_STARTED_STYLE}
        <div class="section-head">
          <p class="kicker">Get started</p>
          <h2>Stand up a self-improving team</h2>
          <p>From nothing to a team of AI agents that improves its own profiles — on your private shelf, under your team's review. Each step is one command to copy and run.</p>
        </div>
        <ol class="gs-steps">
{steps}
        </ol>
      </div>
    </section>"""


def render_landing_page(*, public_origin: str, blueprints: Any = None) -> str:
    copy = naapp.COPY_BTN
    catalog_teaser = _catalog_teaser(blueprints)
    get_started = _get_started_section(copy)
    site = _site(
        public_origin=public_origin,
        title="library — agent profiles for AWID teams",
        description=(
            "library is the agent-first service for public blueprints, private team "
            "shelves, bindings, materialization, and learning for AWID teams."
        ),
    )
    body = f"""    <style>
      /* The chrome header is sticky (~68px); offset in-page anchor jumps like the
         hero's Get started -> #use so a section's heading is not hidden under it. */
      html {{ scroll-padding-top: 5.5rem; }}
    </style>
    <section class="hero-center">
      <div class="wrap">
        <p class="kicker">Native Agentic App · library.aweb.ai</p>
        <h1>Where teams of AI agents choose, keep and improve the profiles they run.</h1>
        {_MODEL_DIAGRAM}
        <div class="cta-row">
          <a class="btn primary btn--lg" href="#use">Get started</a>
          <a class="btn secondary btn--lg" href="/llms.txt">Read llms.txt</a>
        </div>
        <p style="margin-top:var(--s3);font-size:var(--step-0);color:var(--muted)">Open source, MIT-licensed — <a href="https://github.com/awebai/library" style="color:var(--accent);font-weight:550">github.com/awebai/library</a></p>
      </div>
    </section>

{get_started}

{catalog_teaser}

{_WHY_SECTION}

{_WHATIS_SECTION}

    <section class="section section--tint" id="model">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">The model</p>
          <h2>A catalog, a shelf, and an approval loop</h2>
          <p>The public catalog holds first-party blueprints — today, aweb.team — that any team can start from. Your shelf is your team's private working set: you adopt profiles onto it, materialize them into runnable agent homes, and improve them under review.</p>
        </div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Profiles</h3><p>An agent's job description as a file: mission, instructions, the tools it may use, the actions that need a human's sign-off, and its skills. Versioned by content digest.</p></article>
          <article class="card"><h3>Public catalog</h3><p>The public, versioned catalog of first-party blueprints — today just <code>aweb.team</code>, a proven set of roles like coordinator, developer, and reviewer any team can start from. Any team can publish into it.</p></article>
          <article class="card"><h3>Private shelf</h3><p>Your team's own copies — started from a blueprint or authored fresh — the working set you edit and own.</p></article>
          <article class="card"><h3>Materialize</h3><p>Creating or refreshing an agent turns a profile into its runnable home: a composed AGENTS.md, installed skills, and the full profile under <code>.aw/profile/</code>.</p></article>
          <article class="card"><h3>Proposals &amp; minting</h3><p>An agent proposes a new version from what it learned; your team reviews and approves, and library mints it — immutably versioned by digest, with the signer recorded.</p></article>
          <article class="card"><h3>Update from source</h3><p>Pull a newer blueprint version's improvements into the parts you have not edited — a per-part merge that never clobbers local work.</p></article>
        </div>
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


## Browse the catalog

Human-readable pages render the live catalog for a person choosing a role — the
same data the /v1/blueprints endpoints serve as JSON:

- Catalog index:  {origin}/blueprints
- A blueprint:    {origin}/blueprints/BLUEPRINT_REF
- A profile:      {origin}/blueprints/BLUEPRINT_REF/profiles/PROFILE_REF
- A skill:        {origin}/blueprints/BLUEPRINT_REF/profiles/PROFILE_REF/skills/SKILL_NAME

For example, the starter team: {origin}/blueprints/aweb.team,
{origin}/blueprints/aweb.team/profiles/developer, and
{origin}/blueprints/aweb.team/profiles/reviewer.


## Getting started

The minimal do-this-now onboarding. This is the single canonical shape landing
pages and naapp sites quote verbatim. `aw init` creates the account, workspace,
and first team; `aw team admin add` materializes starter agents from the `aweb.team`
blueprint over a public read (no Library plugin on aw 1.30+); then you run each
agent **interactively in its home** with its runtime.

```bash
# Install the aw CLI, create your account + first team
npm install -g @awebai/aw
aw init

# Add starter agents from the aweb.team blueprint
aw team admin add alice@aweb.team/developer=claude-code
aw team admin add bob@aweb.team/reviewer=claude-code
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
AWEB_API_KEY=<key> AWEB_URL=<url> aw team admin add alice@aweb.team/developer --runtime claude-code
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

The start path is core aw: aw init, aw team admin add NAME@aweb.team/PROFILE=RUNTIME,
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

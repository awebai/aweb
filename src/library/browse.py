"""Human-readable browse pages for the public catalog: the blueprint index, a
blueprint, a profile, and a skill. These render the live catalog view data
(assembled by the API layer) in the aweb Paper/Clay system via the shared naapp
chrome. All browse-specific classes carry the ``browse-`` prefix to stay clear
of the shared design-system classes (``.roster``/``.tag`` are already taken);
``.markdown-body`` is the shared wrapper the markdown renderer emits.

The rendered instructions and SKILL.md bodies arrive as already-sanitized HTML
and are inserted verbatim; every other value is a data field and is escaped.
"""

from __future__ import annotations

from html import escape
from typing import Any

import aweb_naapp as naapp

from library import surfaces

__all__ = [
    "render_catalog_page",
    "render_blueprint_page",
    "render_profile_page",
    "render_skill_page",
]


# The browse pages' styling, scoped to browse- classes and emitted in the page
# body like the landing's section styles. Reuses design-system tokens; adds no
# shared class. Kept as one constant so the four pages share one stylesheet.
_STYLE = """<style>
  .browse-hero { padding: var(--s7) 0 var(--s5); border-bottom: 1px solid var(--line); }
  .browse-hero .kicker { display: inline-block; margin-bottom: var(--s3); }
  .browse-title { font-size: var(--step-4); line-height: 1.05; margin: 0; letter-spacing: -0.02em; }
  .browse-title.is-id { font-family: var(--font-mono); font-weight: 600; letter-spacing: -0.01em; word-break: break-word; }
  .browse-summary { color: var(--muted); font-size: var(--step-1); max-width: 60ch; margin: var(--s3) 0 0; }
  .browse-meta { display: flex; flex-wrap: wrap; gap: 0.5rem 0.9rem; margin: var(--s4) 0 0;
    font: 500 var(--step--1)/1.4 var(--font-mono); color: var(--faint); align-items: center; }
  .browse-meta span { display: inline-flex; align-items: center; gap: 0.4rem; }
  .browse-meta span + span::before { content: "\\00b7"; margin-right: 0.9rem; color: var(--line-strong); }
  .browse-meta b { color: var(--muted); font-weight: 600; }

  .browse-section { padding: var(--s6) 0; border-top: 1px solid var(--line); }
  .browse-section:first-of-type { border-top: none; }
  .browse-section-head { max-width: 60ch; margin-bottom: var(--s4); }
  .browse-section-title { font-size: var(--step-2); margin: 0; }
  .browse-section-head p { color: var(--muted); margin: var(--s2) 0 0; max-width: 60ch; }

  .browse-tags { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: var(--s3) 0 0; padding: 0; list-style: none; }
  .browse-tag { font: 600 0.72rem/1 var(--font-mono); letter-spacing: 0.02em; padding: 0.4rem 0.55rem;
    border-radius: 999px; background: var(--surface-2); border: 1px solid var(--line); color: var(--muted); }

  .browse-blueprints { list-style: none; margin: 0; padding: 0; display: grid; gap: var(--s4); }
  .browse-blueprint-card { display: block; padding: var(--s4); background: var(--surface); border: 1px solid var(--line);
    border-radius: var(--radius); text-decoration: none; color: inherit; transition: border-color .15s, box-shadow .15s; }
  .browse-blueprint-card:hover { border-color: var(--line-strong); box-shadow: var(--shadow-lg); }
  .browse-blueprint-card__head { display: flex; align-items: baseline; justify-content: space-between; gap: var(--s3); flex-wrap: wrap; }
  .browse-blueprint-card__title { font: 600 var(--step-2)/1.1 var(--font-mono); letter-spacing: -0.01em; color: var(--ink); margin: 0; }
  .browse-blueprint-card__count { font: 600 var(--step--1)/1 var(--font-mono); color: var(--accent); white-space: nowrap; }
  .browse-blueprint-card__summary { color: var(--muted); margin: var(--s2) 0 0; max-width: 68ch; }
  .browse-blueprint-card__roster { margin: var(--s3) 0 0; color: var(--faint); font: 500 var(--step--1)/1.5 var(--font-mono); }
  .browse-blueprint-card__roster b { color: var(--muted); font-weight: 600; }

  .browse-table-scroll { overflow-x: auto; margin: var(--s4) 0 0; border: 1px solid var(--line); border-radius: var(--radius); }
  .browse-roster { width: 100%; border-collapse: collapse; min-width: 640px; background: var(--surface); }
  .browse-roster th { text-align: left; font: 600 0.7rem/1 var(--font-mono); text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--faint); padding: 0.9rem 1rem; border-bottom: 1px solid var(--line); background: var(--surface-2); }
  .browse-roster td { padding: 0.95rem 1rem; border-bottom: 1px solid var(--line); vertical-align: top; font-size: var(--step-0); }
  .browse-roster tr:last-child td { border-bottom: none; }
  .browse-roster tr:hover td { background: var(--bg-tint); }
  .browse-roster__name a { font: 600 var(--step-0)/1.2 var(--font-mono); color: var(--ink); text-decoration: none; }
  .browse-roster__name a:hover { color: var(--accent); }
  .browse-roster__mission { color: var(--muted); }
  .browse-roster__count { font: 500 var(--step-0)/1 var(--font-mono); color: var(--ink); white-space: nowrap; }
  .browse-roster__count .range { color: var(--faint); }
  .browse-roster__runtime { font: 500 var(--step--1)/1 var(--font-mono); color: var(--muted); white-space: nowrap; }

  .browse-profiles { list-style: none; margin: var(--s4) 0 0; padding: 0; display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--s3); }
  .browse-profile-card { display: block; padding: var(--s4); background: var(--surface); border: 1px solid var(--line);
    border-radius: var(--radius); text-decoration: none; color: inherit; transition: border-color .15s, box-shadow .15s; }
  .browse-profile-card:hover { border-color: var(--line-strong); box-shadow: var(--shadow-lg); }
  .browse-profile-card__title { font: 600 var(--step-1)/1.1 var(--font-mono); color: var(--ink); margin: 0; }
  .browse-profile-card__mission { color: var(--muted); font-size: var(--step--1); margin: var(--s2) 0 0; }
  .browse-profile-card__foot { margin: var(--s3) 0 0; font: 600 0.72rem/1 var(--font-mono); color: var(--accent); }

  .browse-specs { margin: var(--s4) 0 0; display: grid; grid-template-columns: 1fr 1fr; gap: var(--s4) var(--s6); }
  .browse-specs > div { border-top: 1px solid var(--line-strong); padding-top: var(--s3); }
  .browse-specs > div:first-child { border-top-color: var(--accent); }
  .browse-specs dt { font: 650 var(--step--1)/1 var(--font-mono); letter-spacing: 0.02em; color: var(--ink); }
  .browse-specs dd { margin: var(--s2) 0 0; color: var(--muted); font-size: var(--step-0); }
  .browse-specs dd ul { margin: 0; padding-left: 1.1rem; }
  .browse-specs dd li { margin: 0.15rem 0; }
  .browse-specs dd .empty { color: var(--faint); font-style: italic; }

  .browse-missions { list-style: none; margin: var(--s4) 0 0; padding: 0; display: grid; gap: var(--s2); }
  .browse-missions li { padding: var(--s3); background: var(--surface); border: 1px solid var(--line);
    border-left: 2px solid var(--accent); border-radius: var(--radius-sm); color: var(--muted); font-size: var(--step-0); }

  .browse-skills { list-style: none; margin: var(--s4) 0 0; padding: 0; display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--s3); }
  .browse-skill-card { display: block; padding: var(--s4); background: var(--surface); border: 1px solid var(--line);
    border-radius: var(--radius); text-decoration: none; color: inherit; transition: border-color .15s, box-shadow .15s; }
  .browse-skill-card:hover { border-color: var(--line-strong); box-shadow: var(--shadow-lg); }
  .browse-skill-card__name { font: 600 var(--step-0)/1.1 var(--font-mono); color: var(--ink); margin: 0; }
  .browse-skill-card__desc { color: var(--muted); font-size: var(--step--1); margin: var(--s2) 0 0; }
  .browse-resources { list-style: none; margin: var(--s4) 0 0; padding: 0; display: grid; gap: 0.4rem; }
  .browse-resources a { font: 500 var(--step-0)/1.4 var(--font-mono); color: var(--accent); text-decoration: none;
    display: inline-flex; gap: 0.5rem; align-items: baseline; }
  .browse-resources a:hover { text-decoration: underline; }

  .browse-frontmatter { margin: var(--s4) 0 0; display: grid; grid-template-columns: max-content 1fr; gap: 0.5rem var(--s3);
    padding: var(--s3) var(--s4); background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--radius); }
  .browse-frontmatter dt { font: 650 0.72rem/1.4 var(--font-mono); text-transform: uppercase; letter-spacing: 0.04em; color: var(--faint); }
  .browse-frontmatter dd { margin: 0; font-size: var(--step--1); color: var(--muted); }

  .markdown-body { max-width: 74ch; margin: 0; color: var(--ink); font-size: var(--step-0); line-height: 1.7; }
  .markdown-body > :first-child { margin-top: 0; }
  .markdown-body h1 { font-size: var(--step-3); margin: var(--s5) 0 var(--s2); }
  .markdown-body h2 { font-size: var(--step-2); margin: var(--s5) 0 var(--s2); padding-top: var(--s3); border-top: 1px solid var(--line); }
  .markdown-body h3 { font: 600 var(--step-1)/1.2 var(--font-mono); margin: var(--s4) 0 var(--s2); letter-spacing: -0.01em; }
  .markdown-body h4 { font: 650 var(--step-0)/1.2 var(--font-mono); margin: var(--s4) 0 var(--s1); color: var(--muted); }
  .markdown-body p { margin: var(--s2) 0; }
  .markdown-body ul, .markdown-body ol { margin: var(--s2) 0; padding-left: 1.4rem; }
  .markdown-body li { margin: 0.3rem 0; }
  .markdown-body li::marker { color: var(--faint); }
  .markdown-body a { color: var(--accent); text-decoration: none; border-bottom: 1px solid var(--accent-soft); }
  .markdown-body a:hover { border-bottom-color: var(--accent); }
  .markdown-body strong { font-weight: 650; }
  .markdown-body code { font: 500 0.88em/1.4 var(--font-mono); background: var(--surface-2);
    border: 1px solid var(--line); border-radius: 5px; padding: 0.08em 0.34em; }
  .markdown-body pre { margin: var(--s3) 0; padding: var(--s3); background: var(--surface); border: 1px solid var(--line);
    border-radius: var(--radius); overflow-x: auto; }
  .markdown-body pre code { background: none; border: none; padding: 0; font-size: 0.85em; line-height: 1.6; color: var(--ink); }
  .markdown-body blockquote { margin: var(--s3) 0; padding: 0.2rem 0 0.2rem var(--s3); border-left: 2px solid var(--accent); color: var(--muted); }
  .markdown-body hr { border: none; border-top: 1px solid var(--line); margin: var(--s5) 0; }
  .markdown-body table { border-collapse: collapse; margin: var(--s3) 0; font-size: var(--step--1); display: block; overflow-x: auto; }
  .markdown-body th, .markdown-body td { border: 1px solid var(--line); padding: 0.5rem 0.7rem; text-align: left; }
  .markdown-body th { background: var(--surface-2); font-family: var(--font-mono); }

  .browse-crumbs { font: 500 var(--step--1)/1 var(--font-mono); color: var(--faint); margin: 0 0 var(--s3); }
  .browse-crumbs a { color: var(--muted); text-decoration: none; }
  .browse-crumbs a:hover { color: var(--accent); }
  .browse-crumbs .sep { margin: 0 0.5rem; color: var(--line-strong); }

  @media (max-width: 720px) { .browse-specs { grid-template-columns: 1fr; } }
</style>"""


# --------------------------------------------------------------------- helpers
def _e(value: Any) -> str:
    return escape("" if value is None else str(value))


def _crumbs(*parts: tuple[str, str | None]) -> str:
    links = [
        f'<a href="{escape(href, quote=True)}">{_e(label)}</a>' if href else _e(label)
        for label, href in parts
    ]
    return '<p class="browse-crumbs">' + '<span class="sep">/</span>'.join(links) + "</p>"


def _tags(tags: list[str]) -> str:
    if not tags:
        return ""
    items = "".join(f'<li class="browse-tag">{_e(t)}</li>' for t in tags)
    return f'<ul class="browse-tags">{items}</ul>'


def _list_items(values: list[str]) -> str:
    if not values:
        return '<span class="empty">none</span>'
    return "<ul>" + "".join(f"<li>{_e(v)}</li>" for v in values) + "</ul>"


def _memory_policy_html(policy: Any) -> str:
    if policy is None or policy == "" or policy == []:
        return '<span class="empty">not specified</span>'
    if isinstance(policy, dict):
        return "<ul>" + "".join(
            f"<li><b>{_e(k)}:</b> {_e(v)}</li>" for k, v in policy.items()
        ) + "</ul>"
    if isinstance(policy, list):
        return _list_items([str(v) for v in policy])
    return _e(policy)


def _profile_href(blueprint_ref: str, profile_ref: str) -> str:
    return f"/blueprints/{blueprint_ref}/profiles/{profile_ref}"


# ----------------------------------------------------------------------- pages
def render_catalog_page(*, public_origin: str, blueprints: list[dict[str, Any]]) -> str:
    site = surfaces._site(
        public_origin=public_origin,
        title="library — blueprint catalog",
        description="Browse the public catalog of agent-team blueprints any AWID team can adopt.",
    )
    cards = []
    for bp in blueprints:
        ref = bp["blueprint_ref"]
        name = bp.get("name") or ref
        summary = bp.get("summary") or bp.get("description") or ""
        count = bp.get("profile_count")
        roster = bp.get("roster") or bp.get("profiles") or []
        role_names = ", ".join(r.get("profile_ref") or r.get("name") or "" for r in roster)
        count_html = (
            f'<span class="browse-blueprint-card__count">{count} profiles</span>'
            if count is not None
            else ""
        )
        roster_html = (
            f'<p class="browse-blueprint-card__roster"><b>Roles:</b> {_e(role_names)}</p>'
            if role_names
            else ""
        )
        cards.append(
            f"""      <a class="browse-blueprint-card" href="/blueprints/{_e(ref)}">
        <div class="browse-blueprint-card__head">
          <h2 class="browse-blueprint-card__title">{_e(name)}</h2>
          {count_html}
        </div>
        <p class="browse-blueprint-card__summary">{_e(summary)}</p>
        {roster_html}
      </a>"""
        )
    listing = (
        f'<ul class="browse-blueprints">\n{chr(10).join(cards)}\n        </ul>'
        if cards
        else '<p class="browse-summary">No blueprints published yet.</p>'
    )
    body = f"""    <section class="browse-hero">
      <div class="wrap">
        <p class="kicker">Catalog</p>
        <h1 class="browse-title">Blueprints</h1>
        <p class="browse-summary">Proven, versioned collections of agent profiles any <span class="brand-word">awid</span> team can adopt. Each blueprint is a team you can stand up in minutes and then evolve on your own shelf.</p>
      </div>
    </section>
    <section class="browse-section">
      <div class="wrap">
        {listing}
      </div>
    </section>"""
    return naapp.page(site, _STYLE + "\n" + body)


def render_blueprint_page(*, public_origin: str, blueprint: dict[str, Any]) -> str:
    ref = blueprint["blueprint_ref"]
    name = blueprint.get("name") or ref
    summary = blueprint.get("summary") or blueprint.get("description") or ""
    roster = blueprint.get("roster") or blueprint.get("profiles") or []
    missions = blueprint.get("first_mission_examples") or []
    tags = blueprint.get("tags") or []
    site = surfaces._site(
        public_origin=public_origin,
        title=f"{name} — blueprint",
        description=summary or f"The {name} blueprint and the roles it ships.",
    )

    rows = []
    for r in roster:
        pref = r.get("profile_ref") or r.get("name") or ""
        default = r.get("default_count")
        lo, hi = r.get("count_min"), r.get("count_max")
        if default is None:
            count_html = '<span class="range">&mdash;</span>'
        elif lo is not None and hi is not None and not (lo == hi == default):
            count_html = f'{default} <span class="range">({lo}&ndash;{hi})</span>'
        else:
            count_html = f"{default}"
        runtimes = r.get("runtime_hints") or []
        rows.append(
            f"""            <tr>
              <td class="browse-roster__name"><a href="{_profile_href(_e(ref), _e(pref))}">{_e(pref)}</a></td>
              <td class="browse-roster__mission">{_e(r.get('mission') or '')}</td>
              <td class="browse-roster__count">{count_html}</td>
              <td class="browse-roster__runtime">{_e(' · '.join(runtimes)) or '&mdash;'}</td>
            </tr>"""
        )
    roster_section = (
        f"""    <section class="browse-section">
      <div class="wrap">
        <div class="browse-section-head">
          <h2 class="browse-section-title">Roster</h2>
          <p>The roles this blueprint ships, with the default number of each and the range you can scale to.</p>
        </div>
        <div class="browse-table-scroll">
          <table class="browse-roster">
            <thead><tr><th>Role</th><th>Mission</th><th>Default</th><th>Runtime</th></tr></thead>
            <tbody>
{chr(10).join(rows)}
            </tbody>
          </table>
        </div>
      </div>
    </section>"""
        if rows
        else ""
    )

    cards = []
    for r in roster:
        pref = r.get("profile_ref") or r.get("name") or ""
        cards.append(
            f"""          <a class="browse-profile-card" href="{_profile_href(_e(ref), _e(pref))}">
            <h3 class="browse-profile-card__title">{_e(pref)}</h3>
            <p class="browse-profile-card__mission">{_e(r.get('mission') or '')}</p>
            <p class="browse-profile-card__foot">View profile &rarr;</p>
          </a>"""
        )
    profiles_section = (
        f"""    <section class="browse-section">
      <div class="wrap">
        <div class="browse-section-head">
          <h2 class="browse-section-title">Profiles</h2>
          <p>Open a role to see its full mission, how it works, and its skills.</p>
        </div>
        <div class="browse-profiles">
{chr(10).join(cards)}
        </div>
      </div>
    </section>"""
        if cards
        else ""
    )

    missions_section = (
        f"""    <section class="browse-section">
      <div class="wrap">
        <div class="browse-section-head">
          <h2 class="browse-section-title">First missions</h2>
          <p>Concrete ways teams start with this blueprint.</p>
        </div>
        <ul class="browse-missions">{''.join(f'<li>{_e(m)}</li>' for m in missions)}</ul>
      </div>
    </section>"""
        if missions
        else ""
    )

    meta_bits = [f"<span><b>version</b> {_e(blueprint.get('version') or '')}</span>"]
    if blueprint.get("digest"):
        meta_bits.append(f"<span><b>digest</b> {_e(blueprint['digest'])}</span>")
    if roster:
        meta_bits.append(f"<span><b>{len(roster)}</b> profiles</span>")

    body = f"""    <section class="browse-hero">
      <div class="wrap">
        {_crumbs(("Blueprints", "/blueprints"), (name, None))}
        <p class="kicker">Blueprint</p>
        <h1 class="browse-title is-id">{_e(name)}</h1>
        <p class="browse-summary">{_e(summary)}</p>
        <div class="browse-meta">{''.join(meta_bits)}</div>
        {_tags(tags)}
      </div>
    </section>
{roster_section}
{profiles_section}
{missions_section}"""
    return naapp.page(site, _STYLE + "\n" + body)


def render_profile_page(*, public_origin: str, profile: dict[str, Any]) -> str:
    ref = profile["blueprint_ref"]
    pref = profile["profile_ref"]
    mission = profile.get("mission") or ""
    site = surfaces._site(
        public_origin=public_origin,
        title=f"{pref} — {ref} profile",
        description=mission or f"The {pref} role in the {ref} blueprint.",
    )

    specs = f"""        <dl class="browse-specs">
          <div><dt>accepted work</dt><dd>{_list_items(profile.get('accepted_work') or [])}</dd></div>
          <div><dt>runtime assumptions</dt><dd>{_list_items(profile.get('runtime_assumptions') or [])}</dd></div>
          <div><dt>memory policy</dt><dd>{_memory_policy_html(profile.get('memory_policy'))}</dd></div>
          <div><dt>needs approval</dt><dd>{_list_items(profile.get('approval_required') or [])}</dd></div>
        </dl>"""

    skills = profile.get("skills") or []
    skill_cards = "".join(
        f"""          <a class="browse-skill-card" href="{escape(s.get('href') or _profile_href(ref, pref) + '/skills/' + (s.get('name') or ''), quote=True)}">
            <h3 class="browse-skill-card__name">{_e(s.get('name') or '')}</h3>
            <p class="browse-skill-card__desc">{_e(s.get('description') or '')}</p>
          </a>"""
        for s in skills
    )
    skills_section = (
        f"""    <section class="browse-section">
      <div class="wrap">
        <div class="browse-section-head">
          <h2 class="browse-section-title">Skills</h2>
          <p>Procedures this role loads on demand.</p>
        </div>
        <ul class="browse-skills">{skill_cards}</ul>
      </div>
    </section>"""
        if skills
        else ""
    )

    artifacts = profile.get("artifacts") or []
    artifact_links = "".join(
        f'<li><a href="{escape(a.get("href") or "", quote=True)}">{_e(a.get("name") or "")}</a></li>'
        for a in artifacts
    )
    artifacts_section = (
        f"""    <section class="browse-section">
      <div class="wrap">
        <div class="browse-section-head">
          <h2 class="browse-section-title">Artifacts</h2>
          <p>Files this profile ships alongside its instructions.</p>
        </div>
        <ul class="browse-resources">{artifact_links}</ul>
      </div>
    </section>"""
        if artifacts
        else ""
    )

    instructions_html = profile.get("instructions_html") or ""
    instructions_section = (
        f"""    <section class="browse-section">
      <div class="wrap">
        <div class="browse-section-head">
          <h2 class="browse-section-title">Instructions</h2>
          <p>The full role definition materialized into the agent's home.</p>
        </div>
        <div class="markdown-body">
{instructions_html}
        </div>
      </div>
    </section>"""
        if instructions_html
        else ""
    )

    meta_bits = [f"<span><b>version</b> {_e(profile.get('version') or '')}</span>"]
    if profile.get("digest"):
        meta_bits.append(f"<span><b>digest</b> {_e(profile['digest'])}</span>")
    runtime_hints = profile.get("runtime_hints") or []
    if runtime_hints:
        meta_bits.append(f"<span><b>runtime</b> {_e(' · '.join(runtime_hints))}</span>")

    body = f"""    <section class="browse-hero">
      <div class="wrap">
        {_crumbs(("Blueprints", "/blueprints"), (ref, f"/blueprints/{ref}"), (pref, None))}
        <p class="kicker">Profile &middot; in {_e(ref)}</p>
        <h1 class="browse-title is-id">{_e(pref)}</h1>
        <p class="browse-summary">{_e(mission)}</p>
        <div class="browse-meta">{''.join(meta_bits)}</div>
      </div>
    </section>
    <section class="browse-section">
      <div class="wrap">
        <div class="browse-section-head">
          <h2 class="browse-section-title">How it works</h2>
          <p>What this role accepts, what it assumes about its runtime, how it treats memory, and the actions that need a human's sign-off.</p>
        </div>
{specs}
      </div>
    </section>
{skills_section}
{artifacts_section}
{instructions_section}"""
    return naapp.page(site, _STYLE + "\n" + body)


def render_skill_page(*, public_origin: str, skill: dict[str, Any]) -> str:
    ref = skill["blueprint_ref"]
    pref = skill["profile_ref"]
    name = skill["skill_name"]
    frontmatter = skill.get("frontmatter") or {}
    description = frontmatter.get("description") or ""
    body_html = skill.get("body_html") or ""
    site = surfaces._site(
        public_origin=public_origin,
        title=f"{name} — {pref} skill",
        description=description or f"The {name} skill of the {pref} role.",
    )

    # Frontmatter: show only keys beyond name/description (the hero already
    # renders those); render values plainly so a nested mapping stays readable.
    extra = {
        k: v for k, v in frontmatter.items() if k not in ("name", "description")
    }
    fm_rows = "".join(
        f"<dt>{_e(k)}</dt><dd>{_e(v if not isinstance(v, dict) else ' · '.join(f'{ik}: {iv}' for ik, iv in v.items()))}</dd>"
        for k, v in extra.items()
    )
    fm_html = f'<dl class="browse-frontmatter">{fm_rows}</dl>' if fm_rows else ""

    body = f"""    <section class="browse-hero">
      <div class="wrap">
        {_crumbs(("Blueprints", "/blueprints"), (ref, f"/blueprints/{ref}"), (pref, _profile_href(ref, pref)), (name, None))}
        <p class="kicker">Skill &middot; {_e(pref)} &middot; {_e(ref)}</p>
        <h1 class="browse-title is-id">{_e(name)}</h1>
        <p class="browse-summary">{_e(description)}</p>
        {fm_html}
      </div>
    </section>
    <section class="browse-section">
      <div class="wrap">
        <div class="markdown-body">
{body_html}
        </div>
      </div>
    </section>"""
    return naapp.page(site, _STYLE + "\n" + body)

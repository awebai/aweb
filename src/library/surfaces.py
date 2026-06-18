from __future__ import annotations

import os
import re
from html import escape
from pathlib import Path

_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_DIR = _REPO_ROOT / "skills"
_CONTAINER_SKILLS_DIR = Path("/app/skills")


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
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="library is the agent-first service for profile packs, agent profiles, bindings, and learning for AWID teams.">
  <title>library — agent profiles for AWID teams</title>
  <style>
    :root {{ color-scheme: light; --bg: #fffaf0; --panel: #ffffff; --ink: #17201a; --muted: #5f685f; --line: #ded6c4; --accent: #246b49; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.6; }}
    a {{ color: var(--accent); text-underline-offset: .18em; }}
    header, main, footer {{ max-width: 72rem; margin: 0 auto; padding: 1.25rem; }}
    nav {{ display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }}
    .brand {{ color: var(--ink); font-weight: 800; text-decoration: none; }}
    .links {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
    .hero {{ padding: 5rem 0 3rem; }}
    .eyebrow {{ color: var(--accent); font-weight: 800; letter-spacing: .08em; text-transform: uppercase; font-size: .78rem; }}
    h1 {{ font-size: clamp(2.6rem, 7vw, 5.8rem); line-height: .95; letter-spacing: -.06em; margin: .25rem 0 1rem; max-width: 58rem; }}
    .lede {{ color: var(--muted); font-size: clamp(1.15rem, 2.4vw, 1.6rem); max-width: 54rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); gap: 1rem; margin: 2rem 0; }}
    .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 1rem; padding: 1.1rem; }}
    .card h2 {{ margin-top: 0; }}
    footer {{ color: var(--muted); border-top: 1px solid var(--line); font-size: .92rem; }}
  </style>
</head>
<body>
  <header>
    <nav aria-label="Main navigation">
      <a class="brand" href="/">library</a>
      <div class="links">
        <a href="/llms.txt">llms.txt</a>
        <a href="/skills/">agent skills</a>
        <a href="https://aweb.ai">aweb.ai hub</a>
        <a href="https://awid.ai">AWID</a>
      </div>
    </nav>
  </header>
  <main>
    <section class="hero">
      <p class="eyebrow">Agent profiles for AWID teams</p>
      <h1>library is where teams learn how their agents should work.</h1>
      <p class="lede">Reusable profile packs, individual agent profiles with versions and digests, agent-profile bindings, materialization payloads for local and custodial runtimes, and profile learning. Agents authenticate with an <a href="https://awid.ai">AWID team certificate</a>; there are no app accounts.</p>
    </section>
    <section class="grid" aria-label="What library does">
      <article class="card"><h2>Profile packs</h2><p>Public, first-party collections of agent profiles a team can discover and adopt.</p></article>
      <article class="card"><h2>Bindings</h2><p>The team decides which profile an agent identity runs as; library owns that binding, not the dashboard.</p></article>
      <article class="card"><h2>Materialization &amp; learning</h2><p>Profiles materialize into a local <code>.aw</code> home or a custodial runtime, and agents propose improvements back.</p></article>
    </section>
  </main>
  <footer>
    <p>library is an aweb anapp on the <a href="https://aweb.ai">aweb.ai</a> hub. <a href="https://awid.ai">AWID</a> is the identity authority. Origin: {origin}</p>
  </footer>
</body>
</html>"""


def llms_txt(*, public_origin: str) -> str:
    origin = public_origin.rstrip("/")
    return f"""# library — agent-first profiles for AWID teams

library is the app that owns agent profiles, profile packs, profile versions and
digests, agent-profile bindings, materialization payloads, and profile learning.
This is an aweb anapp: an agent-native app published by convention for the aweb.ai hub index.
Agents authenticate with an AWID team certificate using aw id request --team-auth.
AWID is the identity authority: https://awid.ai
Aweb anapp hub: https://aweb.ai
There are no app-local accounts, passwords, or OAuth sessions.

Origin:
- Production: {origin}
- Local development: http://127.0.0.1:8765

Public endpoints (no auth):
- GET / — human landing page
- GET /llms.txt — this agent-readable entrypoint
- GET /skills/ — skill index
- GET /aweb-app.json and GET /.well-known/aweb-app.json — app manifest for aw/gateway dispatch
- GET /v1/profile-packs — list first-party profile packs
- GET /v1/profile-packs/{{pack_id}} — profile pack detail
- GET /v1/profiles/{{profile_id}} — profile detail

Team-auth endpoints (AWID team certificate):
- POST /v1/profile-packs/import — import a local/git profile pack
- POST /v1/agents/{{agent_id}}/profile-binding — bind an agent identity to a profile
- GET /v1/agents/{{agent_id}}/profile-binding — read an agent's profile binding
- POST /v1/materialize — materialize a profile for a local or custodial runtime
- POST /v1/proposals — submit a learning proposal
- GET /v1/proposals — list the team's proposals
- POST /v1/proposals/{{proposal_id}}/approve — approve a proposal
- POST /v1/proposals/{{proposal_id}}/reject — reject a proposal

Important invariants:
- AWID is authority for team keys, certificates, and revocation.
- Every team-scoped read/write is keyed by the verified certificate team_id.
- Public catalog reads are unauthenticated; profiles do not grant app access.
- library owns its own binding, materialization, and proposal state. AC does not authorize library.

Status: scaffold (default-aaas.14.1). Team-scoped write routes are present and
cert-auth-gated but not yet implemented; the profile/pack model and real bodies arrive in later tasks.
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
        "library is an aweb anapp: an agent-native app on the aweb.ai hub.",
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

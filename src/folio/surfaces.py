from __future__ import annotations

import os
import re
from html import escape
from pathlib import Path

USER_CONTENT_ROBOTS_HEADER = "noindex, nofollow, noarchive"

_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_DIR = _REPO_ROOT / "skills"
_CONTAINER_SKILLS_DIR = Path("/app/skills")


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
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="folio is a private, agent-first document and presentation service for AWID teams.">
  <title>folio — agent-first documents and presentations</title>
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
    pre {{ overflow-x: auto; background: #122016; color: #eff9ef; border-radius: .8rem; padding: 1rem; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    footer {{ color: var(--muted); border-top: 1px solid var(--line); font-size: .92rem; }}
  </style>
</head>
<body>
  <header>
    <nav aria-label="Main navigation">
      <a class="brand" href="/">folio</a>
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
      <p class="eyebrow">Private capability links for human browser moments</p>
      <h1>folio is a private document and presentation service for AWID teams.</h1>
      <p class="lede">Agents authenticate with an <a href="https://awid.ai">AWID team certificate</a>, write append-only Markdown documents, brand them with a team theme, embed safe media, and mint no-login presentation links for humans.</p>
    </section>
    <section class="grid" aria-label="What folio does">
      <article class="card"><h2>Agent-first API</h2><p>No app accounts, passwords, or OAuth. Use <code>aw id request --team-auth</code>; the certificate is the login.</p></article>
      <article class="card"><h2>Presentation links</h2><p>Present links are opaque, revocable capability URLs. User content under <code>/present/</code> and <code>/assets/</code> is marked noindex.</p></article>
      <article class="card"><h2>Media and themes</h2><p>Safe raster images and Cloudflare Stream video render inside themed presentation pages without accepting team-supplied HTML or JavaScript.</p></article>
    </section>
    <section class="card" aria-label="Quick start">
      <h2>Quick start</h2>
      <pre><code>export FOLIO_ORIGIN={origin}
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw \
  --body '{{"slug":"pitch","title":"Pitch","body":"# Pitch\\n\\nInitial draft."}}'
aw id request POST "$FOLIO_ORIGIN/v1/present" --team-auth --raw \
  --body '{{"slug":"pitch","ttl_seconds":86400}}'</code></pre>
      <p>Agents can fetch <a href="/llms.txt">/llms.txt</a> and task-specific <a href="/skills/">skills</a> instead of browsing.</p>
    </section>
  </main>
  <footer>
    <p>folio is an aweb anapp on the <a href="https://aweb.ai">aweb.ai</a> hub. <a href="https://awid.ai">AWID</a> is the identity authority. Public docs are indexable; team documents, media assets, and present pages are not.</p>
  </footer>
</body>
</html>"""


def llms_txt(*, public_origin: str) -> str:
    origin = public_origin.rstrip("/")
    return f"""# folio — agent-first document and presentation service

folio is a private, agent-first document and presentation service for AWID teams.
This is an aweb anapp: an agent-native app published by convention for the aweb.ai hub index.
Agents authenticate with an AWID team certificate using aw id request --team-auth.
AWID is the identity authority: https://awid.ai
Aweb anapp hub: https://aweb.ai
There are no app-local accounts, passwords, OAuth sessions, public document listings, or user-content feeds.

Origin:
- Production: {origin}
- Local development: http://127.0.0.1:8765

Core commands use the aw-native signed request path:
```bash
export FOLIO_ORIGIN={origin}
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw --body '{{"slug":"pitch","title":"Pitch","body":"# Pitch"}}'
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw --body '{{"slug":"deck","title":"Deck","template":{{"name":"pitch","slots":{{"cover":{{"title":"Deck"}},"sections":[]}}}}}}'
aw id request POST "$FOLIO_ORIGIN/v1/documents/pitch/versions" --team-auth --raw --body-file pitch-v2.md
aw id request POST "$FOLIO_ORIGIN/v1/documents/deck/versions/template" --team-auth --raw --body '{{"name":"memo","slots":{{"cover":{{"title":"Deck v2"}},"sections":[]}}}}'
aw id request POST "$FOLIO_ORIGIN/v1/assets" --team-auth --raw --body-file image-upload.json
aw id request POST "$FOLIO_ORIGIN/v1/assets/video/direct-upload" --team-auth --raw --body '{{"content_type":"video/mp4","max_duration_seconds":600}}'
aw id request PUT "$FOLIO_ORIGIN/v1/theme" --team-auth --raw --body-file theme.json
aw id request POST "$FOLIO_ORIGIN/v1/present" --team-auth --raw --body '{{"slug":"pitch","ttl_seconds":86400}}'
aw id request POST "$FOLIO_ORIGIN/v1/present/<token>/revoke" --team-auth --raw
```

Declarative templates:
- Template slots are schema-validated and rendered to ordinary Markdown before storage; presentation falls back to the same themed Markdown renderer.
- pitch slots: cover, metrics, sections, ask
- memo slots: cover, sections
- metrics slots: cover, metrics
- cover fields: title (required), subtitle, eyebrow
- metrics item fields: label (required), value (required), caption
- sections item fields: heading (required), body
- ask fields: headline, body, items (array of strings)
- Create docs with JSON: {{"slug":"deck","title":"Deck","template":{{"name":"pitch","slots":{{"cover":{{"title":"Deck"}},"metrics":[{{"label":"Metric","value":"Value","caption":"Note"}}],"sections":[{{"heading":"Problem","body":"Markdown body"}}],"ask":{{"headline":"Ask","body":"Approve launch","items":["Ship"]}}}}}}}}
- Append template versions with POST /v1/documents/{{slug}}/versions/template and body: {{"name":"memo","slots":{{"cover":{{"title":"Update"}},"sections":[{{"heading":"Status","body":"Markdown body"}}]}}}}

Team-auth endpoints:
- POST /v1/documents — JSON {{slug,title,body}}
- GET /v1/documents — list team documents
- GET /v1/documents/{{slug}} — current version
- GET /v1/documents/{{slug}}/versions — version metadata
- POST /v1/documents/{{slug}}/versions — raw UTF-8 Markdown body
- POST /v1/documents/{{slug}}/versions/template — JSON built-in template version body
- POST /v1/assets — upload safe raster image bytes
- POST /v1/assets/video/direct-upload — create Cloudflare Stream direct upload
- GET /v1/assets/{{asset_id}} — poll team-scoped image/video asset metadata
- GET /v1/theme, PUT /v1/theme — team presentation theme
- POST /v1/present — mint read-only capability link
- POST /v1/present/{{token}}/revoke — revoke a team-owned link
- GET /v1/billing — current v1 caps and usage

Public endpoints:
- GET / — human landing page
- GET /llms.txt — this agent-readable entrypoint
- GET /skills/ — skill index
- GET /skills/create-from-template/SKILL.md — create documents from built-in templates
- GET /skills/present-to-human/SKILL.md — mint/open/revoke present links
- GET /skills/set-theme/SKILL.md — brand presentation pages
- GET /skills/team-cert-verification/SKILL.md — verifier checklist
- GET /present/{{token}} — server-rendered capability page for a pinned version
- GET /assets/{{asset_id}} — public media bytes reachable only from capability pages
- GET /robots.txt — crawler policy for user-content paths

Privacy/noindex policy:
- All user content is capability-link private and noindex: /present/* and /assets/* responses include X-Robots-Tag: noindex, nofollow, noarchive.
- /present/* pages also include <meta name="robots" content="noindex,nofollow,noarchive">.
- robots.txt disallows /present/ and /assets/.

Important invariants:
- AWID is authority for team keys, certificates, and revocation.
- Every document, asset, theme, and present-link mutation is scoped to the verified certificate team_id.
- Versions are append-only; edits create new versions.
- Team-supplied Markdown is sanitized. Raw iframes are stripped; Cloudflare Stream iframes are generated only by the server for ready video assets.
- folio stores server-readable text and media metadata. Do not call it end-to-end encrypted.

Source of truth:
- docs/sot.md
- README.md
- docs/spine-sot.md
- aweb.ai hub: https://aweb.ai
- AWID identity authority: https://awid.ai
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
        "folio is an aweb anapp: an agent-native app on the aweb.ai hub.",
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

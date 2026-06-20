from __future__ import annotations

import os
import re
from functools import lru_cache
from html import escape
from pathlib import Path
from typing import Any

from library.aweb_manifest import MANIFEST

_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_DIR = _REPO_ROOT / "skills"
_CONTAINER_SKILLS_DIR = Path("/app/skills")
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"

# aweb design system, vendored verbatim from the awebai/ac repo
# (site/static/css/aweb.css, sha256
# 6b2acef0d614c33508fe0f4e7270b4a2770ef18fb45d856c0d3e7862f85f2c19) and served at
# /css/aweb.css. The shared Paper/Clay foundation, byte-for-byte.


@lru_cache(maxsize=1)
def aweb_css() -> str:
    return (_ASSETS_DIR / "aweb.css").read_text(encoding="utf-8")


def _skills_dir() -> Path:
    configured = os.environ.get("LIBRARY_SKILLS_DIR")
    if configured:
        return Path(configured)
    if _SKILLS_DIR.is_dir():
        return _SKILLS_DIR
    if _CONTAINER_SKILLS_DIR.is_dir():
        return _CONTAINER_SKILLS_DIR
    return _SKILLS_DIR


_COPY_BTN = (
    '<button class="copy-btn" type="button" aria-label="Copy command">'
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>'
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>'
)

# Shared site chrome — used verbatim by the landing and the reference page so the
# two surfaces stay consistent. The scripts live in plain string constants (not
# f-strings) so the JS braces need no escaping.
_THEME_INIT_SCRIPT = """  <script>
    (function () {
      try {
        var t = localStorage.getItem('aweb-theme');
        if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
      } catch (e) {}
    })();
  </script>"""

_SITE_HEADER = """  <header class="site-header">
    <div class="wrap">
      <a class="brand" href="/"><span class="dot"></span>library</a>
      <nav class="nav-links">
        <a href="/#model">Model</a>
        <a href="/llms.txt">llms.txt</a>
        <a href="/reference">Reference</a>
        <a href="/skills/">Skills</a>
        <a href="https://awid.ai">AWID</a>
      </nav>
      <div class="header-right">
        <button class="theme-toggle" type="button" aria-label="Toggle dark mode" onclick="awebToggleTheme()">
          <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
          <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
        </button>
        <a class="btn secondary" href="https://aweb.ai">aweb.ai</a>
        <a class="btn primary" href="/llms.txt">Read llms.txt <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></svg></a>
      </div>
    </div>
  </header>"""

_SITE_SCRIPT_BODY = """    function awebToggleTheme() {
      var el = document.documentElement;
      var cur = el.getAttribute('data-theme');
      if (!cur) {
        cur = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      }
      var next = cur === 'dark' ? 'light' : 'dark';
      el.setAttribute('data-theme', next);
      try { localStorage.setItem('aweb-theme', next); } catch (e) {}
    }
    Array.prototype.forEach.call(document.querySelectorAll('.cmd .copy-btn'), function (button) {
      button.addEventListener('click', function () {
        var pre = button.parentElement.querySelector('pre');
        if (!pre) return;
        navigator.clipboard.writeText(pre.textContent).then(function () {
          button.classList.add('copied');
          setTimeout(function () { button.classList.remove('copied'); }, 1600);
        });
      });
    });"""

_COPY_LLMS_SCRIPT = """    var llmsBtn = document.getElementById('copy-llms');
    if (llmsBtn) {
      llmsBtn.addEventListener('click', function () {
        fetch(llmsBtn.getAttribute('data-llms-url')).then(function (r) { return r.text(); }).then(function (text) {
          navigator.clipboard.writeText(text).then(function () {
            var label = llmsBtn.textContent;
            llmsBtn.classList.add('copied');
            llmsBtn.textContent = 'Copied llms.txt';
            setTimeout(function () { llmsBtn.classList.remove('copied'); llmsBtn.textContent = label; }, 1600);
          });
        });
      });
    }"""


def _site_head(*, title: str, description: str) -> str:
    return f"""<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{escape(description, quote=True)}">
  <meta name="theme-color" content="#faf7f2" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#0a0705" media="(prefers-color-scheme: dark)">
  <title>{escape(title)}</title>
{_THEME_INIT_SCRIPT}
  <link rel="stylesheet" href="/css/aweb.css">
</head>"""


def _site_scripts(*, include_copy_llms: bool = False) -> str:
    body = _SITE_SCRIPT_BODY
    if include_copy_llms:
        body = f"{body}\n{_COPY_LLMS_SCRIPT}"
    return f"  <script>\n{body}\n  </script>"


def _site_footer(origin: str) -> str:
    return f"""  <footer class="site-footer">
    <div class="wrap">
      <div class="footer-cols">
        <div class="footer-brand">
          <a class="brand" href="/"><span class="dot"></span>library</a>
          <p>Public profile packs and private team shelves for AWID teams — adopt, bind, materialize, and evolve your agents' profiles.</p>
        </div>
        <div class="footer-col">
          <h4>Agents</h4>
          <a href="/llms.txt">llms.txt</a>
          <a href="/reference">API reference</a>
          <a href="/skills/">Skills</a>
          <a href="/aweb-app.json">App manifest</a>
        </div>
        <div class="footer-col">
          <h4>aweb</h4>
          <a href="https://aweb.ai">aweb.ai</a>
          <a href="https://awid.ai">AWID</a>
        </div>
      </div>
      <div class="footer-bottom">library is a Native Agentic App on the aweb.ai hub. AWID is the identity authority. Origin: {origin}</div>
    </div>
  </footer>"""


def render_landing_page(*, public_origin: str) -> str:
    origin = escape(public_origin.rstrip("/"), quote=True)
    copy = _COPY_BTN
    head = _site_head(
        title="library — agent profiles for AWID teams",
        description=(
            "library is the agent-first service for public profile packs, private team "
            "shelves, bindings, materialization, and learning for AWID teams."
        ),
    )
    return f"""<!doctype html>
<html lang="en">
{head}
<body>
{_SITE_HEADER}
  <main>
    <section class="hero-center">
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
    </section>
  </main>
{_site_footer(origin)}
{_site_scripts(include_copy_llms=True)}
</body>
</html>"""


# Live values that make the public catalog-read examples genuinely runnable
# against production (these resolve against the seeded engineering pack).
_EXAMPLE_PATH_VALUES = {"pack_ref": "aweb.engineering-pack", "profile_ref": "coordinator"}


def _tool_params(tool: dict[str, Any]) -> tuple[list[str], list[str]]:
    """A tool's (required, optional) parameter names, in manifest order.

    Path params are required by construction — the route cannot match without
    them — even when the manifest input_schema does not list them in `required`.
    Treating them as required here (a rendering concern) keeps the served
    manifest digest unchanged."""
    schema = tool.get("input_schema") or {}
    path_params = {p["name"] for p in tool.get("params", []) if p.get("in") == "path"}
    required = set(schema.get("required") or []) | path_params
    order: list[str] = [p["name"] for p in tool.get("params", []) if "name" in p]
    for name in schema.get("properties") or {}:
        if name not in order:
            order.append(name)
    req = [n for n in order if n in required]
    opt = [n for n in order if n not in required]
    return req, opt


def _example_path(tool: dict[str, Any]) -> str:
    """The path with placeholders replaced by live values, so a public read is a
    genuinely runnable URL with no brace placeholders."""
    path = tool["path"]
    for name, value in _EXAMPLE_PATH_VALUES.items():
        path = path.replace("{" + name + "}", value)
    return path


def _public_tools() -> list[dict[str, Any]]:
    return [t for t in MANIFEST["tools"] if t.get("auth") == "none"]


def _cert_tools() -> list[dict[str, Any]]:
    return [t for t in MANIFEST["tools"] if t.get("auth") != "none"]


def _llms_operation_block(tool: dict[str, Any]) -> str:
    req, opt = _tool_params(tool)
    lines = [
        f"aw library {tool['name']}  ({tool['method']} {tool['path']})",
        f"    {tool['description']}",
    ]
    if req:
        lines.append(f"    required: {', '.join(req)}")
    if opt:
        lines.append(f"    optional: {', '.join(opt)}")
    return "\n".join(lines)


def llms_txt(*, public_origin: str) -> str:
    origin = public_origin.rstrip("/")
    public_ops = "\n\n".join(_llms_operation_block(t) for t in _public_tools())
    team_ops = "\n\n".join(_llms_operation_block(t) for t in _cert_tools())
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

Public catalog reads (list-packs, get-pack, get-profile) need no auth. Every other
operation is team-scoped and authenticated with your AWID team certificate. When you
call through the aw plugin verbs (or the low-level aw id request --team-auth), aw
signs each request for you with your team member key — you never assemble auth
headers by hand.

For raw HTTP without aw, every team-certificate request carries four headers:
- Authorization: DIDKey <did:key> <signature> — base64 Ed25519 signature (standard alphabet, no padding) over the canonical payload bytes
- X-AWEB-Timestamp: <RFC3339 UTC> — equals the envelope timestamp; 300s replay window
- X-AWEB-Signed-Payload: base64url WITHOUT padding of the canonical JSON envelope — sorted keys, no whitespace; v=2; reserved fields aud, body_sha256, method, path, team_id, timestamp, v
- X-AWID-Team-Certificate: standard base64 of the team certificate JSON

This wire format tracks the aweb team-auth-envelope-v2 conformance vector. The full
signing recipe with per-operation curl is at {origin}/reference.


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


_SIGNED_HEADERS = (
    "Authorization: DIDKey <did:key> <base64 Ed25519 signature, standard alphabet, no padding>\n"
    "X-AWEB-Timestamp: <RFC3339 UTC, equal to the envelope timestamp field>\n"
    "X-AWEB-Signed-Payload: <base64url WITHOUT padding of the canonical JSON payload bytes>\n"
    "X-AWID-Team-Certificate: <standard base64 of the team certificate JSON>"
)


def _envelope_spec(origin: str) -> str:
    """The signed-payload envelope, shown with canonical (sorted) key order. The
    bytes actually signed are canonical JSON — sorted keys, no insignificant
    whitespace, UTF-8, no HTML escaping — so this pretty-printed form is for
    reading; a signer must emit the compact canonical bytes."""
    return (
        "{\n"
        f'  "aud": "{origin}",\n'
        '  "body_sha256": "<lowercase hex sha256 of the exact request body bytes;'
        ' empty body hashes the empty string>",\n'
        '  "method": "<uppercase HTTP method, e.g. POST>",\n'
        '  "path": "<escaped request target incl. query, e.g. /v1/shelf/import'
        ' or /v1/profile-packs?tags=starter>",\n'
        '  "team_id": "<your AWID team id>",\n'
        '  "timestamp": "<RFC3339 UTC, equal to X-AWEB-Timestamp>",\n'
        '  "v": 2\n'
        "}"
    )


def _params_by_loc(tool: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p.get("in", "body") for p in tool.get("params", []) if "name" in p}


def _aw_command(tool: dict[str, Any], *, examples: dict[str, str] | None = None) -> str:
    req, _opt = _tool_params(tool)
    examples = examples or {}
    parts = [f"aw library {tool['name']}"]
    parts += [f"--{name} {examples.get(name, f'<{name}>')}" for name in req]
    return " ".join(parts)


def _aw_id_request(origin: str, tool: dict[str, Any]) -> str:
    locs = _params_by_loc(tool)
    req, _opt = _tool_params(tool)
    cmd = f"aw id request --team-auth {tool['method']} {origin}{tool['path']}"
    body_req = [n for n in req if locs.get(n) == "body"]
    if body_req:
        body = "{" + ", ".join(f'"{n}": "..."' for n in body_req) + "}"
        cmd += f" --body '{body}'"
    return cmd


def _wire_block(origin: str, tool: dict[str, Any]) -> str:
    if tool.get("auth") == "none":
        return f"curl -s {origin}{_example_path(tool)}"
    locs = _params_by_loc(tool)
    req, opt = _tool_params(tool)
    lines = [f"{tool['method']} {tool['path']}", _SIGNED_HEADERS]
    body_req = [n for n in req if locs.get(n) == "body"]
    body_opt = [n for n in opt if locs.get(n) == "body"]
    if body_req or body_opt:
        lines.append("Content-Type: application/json")
        lines.append("")
        lines.append("{" + ", ".join(f'"{n}": "..."' for n in body_req) + "}")
    return "\n".join(lines)


def _reference_operation(origin: str, tool: dict[str, Any]) -> str:
    req, opt = _tool_params(tool)
    is_public = tool.get("auth") == "none"
    pill = (
        '<span class="pill ok">public</span>'
        if is_public
        else '<span class="pill run">team cert</span>'
    )
    bits = []
    if req:
        bits.append(f"required: {escape(', '.join(req))}")
    if opt:
        bits.append(f"optional: {escape(', '.join(opt))}")
    params_line = f'<p class="op-params">{" · ".join(bits)}</p>' if bits else ""

    signed = ""
    if not is_public:
        signed = (
            '\n          <p class="cmd-label">Run it signed, without the plugin</p>'
            f'\n          <div class="cmd-list"><div class="cmd"><pre>{escape(_aw_id_request(origin, tool), quote=False)}</pre>{_COPY_BTN}</div></div>'
        )
    wire_label = "On the wire — runnable" if is_public else "On the wire — aw signs this for you"
    aw_examples = _EXAMPLE_PATH_VALUES if is_public else None

    return f"""        <div class="cmd-panel op" id="op-{tool['name']}">
          <h3><code>aw library {tool['name']}</code> {pill}</h3>
          <p class="op-meta"><code>{tool['method']} {escape(tool['path'])}</code></p>
          <p>{escape(tool['description'])}</p>
          {params_line}
          <p class="cmd-label">Run it</p>
          <div class="cmd-list"><div class="cmd"><pre>{escape(_aw_command(tool, examples=aw_examples), quote=False)}</pre>{_COPY_BTN}</div></div>{signed}
          <p class="cmd-label">{wire_label}</p>
          <div class="cmd-list"><div class="cmd"><pre>{escape(_wire_block(origin, tool), quote=False)}</pre>{_COPY_BTN}</div></div>
        </div>"""


def render_reference_page(*, public_origin: str) -> str:
    raw_origin = public_origin.rstrip("/")
    origin = escape(raw_origin, quote=True)
    copy = _COPY_BTN
    head = _site_head(
        title="library — API reference",
        description=(
            "Every library operation in parallel: the canonical aw library verb and the "
            "raw HTTP wire format with AWID team-certificate signing."
        ),
    )
    public_ops = "\n".join(_reference_operation(raw_origin, t) for t in _public_tools())
    team_ops = "\n".join(_reference_operation(raw_origin, t) for t in _cert_tools())
    return f"""<!doctype html>
<html lang="en">
{head}
<body>
{_SITE_HEADER}
  <main>
    <section class="hero-center">
      <div class="wrap">
        <p class="kicker">API reference · library.aweb.ai</p>
        <h1>Every operation, two ways</h1>
        <p class="lede">Each library operation is shown as the canonical <code>aw library</code> verb a person or agent runs, and as the raw HTTP wire format for anyone writing their own client. The verbs are the <a href="/aweb-app.json">canonical manifest</a>; this page is generated from it.</p>
        <div class="cta-row">
          <a class="btn primary btn--lg" href="/llms.txt">Read llms.txt</a>
          <a class="btn secondary btn--lg" href="/#use">Getting started</a>
        </div>
      </div>
    </section>

    <section class="section section--tint" id="auth">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">Authentication</p>
          <h2>Public reads need nothing; everything else is signed</h2>
          <p>The three public catalog reads take no auth. Every other operation is team-scoped and authenticated with your AWID team certificate. Through the <code>aw</code> plugin verbs (or <code>aw id request --team-auth</code>), aw signs each request for you — you never assemble these headers by hand. Build your own client only if you are porting the signer to another language.</p>
        </div>
        <p class="prose-intro">This wire format tracks the canonical <strong>team-auth-envelope-v2</strong> conformance vector — the source of truth, at <code>aweb/cli/go/internal/conformance/vectors/team-auth-envelope-v2.json</code>. To port a signer to another language, match that vector byte for byte.</p>
        <p class="cmd-label">Every team-certificate request carries four headers</p>
        <div class="cmd-list"><div class="cmd"><pre>{escape(_SIGNED_HEADERS, quote=False)}</pre>{copy}</div></div>
        <p class="prose-intro">Mind the three encodings — do not mix them: the <code>Authorization</code> signature and the certificate use standard base64; the signed payload uses base64url <strong>without padding</strong> (Library rejects values containing <code>=</code>). The certificate's <code>member_did_key</code> must equal the <code>Authorization</code> did:key.</p>
        <p class="cmd-label">The signed payload — a canonical-JSON envelope (version 2)</p>
        <div class="cmd-list"><div class="cmd"><pre>{escape(_envelope_spec(raw_origin), quote=False)}</pre>{copy}</div></div>
        <p class="prose-intro">The bytes signed are <strong>canonical JSON</strong>: sorted keys, no insignificant whitespace, UTF-8, no HTML escaping (the same convention as awid <code>canonical_json_bytes</code>). The fields are shown above in sorted order; the pretty-printing is for reading only. The signature is over those canonical payload bytes <strong>after</strong> the timestamp is injected — not over the base64url <code>X-AWEB-Signed-Payload</code> header value.</p>
        <p class="prose-outro">Reserved fields are <code>aud</code>, <code>body_sha256</code>, <code>method</code>, <code>path</code>, <code>team_id</code>, <code>timestamp</code>, and <code>v</code>; a surface may add custom fields only in addition to these. aw sets <code>aud</code> to this origin (scheme and host), <code>method</code> uppercase, <code>path</code> to the exact escaped request target the server receives — the root-mounted <code>/v1/...</code> with its query string and no <code>/api</code> prefix — <code>body_sha256</code> to the lowercase hex SHA-256 of the exact body bytes (empty body hashes the empty string), <code>timestamp</code> equal to <code>X-AWEB-Timestamp</code>, and <code>team_id</code> from the certificate. The server recomputes and verifies all of it within a replay window of 300 seconds.</p>
      </div>
    </section>

    <section class="section" id="public">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">Public operations</p>
          <h2>Catalog reads — no auth</h2>
          <p>Browse the public profile-pack catalog. These are literal and copy-paste-runnable.</p>
        </div>
{public_ops}
      </div>
    </section>

    <section class="section section--tint" id="team">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">Team operations</p>
          <h2>Shelf, bindings, materialize, proposals — AWID team certificate</h2>
          <p>Each shows the canonical verb, the signed hand-runnable <code>aw id request</code> form, and the raw wire format aw produces.</p>
        </div>
{team_ops}
      </div>
    </section>
  </main>
{_site_footer(origin)}
{_site_scripts()}
</body>
</html>"""


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

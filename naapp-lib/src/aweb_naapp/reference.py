"""The /reference page: every manifest operation in parallel — the canonical
``aw <verb>`` command and the raw HTTP wire format — plus the honest team-cert v2
envelope reference linked to the conformance vector. Generated from the manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from typing import Any

from aweb_naapp.chrome import COPY_BTN, SiteConfig, page
from aweb_naapp.manifest import (
    cert_tools,
    example_path,
    is_fully_substituted,
    params_by_loc,
    public_tools,
    tool_params,
)


@dataclass(frozen=True)
class ReferenceCopy:
    """App-specific copy on the /reference page. Defaults are domain-neutral so a
    naapp gets a correct generic page out of the box; an app overrides the
    fragments that name its own nouns."""

    reads_phrase: str = "reads"
    rejects_subject: str = "the server"
    envelope_path_example: str = "/v1/resources/import or /v1/resources?filter=active"
    public_kicker: str = "Public operations"
    public_heading: str = "Reads — no auth"
    public_blurb: str = "These need no authentication and are copy-paste-runnable."
    team_kicker: str = "Team operations"
    team_heading: str = "Authenticated operations — AWID team certificate"
    team_blurb: str = (
        "Each shows the canonical verb, the signed hand-runnable "
        "<code>aw id request</code> form, and the raw wire format aw produces."
    )
    events_kicker: str = "Events"
    events_heading: str = "Events this app emits"
    events_blurb: str = (
        "Subscribed agents are woken when these events fire. Emitters are declared "
        "in the manifest and each event is signed."
    )


VECTOR_URL = (
    "https://github.com/awebai/aweb/blob/main/cli/go/internal/conformance/"
    "vectors/team-auth-envelope-v2.json"
)

_SIGNED_HEADERS = (
    "Authorization: DIDKey <did:key> <base64 Ed25519 signature, standard alphabet, no padding>\n"
    "X-AWEB-Timestamp: <RFC3339 UTC, equal to the envelope timestamp field>\n"
    "X-AWEB-Signed-Payload: <base64url WITHOUT padding of the canonical JSON payload bytes>\n"
    "X-AWID-Team-Certificate: <standard base64 of the team certificate JSON>"
)

_COUNT_WORDS = {
    0: "zero", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
    6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten",
}


def _count_word(n: int) -> str:
    return _COUNT_WORDS.get(n, str(n))


def _envelope_spec(origin: str, path_example: str) -> str:
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
        f'  "path": "<escaped request target incl. query, e.g. {path_example}>",\n'
        '  "team_id": "<your AWID team id>",\n'
        '  "timestamp": "<RFC3339 UTC, equal to X-AWEB-Timestamp>",\n'
        '  "v": 2\n'
        "}"
    )


def _aw_command(tool: dict[str, Any], verb: str, *, examples: dict[str, str] | None = None) -> str:
    req, _opt = tool_params(tool)
    examples = examples or {}
    parts = [f"aw {verb} {tool['name']}"]
    parts += [f"--{name} {examples.get(name, f'<{name}>')}" for name in req]
    return " ".join(parts)


def _aw_id_request(origin: str, tool: dict[str, Any]) -> str:
    locs = params_by_loc(tool)
    req, _opt = tool_params(tool)
    cmd = f"aw id request --team-auth {tool['method']} {origin}{tool['path']}"
    body = tool.get("body") or {}
    if body.get("mode") == "raw":
        return f"{cmd} --raw --body '<{body.get('raw_param', 'body')}>'"
    body_req = [n for n in req if locs.get(n) == "body"]
    if body_req:
        body_json = "{" + ", ".join(f'"{n}": "..."' for n in body_req) + "}"
        cmd += f" --body '{body_json}'"
    return cmd


def _wire_block(origin: str, tool: dict[str, Any], values: dict[str, str]) -> str:
    if tool.get("auth") == "none":
        return f"curl -s {origin}{example_path(tool, values)}"
    locs = params_by_loc(tool)
    req, opt = tool_params(tool)
    lines = [f"{tool['method']} {tool['path']}", _SIGNED_HEADERS]
    body = tool.get("body") or {}
    if body.get("mode") == "raw":
        lines.append(f"Content-Type: {body.get('content_type', 'application/octet-stream')}")
        lines.append("")
        lines.append(f"<{body.get('raw_param', 'body')}>")
        return "\n".join(lines)
    body_req = [n for n in req if locs.get(n) == "body"]
    body_opt = [n for n in opt if locs.get(n) == "body"]
    if body_req or body_opt:
        lines.append("Content-Type: application/json")
        lines.append("")
        lines.append("{" + ", ".join(f'"{n}": "..."' for n in body_req) + "}")
    return "\n".join(lines)


def _params_table(tool: dict[str, Any]) -> str:
    """A typed parameter table for one operation: name, location, type, required."""
    schema = tool.get("input_schema") or {}
    props = schema.get("properties") or {}
    req, _opt = tool_params(tool)
    locs = params_by_loc(tool)
    names = [p["name"] for p in tool.get("params", []) if "name" in p]
    for name in props:
        if name not in names:
            names.append(name)
    if not names:
        return ""
    rows = "\n            ".join(
        f"<tr><td><code>{escape(n)}</code></td><td>{escape(locs.get(n, 'body'))}</td>"
        f"<td>{escape(str((props.get(n) or {}).get('type', '—')))}</td>"
        + ('<td class="ref-req">required</td>' if n in req else '<td class="ref-opt">optional</td>')
        + "</tr>"
        for n in names
    )
    return f"""
          <table class="ref-params">
            <thead><tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th></tr></thead>
            <tbody>
            {rows}
            </tbody>
          </table>"""


def _operation(origin: str, tool: dict[str, Any], verb: str, values: dict[str, str]) -> str:
    is_public = tool.get("auth") == "none"
    name = tool["name"]
    auth_tag = (
        '<span class="ref-auth-tag ref-auth-tag--public">public</span>'
        if is_public
        else '<span class="ref-auth-tag ref-auth-tag--team">team cert</span>'
    )
    scope_tags = "".join(
        f'<span class="ref-scope-tag">{escape(s)}</span>' for s in tool.get("scopes") or []
    )
    method_cls = "ref-op-method ref-op-method--write" if tool.get("mutation") else "ref-op-method"
    aw_cmd = escape(_aw_command(tool, verb, examples=values if is_public else None), quote=False)
    wire = escape(_wire_block(origin, tool, values), quote=False)
    if is_public:
        runnable = " — copy-paste runnable" if is_fully_substituted(tool, values) else ""
        wire_body = (
            f'<p class="ref-wire-note">Raw HTTP, no auth{runnable}.</p>'
            f'<div class="cmd"><pre>{wire}</pre>{COPY_BTN}</div>'
        )
    else:
        signed = escape(_aw_id_request(origin, tool), quote=False)
        wire_body = (
            f'<div class="cmd"><pre>{wire}</pre>{COPY_BTN}</div>'
            '<p class="ref-wire-note">Hand-runnable with the aw CLI, no plugin:</p>'
            f'<div class="cmd"><pre>{signed}</pre>{COPY_BTN}</div>'
        )
    return f"""        <article class="ref-op" id="op-{name}">
          <div class="ref-op-sig">
            <span class="ref-op-id">
              <a class="ref-op-anchor" href="#op-{name}" aria-label="Link to {name}">#</a>
              <code class="ref-op-verb">aw {verb} {name}</code>
              <span class="{method_cls}">{tool['method']}</span>
              <code class="ref-op-path">{escape(tool['path'])}</code>
            </span>
            <span class="ref-op-tags">{scope_tags}{auth_tag}</span>
          </div>
          <p class="ref-op-desc">{escape(tool['description'])}</p>{_params_table(tool)}
          <div class="cmd ref-cmd-primary"><pre>{aw_cmd}</pre>{COPY_BTN}</div>
          <details class="ref-wire-details"><summary>HTTP wire format</summary><div class="ref-wire-body">{wire_body}</div></details>
        </article>"""


_AUTH_TAIL = (
    "Through the <code>aw</code> plugin verbs (or <code>aw id request --team-auth</code>), "
    "aw signs each request for you — you never assemble these headers by hand. Build your "
    "own client only if you are porting the signer to another language."
)


def _events_section(events: list[dict[str, Any]], text: ReferenceCopy) -> str:
    if not events:
        return ""
    blocks = "\n".join(
        f"""        <article class="ref-op" id="event-{e["type"].replace("/", "-")}">
          <div class="ref-op-sig">
            <code class="ref-op-verb">{escape(e["type"])}</code>
            <span class="ref-auth-tag ref-auth-tag--team">{escape(str(e.get("default_delivery_intent", "wake")))}</span>
          </div>
          <p class="ref-op-desc">{escape(e.get("description", ""))}</p>
        </article>"""
        for e in events
    )
    return f"""        <div class="ref-section-label"><h2>{text.events_heading}</h2><span class="count">{_count_word(len(events))}</span></div>
{blocks}"""


def render_reference(
    manifest: dict[str, Any],
    site: SiteConfig,
    *,
    verb: str,
    example_path_values: dict[str, str] | None = None,
    copy: ReferenceCopy | None = None,
) -> str:
    """The complete /reference page for a naapp, wrapped in the shared chrome.

    ``verb`` is the app's plugin verb namespace (e.g. "library" → ``aw library``).
    ``example_path_values`` maps path-param names to live values so a public read
    renders a genuinely runnable curl; params with no value stay ``{brace}`` and
    that read is not labelled runnable. ``copy`` overrides the domain-specific copy
    fragments (the defaults are domain-neutral).
    """
    raw_origin = site.origin.rstrip("/")
    values = example_path_values or {}
    text = copy or ReferenceCopy()
    btn = COPY_BTN
    publics = public_tools(manifest)
    certs = cert_tools(manifest)
    events = manifest.get("events") or []
    has_public = bool(publics)

    if has_public:
        auth_intro = (
            f"The {_count_word(len(publics))} public {text.reads_phrase} take no auth. "
            f"Every other operation is team-scoped and authenticated with your AWID team "
            f"certificate. {_AUTH_TAIL}"
        )
    else:
        auth_intro = (
            f"Every operation is team-scoped and authenticated with your AWID team "
            f"certificate. {_AUTH_TAIL}"
        )

    ref_header = """    <div class="wrap ref-page-header">
      <h1 class="ref-page-title">API reference</h1>
      <p class="ref-page-desc">Generated from <a href="/aweb-app.json">aweb-app.json</a> · <a href="/llms.txt">llms.txt</a></p>
    </div>"""

    def _nav_group(label: str, links: str) -> str:
        return f"""        <div class="ref-nav-group">
          <p class="ref-nav-label">{label}</p>
          {links}
        </div>"""

    nav_groups = ""
    if has_public:
        nav_groups += _nav_group(
            "Public",
            "\n          ".join(f'<a href="#op-{escape(t["name"])}">{escape(t["name"])}</a>' for t in publics),
        )
    if certs:
        nav_groups += _nav_group(
            "Authenticated",
            "\n          ".join(f'<a href="#op-{escape(t["name"])}">{escape(t["name"])}</a>' for t in certs),
        )
    if events:
        nav_groups += _nav_group(
            "Events",
            "\n          ".join(
                f'<a href="#event-{e["type"].replace("/", "-")}">{escape(e["type"])}</a>' for e in events
            ),
        )
    sidebar = f"""      <aside class="ref-sidebar">
        <nav class="ref-nav">
{nav_groups}
          <div class="ref-nav-divider"></div>
          <a class="ref-nav-link" href="#auth">Authentication</a>
        </nav>
      </aside>"""

    public_section = ""
    if has_public:
        public_ops = "\n".join(_operation(raw_origin, t, verb, values) for t in publics)
        public_section = f"""        <div class="ref-section-label"><h2>{text.public_heading}</h2><span class="count">{_count_word(len(publics))}</span></div>
{public_ops}"""

    team_section = ""
    if certs:
        team_ops = "\n".join(_operation(raw_origin, t, verb, values) for t in certs)
        team_section = f"""        <div class="ref-section-label"><h2>{text.team_heading}</h2><span class="count">{_count_word(len(certs))}</span></div>
        <p class="ref-section-note">aw signs every team-certificate request for you. The HTTP wire format under each operation is only needed to port a signer — see <a href="#auth">Authentication</a>.</p>
{team_ops}"""

    events_section = _events_section(events, text)

    auth = f"""        <div class="ref-section-label" id="auth"><h2>Authentication</h2></div>
        <p class="ref-op-desc">{auth_intro}</p>
        <p class="ref-wire-note">This wire format tracks the canonical <strong>team-auth-envelope-v2</strong> conformance vector at <a href="{VECTOR_URL}"><code>cli/go/internal/conformance/vectors/team-auth-envelope-v2.json</code></a> — match it byte for byte to port a signer.</p>
        <p class="cmd-label">Four headers on every team-certificate request</p>
        <div class="cmd"><pre>{escape(_SIGNED_HEADERS, quote=False)}</pre>{btn}</div>
        <p class="ref-wire-note">Mind the three encodings: the <code>Authorization</code> signature and the certificate use standard base64; the signed payload uses base64url <strong>without padding</strong> ({text.rejects_subject} rejects values containing <code>=</code>). The certificate's <code>member_did_key</code> must equal the <code>Authorization</code> did:key.</p>
        <p class="cmd-label">The signed payload — a canonical-JSON envelope (version 2)</p>
        <div class="cmd"><pre>{escape(_envelope_spec(raw_origin, text.envelope_path_example), quote=False)}</pre>{btn}</div>
        <p class="ref-wire-note">The bytes signed are <strong>canonical JSON</strong>: sorted keys, no insignificant whitespace, UTF-8, no HTML escaping (the awid <code>canonical_json_bytes</code> convention). The signature is over those canonical payload bytes <strong>after</strong> the timestamp is injected — not over the base64url <code>X-AWEB-Signed-Payload</code> header value.</p>
        <p class="ref-wire-note">Reserved fields are <code>aud</code>, <code>body_sha256</code>, <code>method</code>, <code>path</code>, <code>team_id</code>, <code>timestamp</code>, and <code>v</code>; a surface may add custom fields only in addition to these. aw sets <code>aud</code> to this origin (scheme and host), <code>method</code> uppercase, <code>path</code> to the exact escaped request target the server receives (root-mounted <code>/v1/...</code> with query string, no <code>/api</code> prefix), <code>body_sha256</code> to the lowercase hex SHA-256 of the exact body bytes, <code>timestamp</code> equal to <code>X-AWEB-Timestamp</code>, and <code>team_id</code> from the certificate. The server recomputes and verifies all of it within a 300-second replay window.</p>"""

    content = "\n".join(s for s in [public_section, team_section, events_section, auth] if s)
    layout = f"""    <div class="wrap ref-layout">
{sidebar}
      <div class="ref-content">
{content}
      </div>
    </div>"""
    body = f"{ref_header}\n{layout}"
    return page(site, body)

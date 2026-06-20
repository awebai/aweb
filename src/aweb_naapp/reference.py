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
    body_req = [n for n in req if locs.get(n) == "body"]
    if body_req:
        body = "{" + ", ".join(f'"{n}": "..."' for n in body_req) + "}"
        cmd += f" --body '{body}'"
    return cmd


def _wire_block(origin: str, tool: dict[str, Any], values: dict[str, str]) -> str:
    if tool.get("auth") == "none":
        return f"curl -s {origin}{example_path(tool, values)}"
    locs = params_by_loc(tool)
    req, opt = tool_params(tool)
    lines = [f"{tool['method']} {tool['path']}", _SIGNED_HEADERS]
    body_req = [n for n in req if locs.get(n) == "body"]
    body_opt = [n for n in opt if locs.get(n) == "body"]
    if body_req or body_opt:
        lines.append("Content-Type: application/json")
        lines.append("")
        lines.append("{" + ", ".join(f'"{n}": "..."' for n in body_req) + "}")
    return "\n".join(lines)


def _operation(origin: str, tool: dict[str, Any], verb: str, values: dict[str, str]) -> str:
    req, opt = tool_params(tool)
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
            f'\n          <div class="cmd-list"><div class="cmd"><pre>{escape(_aw_id_request(origin, tool), quote=False)}</pre>{COPY_BTN}</div></div>'
        )
    # A public read is only labelled runnable when every path placeholder has an
    # example value; otherwise the curl keeps a {brace} and is just the shape.
    if not is_public:
        wire_label = "On the wire — aw signs this for you"
    elif is_fully_substituted(tool, values):
        wire_label = "On the wire — runnable"
    else:
        wire_label = "On the wire"
    aw_examples = values if is_public else None

    return f"""        <div class="cmd-panel op" id="op-{tool['name']}">
          <h3><code>aw {verb} {tool['name']}</code> {pill}</h3>
          <p class="op-meta"><code>{tool['method']} {escape(tool['path'])}</code></p>
          <p>{escape(tool['description'])}</p>
          {params_line}
          <p class="cmd-label">Run it</p>
          <div class="cmd-list"><div class="cmd"><pre>{escape(_aw_command(tool, verb, examples=aw_examples), quote=False)}</pre>{COPY_BTN}</div></div>{signed}
          <p class="cmd-label">{wire_label}</p>
          <div class="cmd-list"><div class="cmd"><pre>{escape(_wire_block(origin, tool, values), quote=False)}</pre>{COPY_BTN}</div></div>
        </div>"""


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
    host = raw_origin.split("://", 1)[-1]
    values = example_path_values or {}
    text = copy or ReferenceCopy()
    btn = COPY_BTN
    publics = public_tools(manifest)
    public_ops = "\n".join(_operation(raw_origin, t, verb, values) for t in publics)
    team_ops = "\n".join(_operation(raw_origin, t, verb, values) for t in cert_tools(manifest))
    public_count = _count_word(len(publics))
    body = f"""    <section class="hero-center">
      <div class="wrap">
        <p class="kicker">API reference · {host}</p>
        <h1>Every operation, two ways</h1>
        <p class="lede">Each {site.brand} operation is shown as the canonical <code>aw {verb}</code> verb a person or agent runs, and as the raw HTTP wire format for anyone writing their own client. The verbs are the <a href="/aweb-app.json">canonical manifest</a>; this page is generated from it.</p>
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
          <p>The {public_count} public {text.reads_phrase} take no auth. Every other operation is team-scoped and authenticated with your AWID team certificate. Through the <code>aw</code> plugin verbs (or <code>aw id request --team-auth</code>), aw signs each request for you — you never assemble these headers by hand. Build your own client only if you are porting the signer to another language.</p>
        </div>
        <p class="prose-intro">This wire format tracks the canonical <strong>team-auth-envelope-v2</strong> conformance vector — the source of truth, at <a href="{VECTOR_URL}"><code>cli/go/internal/conformance/vectors/team-auth-envelope-v2.json</code></a>. To port a signer to another language, match that vector byte for byte.</p>
        <p class="cmd-label">Every team-certificate request carries four headers</p>
        <div class="cmd-list"><div class="cmd"><pre>{escape(_SIGNED_HEADERS, quote=False)}</pre>{btn}</div></div>
        <p class="prose-intro">Mind the three encodings — do not mix them: the <code>Authorization</code> signature and the certificate use standard base64; the signed payload uses base64url <strong>without padding</strong> ({text.rejects_subject} rejects values containing <code>=</code>). The certificate's <code>member_did_key</code> must equal the <code>Authorization</code> did:key.</p>
        <p class="cmd-label">The signed payload — a canonical-JSON envelope (version 2)</p>
        <div class="cmd-list"><div class="cmd"><pre>{escape(_envelope_spec(raw_origin, text.envelope_path_example), quote=False)}</pre>{btn}</div></div>
        <p class="prose-intro">The bytes signed are <strong>canonical JSON</strong>: sorted keys, no insignificant whitespace, UTF-8, no HTML escaping (the same convention as awid <code>canonical_json_bytes</code>). The fields are shown above in sorted order; the pretty-printing is for reading only. The signature is over those canonical payload bytes <strong>after</strong> the timestamp is injected — not over the base64url <code>X-AWEB-Signed-Payload</code> header value.</p>
        <p class="prose-outro">Reserved fields are <code>aud</code>, <code>body_sha256</code>, <code>method</code>, <code>path</code>, <code>team_id</code>, <code>timestamp</code>, and <code>v</code>; a surface may add custom fields only in addition to these. aw sets <code>aud</code> to this origin (scheme and host), <code>method</code> uppercase, <code>path</code> to the exact escaped request target the server receives — the root-mounted <code>/v1/...</code> with its query string and no <code>/api</code> prefix — <code>body_sha256</code> to the lowercase hex SHA-256 of the exact body bytes (empty body hashes the empty string), <code>timestamp</code> equal to <code>X-AWEB-Timestamp</code>, and <code>team_id</code> from the certificate. The server recomputes and verifies all of it within a replay window of 300 seconds.</p>
      </div>
    </section>

    <section class="section" id="public">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">{text.public_kicker}</p>
          <h2>{text.public_heading}</h2>
          <p>{text.public_blurb}</p>
        </div>
{public_ops}
      </div>
    </section>

    <section class="section section--tint" id="team">
      <div class="wrap">
        <div class="section-head">
          <p class="kicker">{text.team_kicker}</p>
          <h2>{text.team_heading}</h2>
          <p>{text.team_blurb}</p>
        </div>
{team_ops}
      </div>
    </section>"""
    return page(site, body)

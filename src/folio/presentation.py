from __future__ import annotations

import json
import re
import secrets
from html import escape
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import markdown
import nh3

_ALLOWED_TAGS = {
    "a",
    "blockquote",
    "br",
    "code",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "img",
    "li",
    "ol",
    "p",
    "pre",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
}
_ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "img": {"src", "alt", "title"},
    "th": {"align"},
    "td": {"align"},
}
_ALLOWED_PROTOCOLS = {"http", "https", "mailto"}
_COLOR_VARIABLES = {
    "background": "--bg",
    "surface": "--surface",
    "text": "--text",
    "muted": "--muted",
    "border": "--border",
    "accent": "--accent",
}
_FONT_VARIABLES = {
    "body": "--font-body",
    "heading": "--font-heading",
}
_FONT_ALLOWLIST = {
    "system": 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    "serif": 'Georgia, Cambria, "Times New Roman", Times, serif',
    "mono": 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace',
}
_NAMED_COLORS = {
    "black",
    "white",
    "transparent",
    "red",
    "green",
    "blue",
    "navy",
    "orange",
    "purple",
    "pink",
    "yellow",
    "gray",
    "grey",
}
_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_RGB_COLOR_RE = re.compile(r"^rgba?\(([^)]+)\)$", re.IGNORECASE)
_ASSET_PATH_RE = re.compile(r"^/assets/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
_IMG_WITHOUT_SRC_RE = re.compile(r"<img\b(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)
_MARKDOWN_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def _valid_rgb_color(value: str) -> bool:
    match = _RGB_COLOR_RE.fullmatch(value.strip())
    if not match:
        return False
    parts = [part.strip() for part in match.group(1).split(",")]
    if len(parts) not in {3, 4}:
        return False
    try:
        channels = [int(part) for part in parts[:3]]
    except ValueError:
        return False
    if any(channel < 0 or channel > 255 for channel in channels):
        return False
    if len(parts) == 4:
        try:
            alpha = float(parts[3])
        except ValueError:
            return False
        if alpha < 0 or alpha > 1:
            return False
    return True


def _valid_color(value: str) -> bool:
    candidate = value.strip()
    return bool(
        _HEX_COLOR_RE.fullmatch(candidate)
        or _valid_rgb_color(candidate)
        or candidate.lower() in _NAMED_COLORS
    )


def sanitize_theme_tokens(tokens: Any) -> dict[str, dict[str, str]]:
    if not isinstance(tokens, dict):
        return {}

    sanitized: dict[str, dict[str, str]] = {}
    colors = tokens.get("colors")
    if isinstance(colors, dict):
        safe_colors = {
            str(key): value.strip()
            for key, value in colors.items()
            if key in _COLOR_VARIABLES and isinstance(value, str) and _valid_color(value)
        }
        if safe_colors:
            sanitized["colors"] = safe_colors

    fonts = tokens.get("fonts")
    if isinstance(fonts, dict):
        safe_fonts = {
            str(key): value.lower().strip()
            for key, value in fonts.items()
            if key in _FONT_VARIABLES and isinstance(value, str) and value.lower().strip() in _FONT_ALLOWLIST
        }
        if safe_fonts:
            sanitized["fonts"] = safe_fonts

    return sanitized


def _theme_css(tokens: dict[str, dict[str, str]] | None) -> str:
    if not tokens:
        return ""
    declarations: list[str] = []
    for key, value in tokens.get("colors", {}).items():
        variable = _COLOR_VARIABLES.get(key)
        if variable and _valid_color(value):
            declarations.append(f"      {variable}: {value.strip()};")
    for key, value in tokens.get("fonts", {}).items():
        variable = _FONT_VARIABLES.get(key)
        family = _FONT_ALLOWLIST.get(value.lower().strip())
        if variable and family:
            declarations.append(f"      {variable}: {family};")
    if not declarations:
        return ""
    return "\n" + "\n".join(declarations) + "\n"


def _asset_id_from_same_origin_src(src: str, *, public_origin: str | None) -> UUID | None:
    if public_origin is None:
        return None
    candidate = src.strip()
    if not candidate:
        return None

    origin = urlparse(public_origin.rstrip("/"))
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != origin.scheme or parsed.netloc != origin.netloc:
            return None
    if parsed.params or parsed.query or parsed.fragment:
        return None

    match = _ASSET_PATH_RE.fullmatch(parsed.path)
    if match is None:
        return None
    try:
        return UUID(match.group(1))
    except ValueError:
        return None


def _safe_image_src(src: str, *, public_origin: str | None, image_asset_ids: set[UUID]) -> str | None:
    asset_id = _asset_id_from_same_origin_src(src, public_origin=public_origin)
    if asset_id is None or asset_id not in image_asset_ids:
        return None
    return src.strip()


def _video_iframe_html(*, iframe_url: str, title: str) -> str:
    safe_url = escape(iframe_url, quote=True)
    safe_title = escape(title or "Embedded video", quote=True)
    return (
        '<figure class="folio-video">'
        f'<iframe src="{safe_url}" title="{safe_title}" loading="lazy" '
        'allow="accelerometer; gyroscope; autoplay; encrypted-media; picture-in-picture" '
        'allowfullscreen sandbox="allow-scripts allow-same-origin allow-presentation"></iframe>'
        f'<figcaption>{safe_title}</figcaption>'
        '</figure>'
    )


def _replace_video_markdown(
    body: str,
    *,
    public_origin: str | None,
    video_embeds: dict[UUID, dict[str, str]],
) -> tuple[str, dict[str, str]]:
    replacements: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        alt = match.group(1)
        src = match.group(2)
        asset_id = _asset_id_from_same_origin_src(src, public_origin=public_origin)
        embed = video_embeds.get(asset_id) if asset_id is not None else None
        if embed is None:
            return match.group(0)
        iframe_url = str(embed.get("iframe_url") or "")
        if not iframe_url:
            status = escape(str(embed.get("status") or "processing"))
            return f'\n\n<div class="folio-video-pending">Video is {status}.</div>\n\n'
        token = f"FOLIO_VIDEO_{secrets.token_urlsafe(24)}"
        replacements[token] = _video_iframe_html(iframe_url=iframe_url, title=alt or "Embedded video")
        return f"\n\n{token}\n\n"

    return _MARKDOWN_IMAGE_RE.sub(replace, body), replacements


def render_presented_markdown(
    body: str,
    *,
    public_origin: str | None = None,
    allowed_asset_ids: set[UUID] | None = None,
    asset_embeds: dict[UUID, dict[str, str]] | None = None,
) -> str:
    """Render Markdown to sanitized HTML safe for unauthenticated public pages."""

    embeds = asset_embeds or {}
    image_asset_ids = {
        asset_id for asset_id, embed in embeds.items() if str(embed.get("kind") or "image") == "image"
    }
    image_asset_ids.update(allowed_asset_ids or set())
    video_embeds = {
        asset_id: embed for asset_id, embed in embeds.items() if str(embed.get("kind") or "") == "video"
    }
    preprocessed_body, trusted_video_replacements = _replace_video_markdown(
        body,
        public_origin=public_origin,
        video_embeds=video_embeds,
    )

    def attribute_filter(tag: str, attribute: str, value: str) -> str | None:
        if tag == "img" and attribute == "src":
            return _safe_image_src(value, public_origin=public_origin, image_asset_ids=image_asset_ids)
        return value

    unsafe_html = markdown.markdown(
        preprocessed_body,
        extensions=["extra", "sane_lists"],
        output_format="html",
    )
    sanitized = nh3.clean(
        unsafe_html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        attribute_filter=attribute_filter,
        url_schemes=_ALLOWED_PROTOCOLS,
        link_rel="noopener noreferrer",
    )
    sanitized = _IMG_WITHOUT_SRC_RE.sub("", sanitized)
    for token, iframe_html in trusted_video_replacements.items():
        sanitized = sanitized.replace(f"<p>{token}</p>", iframe_html)
        sanitized = sanitized.replace(token, iframe_html)
    return sanitized


def render_presented_page(
    *,
    body: str,
    theme: dict[str, Any] | None = None,
    public_origin: str | None = None,
    allowed_asset_ids: set[UUID] | None = None,
    asset_embeds: dict[UUID, dict[str, str]] | None = None,
) -> str:
    content = render_presented_markdown(
        body,
        public_origin=public_origin,
        allowed_asset_ids=allowed_asset_ids,
        asset_embeds=asset_embeds,
    )
    safe_tokens = sanitize_theme_tokens((theme or {}).get("tokens"))
    theme_css = _theme_css(safe_tokens)
    logo_url = str((theme or {}).get("logo_url") or "")
    header = str((theme or {}).get("header") or "")
    footer = str((theme or {}).get("footer") or "")
    logo_html = (
        f'      <img class="brand-logo" src="{escape(logo_url, quote=True)}" alt="Team logo">\n'
        if logo_url
        else ""
    )
    header_html = f'      <header class="theme-header">{escape(header)}</header>\n' if header else ""
    footer_html = f'      <footer class="theme-footer">{escape(footer)}</footer>\n' if footer else ""
    title = escape("Presented document")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --surface: #ffffff;
      --text: #111827;
      --muted: #4b5563;
      --border: #e5e7eb;
      --accent: #2563eb;
      --font-body: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --font-heading: var(--font-body);{theme_css}    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-body);
      line-height: 1.6;
    }}
    .page {{
      max-width: 860px;
      margin: 0 auto;
      padding: 48px 20px;
    }}
    .surface {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 20px 45px rgba(15, 23, 42, 0.08);
      padding: clamp(24px, 5vw, 56px);
    }}
    .eyebrow {{
      color: var(--muted);
      font-size: 0.875rem;
      margin: 0 0 24px;
    }}
    .brand-logo {{
      display: block;
      max-height: 72px;
      max-width: min(240px, 100%);
      object-fit: contain;
      margin: 0 0 24px;
    }}
    .theme-header, .theme-footer {{
      color: var(--muted);
      white-space: pre-wrap;
    }}
    .theme-header {{ margin: 0 0 28px; }}
    .theme-footer {{ margin: 32px 0 0; }}
    .document-body :first-child {{ margin-top: 0; }}
    .document-body :last-child {{ margin-bottom: 0; }}
    .document-body h1, .document-body h2, .document-body h3 {{ font-family: var(--font-heading); line-height: 1.2; }}
    .document-body a {{ color: var(--accent); }}
    .document-body pre, .document-body code {{
      background: #f3f4f6;
      border-radius: 8px;
    }}
    .document-body code {{ padding: 0.1rem 0.25rem; }}
    .document-body pre {{ overflow: auto; padding: 1rem; }}
    .document-body blockquote {{
      border-left: 4px solid var(--border);
      color: var(--muted);
      margin-left: 0;
      padding-left: 1rem;
    }}
    .document-body img {{
      display: block;
      max-width: 100%;
      height: auto;
      border-radius: 12px;
      margin: 1rem 0;
    }}
    .folio-video {{ margin: 1.5rem 0; }}
    .folio-video iframe {{
      display: block;
      width: 100%;
      aspect-ratio: 16 / 9;
      border: 0;
      border-radius: 14px;
      background: #000;
    }}
    .folio-video figcaption, .folio-video-pending {{ color: var(--muted); font-size: 0.9rem; }}
    .folio-video-pending {{ border: 1px dashed var(--border); border-radius: 12px; padding: 1rem; }}
    .document-body table {{ border-collapse: collapse; width: 100%; }}
    .document-body th, .document-body td {{ border: 1px solid var(--border); padding: 0.5rem; }}
  </style>
</head>
<body>
  <main class="page">
    <article class="surface">
{logo_html}      <p class="eyebrow">Presented with folio</p>
{header_html}      <div class="document-body">
{content}
      </div>
{footer_html}    </article>
  </main>
</body>
</html>"""


def _script_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def render_editor_page(
    *,
    token: str,
    body: str,
    version_number: int,
    theme: dict[str, Any] | None = None,
    public_origin: str | None = None,
    allowed_asset_ids: set[UUID] | None = None,
    asset_embeds: dict[UUID, dict[str, str]] | None = None,
    nonce: str,
) -> str:
    preview = render_presented_markdown(
        body,
        public_origin=public_origin,
        allowed_asset_ids=allowed_asset_ids,
        asset_embeds=asset_embeds,
    )
    safe_tokens = sanitize_theme_tokens((theme or {}).get("tokens"))
    theme_css = _theme_css(safe_tokens)
    logo_url = str((theme or {}).get("logo_url") or "")
    header = str((theme or {}).get("header") or "")
    footer = str((theme or {}).get("footer") or "")
    logo_html = (
        f'      <img class="brand-logo" src="{escape(logo_url, quote=True)}" alt="Team logo">\n'
        if logo_url
        else ""
    )
    header_html = f'      <header class="theme-header">{escape(header)}</header>\n' if header else ""
    footer_html = f'      <footer class="theme-footer">{escape(footer)}</footer>\n' if footer else ""
    initial_json = _script_json({"body": body, "version_number": version_number, "token": token})
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Edit presented document</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --surface: #ffffff;
      --text: #111827;
      --muted: #4b5563;
      --border: #e5e7eb;
      --accent: #2563eb;
      --font-body: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --font-heading: var(--font-body);{theme_css}    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font-family: var(--font-body); line-height: 1.6; }}
    .page {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px; }}
    .surface {{ background: var(--surface); border: 1px solid var(--border); border-radius: 18px; box-shadow: 0 20px 45px rgba(15, 23, 42, 0.08); padding: clamp(20px, 4vw, 40px); }}
    .eyebrow, .meta, .status, .theme-header, .theme-footer {{ color: var(--muted); }}
    .toolbar {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin: 0 0 16px; }}
    .toolbar button {{ border: 1px solid var(--border); background: #fff; border-radius: 999px; padding: 8px 14px; cursor: pointer; }}
    .toolbar button.primary {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
    .toolbar input {{ border: 1px solid var(--border); border-radius: 999px; padding: 8px 12px; }}
    .editor {{ width: 100%; min-height: 55vh; border: 1px solid var(--border); border-radius: 12px; padding: 16px; font: 1rem/1.5 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .preview {{ border: 1px solid var(--border); border-radius: 12px; padding: 16px; min-height: 55vh; }}
    .hidden {{ display: none; }}
    .brand-logo {{ display: block; max-height: 72px; max-width: min(240px, 100%); object-fit: contain; margin: 0 0 24px; }}
    .theme-header {{ margin: 0 0 20px; white-space: pre-wrap; }}
    .theme-footer {{ margin: 24px 0 0; white-space: pre-wrap; }}
    .preview img {{ display: block; max-width: 100%; height: auto; border-radius: 12px; margin: 1rem 0; }}
  </style>
</head>
<body>
  <main class="page">
    <article class="surface">
{logo_html}      <p class="eyebrow">Editable folio link</p>
{header_html}      <div class="toolbar" aria-label="Editor controls">
        <button id="edit-tab" type="button" class="primary">Edit</button>
        <button id="preview-tab" type="button">Preview</button>
        <input id="editor-name" type="text" maxlength="120" autocomplete="name" placeholder="Editing as (optional)">
        <button id="save" type="button" class="primary">Save new version</button>
        <span id="meta" class="meta">Version {version_number}</span>
      </div>
      <p id="status" class="status" role="status"></p>
      <textarea id="body" class="editor" spellcheck="true"></textarea>
      <div id="preview" class="preview hidden">{preview}</div>
{footer_html}    </article>
  </main>
  <script nonce="{escape(nonce, quote=True)}">
    const INITIAL = {initial_json};
    const bodyEl = document.getElementById('body');
    const previewEl = document.getElementById('preview');
    const statusEl = document.getElementById('status');
    const metaEl = document.getElementById('meta');
    const nameEl = document.getElementById('editor-name');
    let baseVersion = INITIAL.version_number;
    let dirty = false;
    bodyEl.value = INITIAL.body;
    nameEl.value = window.localStorage.getItem('folio.editorName') || '';
    function renderLivePreview() {{
      previewEl.replaceChildren();
      const blocks = bodyEl.value.split(/\n{{2,}}/).filter((block) => block.length > 0);
      if (blocks.length === 0) {{ previewEl.appendChild(document.createElement('p')); return; }}
      for (const block of blocks) {{
        const trimmed = block.trimStart();
        let el;
        if (trimmed.startsWith('## ')) {{ el = document.createElement('h2'); el.textContent = trimmed.slice(3); }}
        else if (trimmed.startsWith('# ')) {{ el = document.createElement('h1'); el.textContent = trimmed.slice(2); }}
        else {{ el = document.createElement('p'); el.textContent = block; }}
        previewEl.appendChild(el);
      }}
    }}
    bodyEl.addEventListener('input', () => {{ dirty = true; renderLivePreview(); }});
    nameEl.addEventListener('input', () => window.localStorage.setItem('folio.editorName', nameEl.value));
    function setStatus(message) {{ statusEl.textContent = message || ''; }}
    function showEdit() {{ bodyEl.classList.remove('hidden'); previewEl.classList.add('hidden'); }}
    function showPreview() {{ previewEl.classList.remove('hidden'); bodyEl.classList.add('hidden'); }}
    document.getElementById('edit-tab').addEventListener('click', showEdit);
    document.getElementById('preview-tab').addEventListener('click', showPreview);
    document.getElementById('save').addEventListener('click', async () => {{
      setStatus('Saving…');
      const response = await fetch('/present/' + encodeURIComponent(INITIAL.token) + '/edit', {{
        method: 'POST',
        headers: {{'content-type': 'application/json'}},
        body: JSON.stringify({{body: bodyEl.value, base_version: baseVersion, editor_name: nameEl.value || null}})
      }});
      const payload = await response.json().catch(() => ({{}}));
      if (response.status === 409) {{
        const latest = payload.detail || payload;
        setStatus('A newer version is available. Review the latest text below and reconcile your edits before saving.');
        bodyEl.value = latest.body || '';
        renderLivePreview();
        baseVersion = latest.version_number || baseVersion;
        metaEl.textContent = 'Version ' + baseVersion;
        dirty = false;
        showEdit();
        return;
      }}
      if (!response.ok) {{ setStatus('Save failed. The link may be expired or revoked.'); return; }}
      baseVersion = payload.version_number;
      metaEl.textContent = 'Version ' + baseVersion;
      dirty = false;
      setStatus('Saved version ' + baseVersion + '. Refresh to see the rendered preview.');
    }});
    async function pollState() {{
      const response = await fetch('/present/' + encodeURIComponent(INITIAL.token) + '/state');
      if (!response.ok) {{ setStatus('This edit link is no longer available.'); return; }}
      const state = await response.json();
      if (state.version_number > baseVersion) {{
        setStatus(dirty ? 'A newer version is available; save will ask you to reconcile.' : 'A newer version is available. Refresh to load it.');
      }}
    }}
    window.setInterval(pollState, 4000);
  </script>
</body>
</html>"""

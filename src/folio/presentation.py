from __future__ import annotations

import re
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


def _safe_image_src(src: str, *, public_origin: str | None, allowed_asset_ids: set[UUID]) -> str | None:
    if public_origin is None or not allowed_asset_ids:
        return None
    candidate = src.strip()
    if not candidate:
        return None

    origin = urlparse(public_origin.rstrip("/"))
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != origin.scheme or parsed.netloc != origin.netloc:
            return None
    path = parsed.path
    if parsed.params or parsed.query or parsed.fragment:
        return None

    match = _ASSET_PATH_RE.fullmatch(path)
    if match is None:
        return None
    try:
        asset_id = UUID(match.group(1))
    except ValueError:
        return None
    if asset_id not in allowed_asset_ids:
        return None
    return candidate


def render_presented_markdown(
    body: str,
    *,
    public_origin: str | None = None,
    allowed_asset_ids: set[UUID] | None = None,
) -> str:
    """Render Markdown to sanitized HTML safe for unauthenticated public pages."""

    allowed_assets = set(allowed_asset_ids or set())

    def attribute_filter(tag: str, attribute: str, value: str) -> str | None:
        if tag == "img" and attribute == "src":
            return _safe_image_src(value, public_origin=public_origin, allowed_asset_ids=allowed_assets)
        return value

    unsafe_html = markdown.markdown(
        body,
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
    return _IMG_WITHOUT_SRC_RE.sub("", sanitized)


def render_presented_page(
    *,
    body: str,
    theme: dict[str, Any] | None = None,
    public_origin: str | None = None,
    allowed_asset_ids: set[UUID] | None = None,
) -> str:
    content = render_presented_markdown(body, public_origin=public_origin, allowed_asset_ids=allowed_asset_ids)
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

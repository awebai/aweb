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
    "div",
    "em",
    "figcaption",
    "figure",
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
    "img": {"src", "alt", "title", "class", "loading", "width", "height", "fetchpriority"},
    "th": {"align"},
    "td": {"align"},
    "figure": {"class"},
    "figcaption": set(),
    "div": {"class"},
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
_NAMED_COLOR_RGB = {
    "black": (0, 0, 0),
    "white": (255, 255, 255),
    "red": (255, 0, 0),
    "green": (0, 128, 0),
    "blue": (0, 0, 255),
    "navy": (0, 0, 128),
    "orange": (255, 165, 0),
    "purple": (128, 0, 128),
    "pink": (255, 192, 203),
    "yellow": (255, 255, 0),
    "gray": (128, 128, 128),
    "grey": (128, 128, 128),
}
_WCAG_AA_NORMAL = 4.5
_LAYOUT_MODES = {"document", "presentation"}
_LAYOUT_MEASURES = {"narrow", "default", "wide"}
_LAYOUT_COLOR_SCHEMES = {"light", "dark", "auto"}
_LAYOUT_DEFAULTS = {"mode": "document", "measure": "default", "color_scheme": "light"}
_LAYOUT_ALLOWED = {
    "mode": _LAYOUT_MODES,
    "measure": _LAYOUT_MEASURES,
    "color_scheme": _LAYOUT_COLOR_SCHEMES,
}
_COLOR_SCHEME_META = {"light": "light", "dark": "dark", "auto": "light dark"}
_LIGHT_PALETTE = {
    "--bg": "#f8fafc",
    "--surface": "#ffffff",
    "--text": "#111827",
    "--muted": "#4b5563",
    "--border": "#e5e7eb",
    "--accent": "#2563eb",
    "--code-bg": "#f3f4f6",
}
_DARK_PALETTE = {
    "--bg": "#0b1220",
    "--surface": "#111827",
    "--text": "#f3f4f6",
    "--muted": "#9ca3af",
    "--border": "#1f2937",
    "--accent": "#60a5fa",
    "--code-bg": "#1f2937",
}
_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_RGB_COLOR_RE = re.compile(r"^rgba?\(([^)]+)\)$", re.IGNORECASE)
_ASSET_PATH_RE = re.compile(r"^/assets/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
_IMG_WITHOUT_SRC_RE = re.compile(r"<img\b(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)
_MARKDOWN_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_MEDIA_IMAGE_PLACEMENTS = {"block", "wrap-left", "wrap-right", "full-width", "full-bleed"}
_MEDIA_FULL_PLACEMENTS = {"full-width", "full-bleed"}
_MEDIA_SIZES = {"w-quarter", "w-third", "w-half", "w-two-thirds"}
_GALLERY_PLACEMENTS = {"gallery-2", "gallery-3"}
_GALLERY_ITEM_RE = re.compile(r'^(\S+)(?:\s+"([^"]*)")?$')
_MEDIA_RE = re.compile(
    r"(?P<block>^:::(?P<kind>media|gallery)[ \t]*\n.*?\n:::[ \t]*$)"
    r"|(?P<image>!\[(?P<alt>[^\]]*)\]\((?P<src>[^)\s]+)\))",
    re.DOTALL | re.MULTILINE,
)


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


def _parse_color_rgb(value: str) -> tuple[int, int, int] | None:
    candidate = value.strip().lower()
    if candidate == "transparent":
        return None
    if candidate in _NAMED_COLOR_RGB:
        return _NAMED_COLOR_RGB[candidate]
    if _HEX_COLOR_RE.fullmatch(candidate):
        digits = candidate[1:]
        if len(digits) == 3:
            digits = "".join(channel * 2 for channel in digits)
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16))
    match = _RGB_COLOR_RE.fullmatch(candidate)
    if match:
        parts = [part.strip() for part in match.group(1).split(",")]
        try:
            channels = tuple(int(parts[index]) for index in range(3))
        except (ValueError, IndexError):
            return None
        if all(0 <= channel <= 255 for channel in channels):
            return channels  # type: ignore[return-value]
    return None


def _relative_luminance(rgb: tuple[int, int, int]) -> float:
    def linear(channel: int) -> float:
        srgb = channel / 255
        return srgb / 12.92 if srgb <= 0.03928 else ((srgb + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(channel) for channel in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(first: str, second: str) -> float | None:
    """WCAG contrast ratio between two colors, or None if either is unparseable."""
    rgb1 = _parse_color_rgb(first)
    rgb2 = _parse_color_rgb(second)
    if rgb1 is None or rgb2 is None:
        return None
    lum1 = _relative_luminance(rgb1)
    lum2 = _relative_luminance(rgb2)
    lighter, darker = max(lum1, lum2), min(lum1, lum2)
    return (lighter + 0.05) / (darker + 0.05)


def content_security_policy(*, mode: str, nonce: str | None, stream_host: str) -> str:
    """Security policy for a present page.

    Scripts are forbidden outright except the fixed fullscreen control on
    presentation pages, which is admitted only by its per-request nonce. Frames
    are limited to the Cloudflare Stream playback host so trusted video embeds load.
    """
    script_src = f"'nonce-{nonce}'" if mode == "presentation" and nonce else "'none'"
    frame_src = f"https://{stream_host}" if stream_host else "'none'"
    return "; ".join(
        [
            "default-src 'none'",
            "img-src 'self'",
            "style-src 'unsafe-inline'",
            f"script-src {script_src}",
            f"frame-src {frame_src}",
            "base-uri 'none'",
            "form-action 'none'",
        ]
    )


def _layout_subset(tokens: Any) -> dict[str, str]:
    """Only the layout values the team explicitly set that pass the allowlist."""
    raw = tokens.get("layout") if isinstance(tokens, dict) else None
    subset: dict[str, str] = {}
    if isinstance(raw, dict):
        for key, allowed in _LAYOUT_ALLOWED.items():
            value = raw.get(key)
            if isinstance(value, str) and value.strip().lower() in allowed:
                subset[key] = value.strip().lower()
    return subset


def sanitize_layout_tokens(tokens: Any) -> dict[str, str]:
    """Resolve the layout token group to a complete set of allowlisted enum values.

    Every key is always present; unknown or malformed values fall back to the
    default so a token can never escape into the emitted CSS.
    """
    return {**_LAYOUT_DEFAULTS, **_layout_subset(tokens)}


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

    layout = _layout_subset(tokens)
    if layout:
        sanitized["layout"] = layout

    return sanitized


def theme_contrast_error(tokens: Any) -> str | None:
    """Reject a theme whose body text would fail WCAG AA against its surface.

    Colors fall back to the palette of the chosen scheme, so a default theme
    always passes and only an explicit unreadable override is flagged.
    """
    colors = sanitize_theme_tokens(tokens).get("colors", {})
    palette = _DARK_PALETTE if sanitize_layout_tokens(tokens)["color_scheme"] == "dark" else _LIGHT_PALETTE
    text = colors.get("text") or palette["--text"]
    surface = colors.get("surface") or palette["--surface"]
    ratio = contrast_ratio(text, surface)
    if ratio is not None and ratio < _WCAG_AA_NORMAL:
        return f"Theme text/surface contrast {ratio:.2f}:1 is below the WCAG AA minimum of {_WCAG_AA_NORMAL}:1."
    return None


def _palette_declarations(palette: dict[str, str], indent: str) -> str:
    return "\n".join(f"{indent}{name}: {value};" for name, value in palette.items())


def _root_css(layout: dict[str, str], theme_css: str) -> str:
    """Build the :root block: color-scheme, the scheme's palette, a dark media
    query for ``auto``, and theme color/font overrides applied last so they win.
    """
    scheme = layout["color_scheme"]
    base = _DARK_PALETTE if scheme == "dark" else _LIGHT_PALETTE
    block = f""":root {{
      color-scheme: {_COLOR_SCHEME_META[scheme]};
{_palette_declarations(base, "      ")}
      --font-body: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --font-heading: var(--font-body);
    }}"""
    if scheme == "auto":
        block += (
            "\n    @media (prefers-color-scheme: dark) {\n      :root {\n"
            + _palette_declarations(_DARK_PALETTE, "        ")
            + "\n      }\n    }"
        )
    if theme_css:
        block += f"\n    :root {{{theme_css}    }}"
    return block


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


def _media_img_tag(src: str, alt: str, state: dict[str, bool]) -> str:
    attrs = ['class="folio-img"', f'src="{escape(src, quote=True)}"', f'alt="{escape(alt, quote=True)}"']
    if state["first"]:
        attrs.append('fetchpriority="high"')
        state["first"] = False
    else:
        attrs.append('loading="lazy"')
    return f"<img {' '.join(attrs)}>"


def _parse_directive_fields(block: str) -> tuple[dict[str, str], list[str]]:
    lines = block.splitlines()
    inner = lines[1:-1] if len(lines) >= 2 else []
    fields: dict[str, str] = {}
    items: list[str] = []
    for line in inner:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("- "):
            items.append(stripped[2:].strip())
        elif ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip().lower()] = value.strip()
    return fields, items


def _render_image_directive(
    fields: dict[str, str], public_origin: str | None, image_asset_ids: set[UUID], state: dict[str, bool]
) -> str:
    safe = _safe_image_src(fields.get("src", ""), public_origin=public_origin, image_asset_ids=image_asset_ids)
    if safe is None:
        return ""
    placement = fields.get("placement", "block").strip().lower()
    if placement not in _MEDIA_IMAGE_PLACEMENTS:
        placement = "block"
    classes = ["folio-media", f"folio-{placement}"]
    size = fields.get("size", "").strip().lower()
    if size in _MEDIA_SIZES and placement not in _MEDIA_FULL_PLACEMENTS:
        classes.append(f"folio-{size}")
    img = _media_img_tag(safe, fields.get("alt", ""), state)
    caption = fields.get("caption")
    figcaption = f"\n  <figcaption>{escape(caption)}</figcaption>" if caption else ""
    return f'\n<figure class="{" ".join(classes)}">\n  {img}{figcaption}\n</figure>\n'


def _render_gallery_directive(
    fields: dict[str, str],
    items: list[str],
    public_origin: str | None,
    image_asset_ids: set[UUID],
    state: dict[str, bool],
) -> str:
    placement = fields.get("placement", "gallery-2").strip().lower()
    if placement not in _GALLERY_PLACEMENTS:
        placement = "gallery-2"
    cells: list[str] = []
    for raw_item in items:
        match = _GALLERY_ITEM_RE.match(raw_item.strip())
        if match is None:
            continue
        safe = _safe_image_src(match.group(1), public_origin=public_origin, image_asset_ids=image_asset_ids)
        if safe is None:
            continue
        img = _media_img_tag(safe, match.group(2) or "", state)
        cells.append(f'    <div class="folio-gallery-item">{img}</div>')
    if not cells:
        return ""
    caption = fields.get("caption")
    figcaption = f"\n  <figcaption>{escape(caption)}</figcaption>" if caption else ""
    grid = "\n".join(cells)
    return (
        f'\n<figure class="folio-media folio-{placement}">\n'
        f'  <div class="folio-gallery-grid">\n{grid}\n  </div>{figcaption}\n</figure>\n'
    )


def _preprocess_media(body: str, *, public_origin: str | None, image_asset_ids: set[UUID]) -> str:
    """Replace :::media / :::gallery directives and bare asset images with
    allowlisted figure HTML.

    Runs after the video replacer (so video refs are already tokens) and before
    Markdown; the emitted HTML carries only fixed folio-* classes, and nh3 still
    re-validates every image source afterwards.
    """
    state = {"first": True}

    def replace(match: re.Match[str]) -> str:
        if match.group("block") is not None:
            kind = match.group("kind")
            fields, items = _parse_directive_fields(match.group("block"))
            if kind == "media":
                return _render_image_directive(fields, public_origin, image_asset_ids, state)
            return _render_gallery_directive(fields, items, public_origin, image_asset_ids, state)
        safe = _safe_image_src(match.group("src"), public_origin=public_origin, image_asset_ids=image_asset_ids)
        if safe is None:
            return match.group(0)
        img = _media_img_tag(safe, match.group("alt"), state)
        return f'\n<figure class="folio-media folio-full-width">\n  {img}\n</figure>\n'

    return _MEDIA_RE.sub(replace, body)


def _fullscreen_control(nonce: str) -> str:
    return (
        '  <button type="button" class="folio-fullscreen" id="folio-fullscreen" '
        'aria-label="Toggle full screen">⛶</button>\n'
        f'  <script nonce="{escape(nonce, quote=True)}">\n'
        "    (function () {\n"
        "      var btn = document.getElementById('folio-fullscreen');\n"
        "      if (!btn || !document.documentElement.requestFullscreen) { if (btn) { btn.hidden = true; } return; }\n"
        "      btn.addEventListener('click', function () {\n"
        "        if (document.fullscreenElement) { document.exitFullscreen(); }\n"
        "        else { document.documentElement.requestFullscreen(); }\n"
        "      });\n"
        "    })();\n"
        "  </script>\n"
    )


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
    preprocessed_body = _preprocess_media(
        preprocessed_body, public_origin=public_origin, image_asset_ids=image_asset_ids
    )

    def attribute_filter(tag: str, attribute: str, value: str) -> str | None:
        if attribute == "class":
            kept = " ".join(token for token in value.split() if token.startswith("folio-"))
            return kept or None
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
    nonce: str | None = None,
) -> str:
    content = render_presented_markdown(
        body,
        public_origin=public_origin,
        allowed_asset_ids=allowed_asset_ids,
        asset_embeds=asset_embeds,
    )
    tokens = (theme or {}).get("tokens")
    safe_tokens = sanitize_theme_tokens(tokens)
    theme_css = _theme_css(safe_tokens)
    layout = sanitize_layout_tokens(tokens)
    root_css = _root_css(layout, theme_css)
    body_class = f"folio-layout-{layout['mode']} folio-measure-{layout['measure']}"
    color_scheme_meta = _COLOR_SCHEME_META[layout["color_scheme"]]
    fullscreen_html = _fullscreen_control(nonce) if layout["mode"] == "presentation" and nonce else ""
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
  <meta name="color-scheme" content="{color_scheme_meta}">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>{title}</title>
  <style>
    {root_css}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-body);
      line-height: 1.6;
    }}
    .folio-measure-narrow {{ --measure: 58ch; }}
    .folio-measure-default {{ --measure: 68ch; }}
    .folio-measure-wide {{ --measure: 82ch; }}
    .folio-layout-presentation.folio-measure-narrow {{ --measure: 960px; }}
    .folio-layout-presentation.folio-measure-default {{ --measure: 1200px; }}
    .folio-layout-presentation.folio-measure-wide {{ --measure: 1400px; }}
    .page {{
      max-width: var(--measure);
      margin: 0 auto;
      padding: 48px 20px;
    }}
    .folio-layout-presentation {{ font-size: 1.2rem; }}
    .folio-layout-presentation .page {{ padding: 4vh 24px; }}
    .folio-layout-presentation .document-body h1 {{ font-size: 2.6rem; }}
    .folio-layout-presentation .document-body h2 {{ font-size: 1.9rem; }}
    .folio-fullscreen {{
      position: fixed;
      top: 16px;
      right: 16px;
      z-index: 10;
      width: 40px;
      height: 40px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text);
      font-size: 18px;
      line-height: 1;
      cursor: pointer;
      opacity: 0.7;
    }}
    .folio-fullscreen:hover {{ opacity: 1; }}
    .surface {{
      --surface-pad: clamp(24px, 5vw, 56px);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 20px 45px rgba(15, 23, 42, 0.08);
      padding: var(--surface-pad);
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
      background: var(--code-bg);
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
    .folio-media {{ margin: 1.5em 0; }}
    .folio-img {{ display: block; width: 100%; height: auto; border-radius: 6px; }}
    .folio-media figcaption {{ font-size: 0.875em; color: var(--muted); margin-top: 0.5em; line-height: 1.4; }}
    .folio-block.folio-w-quarter {{ max-width: 25%; margin-inline: auto; }}
    .folio-block.folio-w-third {{ max-width: 33.33%; margin-inline: auto; }}
    .folio-block.folio-w-half {{ max-width: 50%; margin-inline: auto; }}
    .folio-block.folio-w-two-thirds {{ max-width: 66.66%; margin-inline: auto; }}
    .folio-wrap-left {{ float: left; width: 33.33%; margin: 0.25em 1.5em 1em 0; clear: left; }}
    .folio-wrap-right {{ float: right; width: 33.33%; margin: 0.25em 0 1em 1.5em; clear: right; }}
    .folio-wrap-left.folio-w-quarter, .folio-wrap-right.folio-w-quarter {{ width: 25%; }}
    .folio-wrap-left.folio-w-half, .folio-wrap-right.folio-w-half {{ width: 50%; }}
    .folio-wrap-left.folio-w-two-thirds, .folio-wrap-right.folio-w-two-thirds {{ width: 66.66%; }}
    .document-body p::after, .document-body section::after {{ content: ""; display: table; clear: both; }}
    .folio-full-width .folio-img {{ max-height: 80vh; object-fit: contain; }}
    .folio-full-bleed {{
      margin-inline: calc(-1 * var(--surface-pad));
      width: calc(100% + 2 * var(--surface-pad));
      max-width: none;
    }}
    .folio-full-bleed .folio-img {{ border-radius: 0; max-height: 90vh; }}
    .folio-layout-presentation .folio-full-bleed {{ margin-inline: calc((100% - 100vw) / 2); width: 100vw; }}
    .folio-gallery-grid {{ display: grid; gap: 0.75em; }}
    .folio-gallery-2 .folio-gallery-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .folio-gallery-3 .folio-gallery-grid {{ grid-template-columns: repeat(3, 1fr); }}
    .folio-gallery-item .folio-img {{ height: 200px; object-fit: cover; border-radius: 4px; }}
    @media (max-width: 768px) {{
      .folio-gallery-3 .folio-gallery-grid {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    @media (max-width: 480px) {{
      .folio-wrap-left, .folio-wrap-right {{ float: none; width: 100%; margin-inline: 0; }}
      .folio-block.folio-w-quarter, .folio-block.folio-w-third,
      .folio-block.folio-w-half, .folio-block.folio-w-two-thirds {{ max-width: 100%; }}
      .folio-gallery-2 .folio-gallery-grid, .folio-gallery-3 .folio-gallery-grid {{ grid-template-columns: 1fr; }}
    }}
    @media print {{
      .folio-fullscreen {{ display: none; }}
      body {{ background: #ffffff; color: #111827; }}
      .surface {{ border: none; box-shadow: none; border-radius: 0; padding: 0; }}
      .folio-wrap-left, .folio-wrap-right {{ float: none; width: 100%; }}
      .folio-full-bleed {{ margin-inline: 0; width: 100%; }}
      .folio-gallery-item .folio-img {{ height: auto; object-fit: contain; }}
    }}
  </style>
</head>
<body class="{body_class}">
  <main class="page">
    <article class="surface">
{logo_html}      <p class="eyebrow">Presented with folio</p>
{header_html}      <div class="document-body">
{content}
      </div>
{footer_html}    </article>
  </main>
{fullscreen_html}</body>
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

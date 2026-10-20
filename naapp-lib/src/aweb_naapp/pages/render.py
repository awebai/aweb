"""Shared renderer hosting helpers. No application routes or authority live here."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from html import escape
from urllib.parse import urlsplit


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or re.search(r"[\s;'<>\\]", value)
    ):
        raise ValueError("An HTTPS origin without a path is required")
    return value


@dataclass(frozen=True)
class PageShell:
    html: str
    headers: dict[str, str]


def page_shell(*, script_path: str, asset_origin: str) -> PageShell:
    """Host shell with independent chrome. script_path is trusted packaged host code.

    Hosts serve the packaged pages/assets/page-renderer.js and page-renderer.css;
    their own external entry module fetches an authorized, validated snapshot and
    mounts it. The asset origin is pinned installation metadata, never page data.
    """
    if not re.fullmatch(r"/[A-Za-z0-9_/-]+\.m?js", script_path):
        raise ValueError("A same-origin packaged script path is required")
    asset_origin = _origin(asset_origin)
    nonce = secrets.token_urlsafe(24)
    language = "en"
    headers = {
        "Content-Security-Policy": "; ".join(
            [
                "default-src 'none'",
                f"script-src 'nonce-{nonce}' 'strict-dynamic'",
                "style-src 'self'",
                "connect-src 'self'",
                f"img-src {asset_origin}",
                f"media-src {asset_origin}",
                "font-src 'self'",
                "object-src 'none'",
                "base-uri 'none'",
                "form-action 'none'",
                "frame-ancestors 'none'",
                "require-trusted-types-for 'script'",
                "trusted-types dompurify",
            ]
        ),
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
    html = f'''<!doctype html>
<html lang="{language}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pages · aweb</title><link rel="stylesheet" href="/assets/page-renderer.css">
<script type="module" nonce="{nonce}" src="{escape(script_path, quote=True)}"></script>
</head><body><a class="skip-link" href="#page">Skip to content</a>
<header class="host-chrome"><span class="brand">aweb <span>Pages</span></span><div id="identity"></div></header>
<main><div id="page" tabindex="-1"></div></main>
<aside id="destinations" class="host-chrome" aria-label="Destinations"></aside>
<dialog id="link-confirmation" class="link-confirmation"></dialog>
<div id="announcements" class="sr-only" role="status" aria-live="polite"></div>
</body></html>'''
    return PageShell(html, headers)

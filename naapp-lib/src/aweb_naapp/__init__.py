"""aweb-naapp — the reusable Native Agentic App docs surface.

An app supplies its canonical manifest, a :class:`SiteConfig` (brand, nav,
footer), and its own landing body, and gets the whole standard surface: the
aweb design system, the shared chrome, the manifest-driven llms.txt blocks, and
the /reference page with the honest team-cert v2 envelope.
"""

from __future__ import annotations

from aweb_naapp import llms, manifest
from aweb_naapp.chrome import (
    COPY_BTN,
    FooterColumn,
    NavLink,
    SiteConfig,
    page,
    render_footer,
    render_head,
    render_header,
    render_scripts,
)
from aweb_naapp.css import (
    CSS_SHA256,
    VENDORED_AWEB_CSS_SHA256,
    aweb_css,
    aweb_css_sha256,
    naapp_components_css,
    vendored_aweb_css,
    vendored_aweb_css_sha256,
)
from aweb_naapp.reference import VECTOR_URL, ReferenceCopy, render_reference

__all__ = [
    "llms",
    "manifest",
    "COPY_BTN",
    "FooterColumn",
    "NavLink",
    "SiteConfig",
    "page",
    "render_footer",
    "render_head",
    "render_header",
    "render_scripts",
    "CSS_SHA256",
    "VENDORED_AWEB_CSS_SHA256",
    "aweb_css",
    "aweb_css_sha256",
    "naapp_components_css",
    "vendored_aweb_css",
    "vendored_aweb_css_sha256",
    "VECTOR_URL",
    "ReferenceCopy",
    "render_reference",
]

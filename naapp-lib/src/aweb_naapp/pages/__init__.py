"""Validation of aweb.page/1 page snapshots (docs/page-format.md).

Three layers run in order and stop at the first that fails: host limits, then
the JSON Schema, then semantic lint. Limits are checked iteratively before any
recursive validator sees the page, so a hostile tree cannot exhaust it, and
lint only runs on a structurally valid page. Every error names its layer, a
stable code and the JSON pointer of the offending value. No I/O.

Requires the `pages` extra (jsonschema).
"""

from __future__ import annotations

from aweb_naapp.pages.lint import bundle_sha256, proposal_sha256
from aweb_naapp.pages.text import PageLint, lint_page
from aweb_naapp.pages.validation import (
    PAGE_LIMITS,
    PAGE_SCHEMA,
    PageError,
    Validation,
    validate_page,
    validate_page_bytes,
)

__all__ = [
    "PAGE_LIMITS",
    "PAGE_SCHEMA",
    "PageError",
    "PageLint",
    "lint_page",
    "Validation",
    "bundle_sha256",
    "proposal_sha256",
    "validate_page",
    "validate_page_bytes",
]

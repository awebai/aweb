"""Two-layer CSS bundle for Native Agentic App surfaces.

Layer 1 is ``assets/aweb.css``: the shared aweb design system, vendored
byte-for-byte from the design system's source stylesheet and checked by its own
hash.

Layer 2 is ``assets/naapp-components.css``: selectors emitted only by the
``aweb-naapp`` chrome/reference renderers. Apps serve the concatenated bundle at
``/css/aweb.<hash>.css``; the public ``CSS_SHA256`` fingerprints that full served
bundle, not the vendored SOT file alone.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

_ASSETS_DIR = Path(__file__).resolve().parent / "assets"

# Only redistributable, licensed fonts bundled with the toolkit are served.
FONT_NAMES = frozenset({"Archivo-Latin-Variable.woff2"})


def font_bytes(name: str) -> bytes | None:
    """Return a bundled font by its allowlisted name, never an arbitrary path."""
    if name not in FONT_NAMES:
        return None
    return (_ASSETS_DIR / "fonts" / name).read_bytes()


# Hash of layer 1 only: the vendored design-system stylesheet at
# src/aweb_naapp/assets/aweb.css. This must stay byte-identical to the design
# system's source stylesheet and is intentionally separate from CSS_SHA256.
VENDORED_AWEB_CSS_SHA256 = "1a529122adb1641f6029db84eaf791616c1c4b8ba505ae42fb0426490af9895c"


@lru_cache(maxsize=1)
def vendored_aweb_css() -> str:
    return (_ASSETS_DIR / "aweb.css").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def naapp_components_css() -> str:
    return (_ASSETS_DIR / "naapp-components.css").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def aweb_css() -> str:
    return f"{vendored_aweb_css()}\n{naapp_components_css()}"


# Hash of the served two-layer bundle: vendored aweb.css plus the naapp component
# layer. This is the fingerprint used by all app chrome and downstream CSS URLs.
CSS_SHA256 = hashlib.sha256(aweb_css().encode("utf-8")).hexdigest()


def aweb_css_sha256() -> str:
    return hashlib.sha256(aweb_css().encode("utf-8")).hexdigest()


def vendored_aweb_css_sha256() -> str:
    return hashlib.sha256(vendored_aweb_css().encode("utf-8")).hexdigest()

"""Two-layer CSS bundle for Native Agentic App surfaces.

Layer 1 is ``assets/aweb.css``: the shared aweb design system, vendored
byte-for-byte from the ac site SOT and checked by its own hash.

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

# Hash of layer 1 only: the vendored ac SOT stylesheet at
# src/aweb_naapp/assets/aweb.css. This must stay byte-identical to
# ac/site/static/css/aweb.css and is intentionally separate from CSS_SHA256.
VENDORED_AWEB_CSS_SHA256 = "98d1f6af14a6ff47f25f1eae6e727c3aafa498c16736cef84dab782b1d5e5642"


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

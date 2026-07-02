"""The aweb design system (Paper/Clay), vendored verbatim and sha-pinned.

Every naapp serves the exact same stylesheet so the surfaces look identical. The
sha is asserted by a test; serve the bytes at /css/aweb.css.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

_ASSETS_DIR = Path(__file__).resolve().parent / "assets"

# sha256 of the vendored stylesheet, byte-for-byte from the awebai/ac repo
# (site/static/css/aweb.css).
CSS_SHA256 = "98d1f6af14a6ff47f25f1eae6e727c3aafa498c16736cef84dab782b1d5e5642"


@lru_cache(maxsize=1)
def aweb_css() -> str:
    return (_ASSETS_DIR / "aweb.css").read_text(encoding="utf-8")


def aweb_css_sha256() -> str:
    return hashlib.sha256(aweb_css().encode("utf-8")).hexdigest()

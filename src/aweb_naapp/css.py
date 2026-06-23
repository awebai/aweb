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
CSS_SHA256 = "9c31ca3ad954239cee068051a1b7b21216e0520e7873741ecdd29220e5bfcf3b"


@lru_cache(maxsize=1)
def aweb_css() -> str:
    return (_ASSETS_DIR / "aweb.css").read_text(encoding="utf-8")


def aweb_css_sha256() -> str:
    return hashlib.sha256(aweb_css().encode("utf-8")).hexdigest()

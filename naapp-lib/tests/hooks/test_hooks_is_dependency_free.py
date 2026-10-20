"""The hook catalog imports with the standard library alone, so core can use it."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
HEAVY = (
    "awid",
    "fastapi",
    "httpx",
    "nacl",
    "pgdbm",
    "pydantic",
    "pydantic_settings",
    "starlette",
    "webauthn",
    "aweb_naapp.runtime",
)


def test_hook_catalog_loads_no_runtime_dependency() -> None:
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import aweb_naapp.hooks.catalog\n"
        f"print(','.join(m for m in {HEAVY!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == ""

"""The email sender imports with the standard library alone."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
HEAVY = (
    "fastapi",
    "httpx",
    "nacl",
    "pgdbm",
    "pydantic_settings",
    "starlette",
    "webauthn",
    "aweb_naapp.runtime",
)


def test_email_loads_no_dependency() -> None:
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import aweb_naapp.email\n"
        f"print(','.join(m for m in {HEAVY!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == ""

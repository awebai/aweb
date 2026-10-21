"""The egress guard imports without the naapp runtime or the outbox."""

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
    "pydantic",
    "pydantic_settings",
    "starlette",
    "webauthn",
    "aweb_naapp.runtime",
    "aweb_naapp.outbox",
)


def test_egress_loads_no_runtime_dependency() -> None:
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import aweb_naapp.egress\n"
        f"print(','.join(m for m in {HEAVY!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == ""

"""The docs surface imports with the standard library alone."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
RUNTIME_MODULES = ("awid", "fastapi", "httpx", "nacl", "pgdbm", "pydantic", "starlette", "webauthn")


def test_docs_surface_loads_no_runtime_dependency():
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import aweb_naapp\n"
        f"print(','.join(m for m in {RUNTIME_MODULES!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == ""

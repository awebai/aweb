"""The hooks package stays light enough for the core server to share.

The catalog reader needs the standard library alone. The envelope and the
delivery credential add only Ed25519 and did:key (pynacl and awid), never the
naapp runtime, its web framework, its settings or a database.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
RUNTIME = (
    "fastapi",
    "httpx",
    "pgdbm",
    "pydantic",
    "pydantic_settings",
    "starlette",
    "webauthn",
    "aweb_naapp.runtime",
)


def _loaded(module: str, names: tuple[str, ...]) -> str:
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        f"import {module}\n"
        f"print(','.join(m for m in {names!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def test_hook_catalog_loads_the_standard_library_alone() -> None:
    assert _loaded("aweb_naapp.hooks.catalog", RUNTIME + ("awid", "nacl")) == ""


def test_envelope_and_delivery_load_no_runtime_dependency() -> None:
    assert _loaded("aweb_naapp.hooks.delivery", RUNTIME) == ""

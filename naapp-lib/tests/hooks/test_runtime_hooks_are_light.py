"""The producer-side hooks stay light enough for any naapp to embed.

The commitment helper needs only the key-file reader, the producer adds the
durable outbox and the transport the egress guard: none of them loads the
naapp runtime, its web framework or its settings.
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


def test_commitment_helper_loads_no_runtime_or_awid() -> None:
    assert _loaded("aweb_naapp.hooks.commitment", RUNTIME + ("awid", "nacl")) == ""


def test_the_producer_loads_only_the_outbox_beyond_the_envelope() -> None:
    # The outbox's pgdbm brings pydantic with it; nothing else may load.
    allowed = ("pgdbm", "pydantic")
    assert _loaded("aweb_naapp.hooks.producer", tuple(m for m in RUNTIME if m not in allowed)) == ""


def test_the_transport_loads_the_egress_guard_and_no_runtime() -> None:
    allowed = ("pgdbm", "pydantic")
    assert (
        _loaded("aweb_naapp.hooks.transport", tuple(m for m in RUNTIME if m not in allowed)) == ""
    )

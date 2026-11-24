"""The task-request contract stays light enough for the core server to share.

Task authorizations, stage receipts and answer digests need awid and pynacl
alone, never the rest of the naapp runtime, its web framework, its settings or
a database.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"


def test_task_requests_load_no_other_runtime_module_or_dependency() -> None:
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import aweb_naapp.runtime.task_requests\n"
        "names = ('fastapi', 'httpx', 'pgdbm', 'pydantic', 'pydantic_settings', "
        "'starlette', 'webauthn')\n"
        "loaded = [m for m in sys.modules if m in names or "
        "(m.startswith('aweb_naapp.runtime.') and m != 'aweb_naapp.runtime.task_requests')]\n"
        "print(','.join(sorted(loaded)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == ""

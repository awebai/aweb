"""Local operator preflight; no service contact, credential opening or job spawn."""

from pathlib import Path
from typing import Any

from .errors import Refused
from .jobs import RunnerConfig
from .journal import Journal
from .state import IdentityStore


def doctor(config_file: Path, state_dir: Path) -> dict[str, Any]:
    identity = IdentityStore(state_dir).load()
    if identity.runner_id is None or identity.service_kid is None:
        raise Refused("runner_unregistered")
    jobs = RunnerConfig.load(config_file).doctor(identity.runner_id)
    Journal(state_dir / "journal.sqlite3")
    return {"runner_id": identity.runner_id, "jobs": list(jobs)}

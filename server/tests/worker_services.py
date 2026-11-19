"""Fixed, owned services for the opt-in seven-worker server experiment."""

from __future__ import annotations

import re
from collections.abc import MutableMapping

WORKERS = 7


def service_plan(workers: int) -> list[dict]:
    if workers not in (0, WORKERS):
        raise ValueError("server workers must be 0 or 7")
    return [
        {
            "worker": f"gw{index}",
            "postgres_port": 5432 + index,
            "redis_port": 6379 + index,
        }
        for index in range(workers or 1)
    ]


def configure_worker_environment(environ: MutableMapping[str, str]) -> None:
    """Run before fixture/plugin imports which capture service environment."""
    worker = environ.get("PYTEST_XDIST_WORKER")
    if worker is None:
        return
    if (
        environ.get("AWEB_SERVER_TEST_WORKERS") != str(WORKERS)
        or environ.get("PYTEST_XDIST_WORKER_COUNT") != str(WORKERS)
        or re.fullmatch(r"gw[0-6]", worker) is None
    ):
        raise RuntimeError(
            "parallel server tests require the owned seven-worker service plan"
        )
    services = service_plan(WORKERS)[int(worker[2:])]
    environ["PGHOST"] = environ["TEST_DB_HOST"] = "127.0.0.1"
    environ["PGPORT"] = environ["TEST_DB_PORT"] = str(services["postgres_port"])
    redis = f"redis://127.0.0.1:{services['redis_port']}/0"
    for name in ("REDIS_URL", "AWEB_REDIS_URL", "AWID_REDIS_URL"):
        environ[name] = redis

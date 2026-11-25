"""Bind server workers to their gate-owned or local disposable services."""

from __future__ import annotations

import json
import re
from collections.abc import MutableMapping

# The most workers one runner's port ranges hold: 5432+n stays below 6379.
MAX_WORKERS = 64
# Memory limits of one plan's services. The first pair also serves the serial
# suites; every further worker gets a smaller pair.
PRIMARY_POSTGRES_MIB = 2048
PRIMARY_REDIS_MIB = 1024
WORKER_POSTGRES_MIB = 1280
WORKER_REDIS_MIB = 128


def service_plan(workers: int) -> list[dict]:
    if type(workers) is not int or not 0 <= workers <= MAX_WORKERS or workers == 1:
        raise ValueError(f"server workers must be 0 or 2 to {MAX_WORKERS}")
    return [
        {
            "worker": f"gw{index}",
            "postgres_port": 5432 + index,
            "redis_port": 6379 + index,
        }
        for index in range(workers or 1)
    ]


def service_memory_mib(workers: int) -> int:
    """The memory limits of a plan's Postgres and Redis services together."""
    pairs = len(service_plan(workers))
    return (
        PRIMARY_POSTGRES_MIB
        + PRIMARY_REDIS_MIB
        + (pairs - 1) * (WORKER_POSTGRES_MIB + WORKER_REDIS_MIB)
    )


def configure_worker_environment(environ: MutableMapping[str, str]) -> None:
    """Run before fixture/plugin imports which capture service environment."""
    worker = environ.get("PYTEST_XDIST_WORKER")
    if worker is None:
        return
    if "AWEB_LOCAL_TEST_SERVICES" in environ:
        services = local_worker_service(environ)
        bind_service_environment(environ=environ, services=services)
        return
    planned = environ.get("AWEB_SERVER_TEST_WORKERS", "")
    match = re.fullmatch(r"gw([0-9]+)", worker)
    if (
        not re.fullmatch(r"[1-9][0-9]*", planned)
        or int(planned) < 2
        or int(planned) > MAX_WORKERS
        or environ.get("PYTEST_XDIST_WORKER_COUNT") != planned
        or match is None
        or int(match.group(1)) >= int(planned)
    ):
        raise RuntimeError(
            "parallel server tests require the owned worker service plan"
        )
    services = service_plan(int(planned))[int(match.group(1))]
    bind_service_environment(environ=environ, services=services)


def local_worker_service(environ: MutableMapping[str, str]) -> dict[str, int]:
    """Validate the per-run loopback plan before fixture imports (docs/local-server-tests.md, Guards and cleanup)."""
    recovery = "Re-run make test-server-local with LOCAL_TEST_WORKERS between 1 and 4."
    try:
        plan = json.loads(environ["AWEB_LOCAL_TEST_SERVICES"])
        count = int(environ["PYTEST_XDIST_WORKER_COUNT"])
        worker = environ["PYTEST_XDIST_WORKER"]
        if not isinstance(plan, list) or not 1 <= count <= 4 or len(plan) != count:
            raise ValueError("worker count differs from the service plan")
        if re.fullmatch(r"gw[0-3]", worker) is None or int(worker[2:]) >= count:
            raise ValueError("unknown local worker")
        ports = set()
        for row in plan:
            if not isinstance(row, dict) or set(row) != {"postgres_port", "redis_port"}:
                raise ValueError("invalid local service entry")
            for port in row.values():
                if (
                    type(port) is not int
                    or not 1 <= port <= 65535
                    or port == 5432
                    or port in ports
                ):
                    raise ValueError("unsafe or shared local service port")
                ports.add(port)
        return plan[int(worker[2:])]
    except (KeyError, ValueError, TypeError) as exc:
        raise RuntimeError("Invalid local worker services. " + recovery) from exc


def bind_service_environment(
    *, environ: MutableMapping[str, str], services: dict
) -> None:
    environ["PGHOST"] = environ["TEST_DB_HOST"] = "127.0.0.1"
    environ["PGPORT"] = environ["TEST_DB_PORT"] = str(services["postgres_port"])
    if "AWEB_LOCAL_TEST_SERVICES" in environ:
        environ["TEST_DATABASE_URL"] = (
            f"postgresql://postgres:postgres@127.0.0.1:{services['postgres_port']}/postgres"
        )
    redis = f"redis://127.0.0.1:{services['redis_port']}/0"
    for name in ("REDIS_URL", "AWEB_REDIS_URL", "AWID_REDIS_URL"):
        environ[name] = redis

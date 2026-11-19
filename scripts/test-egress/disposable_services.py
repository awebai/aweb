"""Disposable PostgreSQL and Redis for test fixtures the isolated runner does
not supply services to.

Each container takes a daemon-assigned loopback port and is removed, with its
anonymous volumes, on exit. PostgreSQL's data directory is on tmpfs, verified
rather than assumed.
"""

import subprocess
import sys
import time
from contextlib import contextmanager

POSTGRES_DATA = "/var/lib/postgresql/data"
READY_ATTEMPTS = 120
READY_INTERVAL = 0.25


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def remove_owned_containers(owned):
    # --rm removes anonymous volumes only when Docker itself removes the
    # container; an explicit removal must name -v to remove them.
    for container in reversed(owned):
        subprocess.run(
            ["docker", "rm", "-f", "-v", container], stdout=sys.stderr, check=True
        )


def start_container(owned, image, port, *options):
    container = run(
        "docker", "run", "-d", "--rm", "--cpus", "1", "--memory", "512m",
        "-p", f"127.0.0.1::{port}", *options, image,
    )  # fmt: skip
    owned.append(container)
    return container, run("docker", "port", container, str(port)).rsplit(":", 1)[1]


def wait_for_postgres(container):
    # Over TCP: the image's initialization server listens on its socket only,
    # so only the final server answers here.
    for _ in range(READY_ATTEMPTS):
        ready = subprocess.run(
            [
                "docker",
                "exec",
                container,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if ready.returncode == 0:
            return
        time.sleep(READY_INTERVAL)
    raise RuntimeError(
        f"PostgreSQL in {container} was not ready after "
        f"{READY_ATTEMPTS * READY_INTERVAL:.0f}s"
    )


def verify_postgres_on_tmpfs(container):
    data_directory = run(
        "docker", "exec", container,
        "psql", "-h", "127.0.0.1", "-U", "postgres", "-tAc", "SHOW data_directory",
    )  # fmt: skip
    mounts = run("docker", "exec", container, "cat", "/proc/mounts").splitlines()
    tmpfs = {fields[1] for fields in map(str.split, mounts) if fields[2] == "tmpfs"}
    if data_directory != POSTGRES_DATA or POSTGRES_DATA not in tmpfs:
        raise RuntimeError(
            f"PostgreSQL data directory {data_directory!r} is not on tmpfs "
            f"(tmpfs mounts: {sorted(tmpfs)})"
        )


@contextmanager
def disposable_postgres_and_redis():
    """Yield PG*/REDIS_URL settings for containers removed on exit."""
    owned = []
    try:
        postgres, postgres_port = start_container(
            owned, "postgres:17", 5432,
            "-e", "POSTGRES_PASSWORD=postgres", "--tmpfs", POSTGRES_DATA,
        )  # fmt: skip
        _, redis_port = start_container(owned, "redis:7", 6379)
        wait_for_postgres(postgres)
        verify_postgres_on_tmpfs(postgres)
        yield {
            "PGHOST": "127.0.0.1",
            "PGPORT": postgres_port,
            "PGUSER": "postgres",
            "PGPASSWORD": "postgres",
            "REDIS_URL": f"redis://127.0.0.1:{redis_port}/0",
        }
    finally:
        remove_owned_containers(owned)

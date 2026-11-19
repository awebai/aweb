"""Disposable PostgreSQL and Redis for test fixtures the isolated runner does
not supply services to.

Each container takes a daemon-assigned loopback port and is removed, with its
anonymous volumes, on exit. PostgreSQL's data directory is on tmpfs, verified
rather than assumed.

Run as a script with the PostgreSQL password the caller chose in PGPASSWORD,
it prints one JSON line of PGHOST/PGPORT/REDIS_URL settings once both answer,
and removes the containers when stdin closes: one pair serves every fixture
of a test package run. The password never reaches stdout.
"""

import json
import os
import subprocess
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager

POSTGRES_DATA = "/var/lib/postgresql/data"
READY_ATTEMPTS = 120
READY_INTERVAL = 0.25


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def remove_owned_containers(owned: list[str]) -> None:
    """Remove each owned container with its anonymous volumes, newest first.

    Every removal is attempted; the failures are reported together, so one
    container that cannot be removed does not leave the others behind.
    """
    # --rm removes anonymous volumes only when Docker itself removes the
    # container; an explicit removal must name -v to remove them.
    failures = []
    for container in reversed(owned):
        removal = subprocess.run(
            ["docker", "rm", "-f", "-v", container],
            stdout=sys.stderr,
            stderr=subprocess.PIPE,
            text=True,
        )
        if removal.returncode != 0:
            failures.append(f"{container}: {removal.stderr.strip()}")
    if failures:
        raise RuntimeError("could not remove owned containers: " + "; ".join(failures))


def start_container(
    owned: list[str], *, image: str, port: int, options: tuple[str, ...] = ()
) -> tuple[str, str]:
    """Start image publishing port on a daemon-assigned loopback port; record
    the container in owned and return it with its host port."""
    container = run(
        "docker",
        "run",
        "-d",
        "--rm",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "-p",
        f"127.0.0.1::{port}",
        *options,
        image,
    )
    owned.append(container)
    return container, run("docker", "port", container, str(port)).rsplit(":", 1)[1]


def wait_for_postgres(container: str) -> None:
    # Over TCP: the image's initialization server listens on its socket only,
    # so only the final server answers here.
    probe = ["docker", "exec", container, "pg_isready", "-h", "127.0.0.1"]
    for _ in range(READY_ATTEMPTS):
        ready = subprocess.run(
            [*probe, "-U", "postgres"],
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


def verify_postgres_on_tmpfs(container: str) -> None:
    query = ["psql", "-h", "127.0.0.1", "-U", "postgres", "-tAc"]
    data_directory = run("docker", "exec", container, *query, "SHOW data_directory")
    mounts = run("docker", "exec", container, "cat", "/proc/mounts").splitlines()
    tmpfs = {fields[1] for fields in map(str.split, mounts) if fields[2] == "tmpfs"}
    if data_directory != POSTGRES_DATA or POSTGRES_DATA not in tmpfs:
        raise RuntimeError(
            f"PostgreSQL data directory {data_directory!r} is not on tmpfs "
            f"(tmpfs mounts: {sorted(tmpfs)})"
        )


@contextmanager
def disposable_postgres_and_redis(*, password: str) -> Generator[dict[str, str]]:
    """Yield PGHOST/PGPORT/REDIS_URL for containers removed on exit; the
    postgres user's password is the caller's."""
    owned: list[str] = []
    try:
        postgres, postgres_port = start_container(
            owned,
            image="postgres:17",
            port=5432,
            options=("-e", "POSTGRES_PASSWORD=" + password, "--tmpfs", POSTGRES_DATA),
        )
        _, redis_port = start_container(owned, image="redis:7", port=6379)
        wait_for_postgres(postgres)
        verify_postgres_on_tmpfs(postgres)
        yield {
            "PGHOST": "127.0.0.1",
            "PGPORT": postgres_port,
            "REDIS_URL": f"redis://127.0.0.1:{redis_port}/0",
        }
    finally:
        remove_owned_containers(owned)


def main() -> None:
    with disposable_postgres_and_redis(password=os.environ["PGPASSWORD"]) as services:
        print(json.dumps(services), flush=True)
        sys.stdin.read()


if __name__ == "__main__":
    main()

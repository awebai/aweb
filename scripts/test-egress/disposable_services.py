"""Disposable PostgreSQL and Redis for test fixtures the isolated runner does
not supply services to.

Each container takes a daemon-assigned loopback port and is removed, with its
anonymous volumes, on exit. PostgreSQL runs with the isolated runner's
memory-backed options and passes its readiness and storage checks (docker.py
owns that rule). Each container is labelled with its launcher's pid, so a
launcher killed before its cleanup leaves containers the next launcher removes.

Run as a script with the PostgreSQL password the caller chose in PGPASSWORD,
it prints one JSON line of PGHOST/PGPORT/REDIS_URL settings once both answer,
and removes the containers when stdin closes: one pair serves every fixture
of a test package run. The password never reaches stdout.
"""

import json
import os
import subprocess
import sys
from collections.abc import Generator
from contextlib import contextmanager

from docker import memory_postgres_options, require_memory_postgres, wait_for_postgres

OWNER_LABEL = "aw-test-services.owner-pid"
TEST_SERVICES_REFUSAL = (
    "this test needs the real service stack; run it on the gate or a dev VM "
    "(AWEB_TEST_SERVICES=1)"
)
# One PostgreSQL serves a whole package run: the runner's serial cap.
POSTGRES_MEMORY = "2g"


def require_test_services() -> None:
    """Refuse to start real services in a run that did not opt in; the gate
    and the development VMs set AWEB_TEST_SERVICES=1."""
    if os.environ.get("AWEB_TEST_SERVICES") != "1":
        raise SystemExit(TEST_SERVICES_REFUSAL)


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
        raise RuntimeError(
            "could not remove owned containers: "
            + "; ".join(failures)
            + ". Inspect the listed owned containers and finish their cleanup "
            "before another run."
        )


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def reap_orphaned_containers() -> None:
    """Remove containers a launcher labelled whose launcher no longer exists.

    Containers without the label, and labels that do not name a pid, are left
    alone: they are not this launcher's to judge.
    """
    listing = run(
        "docker",
        "ps",
        "-a",
        "--filter",
        "label=" + OWNER_LABEL,
        "--format",
        '{{.ID}} {{.Label "' + OWNER_LABEL + '"}}',
    )
    orphans = []
    for line in listing.splitlines():
        container, _, owner = line.partition(" ")
        if owner.isdigit() and not process_exists(int(owner)):
            orphans.append(container)
    if orphans:
        remove_owned_containers(orphans)


def start_container(
    owned: list[str],
    *,
    image: str,
    port: int,
    options: tuple[str, ...] = (),
    command: tuple[str, ...] = (),
) -> tuple[str, str]:
    """Start image with options and command, publishing port on a
    daemon-assigned loopback port and labelled with this launcher's pid; record
    the container in owned and return it with its host port."""
    container = run(
        "docker",
        "run",
        "-d",
        "--rm",
        "--label",
        f"{OWNER_LABEL}={os.getpid()}",
        "-p",
        f"127.0.0.1::{port}",
        *options,
        image,
        *command,
    )
    owned.append(container)
    return container, run("docker", "port", container, str(port)).rsplit(":", 1)[1]


@contextmanager
def disposable_postgres_and_redis(*, password: str) -> Generator[dict[str, str]]:
    """Yield PGHOST/PGPORT/REDIS_URL for containers removed on exit; the
    postgres user's password is the caller's."""
    reap_orphaned_containers()
    owned: list[str] = []
    try:
        memory = memory_postgres_options(memory=POSTGRES_MEMORY)
        postgres, postgres_port = start_container(
            owned,
            image="postgres:17",
            port=5432,
            options=(
                "--cpus",
                "1",
                *memory.docker_options,
                "-e",
                "POSTGRES_PASSWORD=" + password,
            ),
            command=memory.server_args,
        )
        _, redis_port = start_container(
            owned,
            image="redis:7",
            port=6379,
            options=("--cpus", "1", "--memory", "512m"),
        )
        wait_for_postgres(postgres)
        require_memory_postgres(postgres)
        yield {
            "PGHOST": "127.0.0.1",
            "PGPORT": postgres_port,
            "REDIS_URL": f"redis://127.0.0.1:{redis_port}/0",
        }
    finally:
        remove_owned_containers(owned)


def main() -> None:
    require_test_services()
    with disposable_postgres_and_redis(password=os.environ["PGPASSWORD"]) as services:
        print(json.dumps(services), flush=True)
        sys.stdin.read()


if __name__ == "__main__":
    main()

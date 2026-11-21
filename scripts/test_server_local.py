#!/usr/bin/env python3
"""Own disposable loopback services for the normal server and registry Make suites."""

from __future__ import annotations

import importlib.util
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from local_suite_slots import SuiteLabel, pytest_scope, suite_slot

ROOT = Path(__file__).resolve().parents[1]
RECOVERY = "Unset inherited database settings and use this target's disposable loopback services."
DATABASE_URLS = (
    "DATABASE_URL",
    "TEST_DATABASE_URL",
    "AWEB_DATABASE_URL",
    "AWID_DATABASE_URL",
    "APPROVAL_TEST_DATABASE_URL",
)


class Refused(RuntimeError):
    """Local test setup cannot safely proceed."""


class Suite(StrEnum):
    ALL = "all"
    SERVER = "server"
    REGISTRY = "registry"
    NAAPP_LIB = "naapp-lib"
    LOGS = "logs"


class Interrupted(Exception):
    def __init__(self, number: int):
        self.number = number


def validate_workers(workers: int) -> None:
    if not 1 <= workers <= 4:
        raise Refused(
            "Local workers must be between 1 and 4. Set LOCAL_TEST_WORKERS accordingly."
        )


def require_loopback(*, host: str | None, port: int | None) -> None:
    if (
        host not in ("127.0.0.1", "localhost", "::1")
        or port is None
        or not 1 <= port <= 65535
        or port == 5432
    ):
        raise Refused(
            "Database endpoint must be loopback on a non-5432 port. " + RECOVERY
        )


def check_inherited_database(environ: dict[str, str]) -> None:
    """Local feedback must never reach an author's ordinary database (docs/local-server-tests.md, Guards and cleanup)."""
    for key in DATABASE_URLS:
        if not environ.get(key):
            continue
        try:
            url = urlsplit(environ[key])
            if (
                url.scheme not in ("postgres", "postgresql", "postgresql+asyncpg")
                or url.query
            ):
                raise ValueError("unsupported database URL")
            require_loopback(host=url.hostname, port=url.port)
        except ValueError as exc:
            raise Refused("Invalid database URL. " + RECOVERY) from exc
    for host, port in (("PGHOST", "PGPORT"), ("TEST_DB_HOST", "TEST_DB_PORT")):
        if host in environ or port in environ:
            try:
                require_loopback(
                    host=environ.get(host, "localhost"),
                    port=int(environ.get(port, "5432")),
                )
            except ValueError as exc:
                raise Refused("Invalid database port. " + RECOVERY) from exc


def pytest_selection(value: str) -> list[str]:
    arguments = shlex.split(value)
    if any(
        arg.startswith(("-n", "--numprocesses", "--dist", "--max-worker"))
        for arg in arguments
    ):
        raise Refused(
            "Worker options belong to LOCAL_TEST_WORKERS (1–4). Remove them from pytest arguments."
        )
    return arguments


def compose_configuration(*, workers: int) -> dict:
    validate_workers(workers)
    services = {}
    for index in range(workers):
        services[f"postgres{index}"] = {
            "image": "postgres:17",
            "environment": {
                "POSTGRES_PASSWORD": "postgres",
                "PGDATA": "/var/lib/postgresql/data/pgdata",
            },
            "ports": [{"target": 5432, "published": "0", "host_ip": "127.0.0.1"}],
            "tmpfs": ["/var/lib/postgresql/data:rw,noexec,nosuid,size=1g"],
            "mem_limit": "2g",
            "memswap_limit": "2g",
            "cpus": 1,
            "pids_limit": 512,
            "command": [
                "postgres",
                "-c",
                "max_wal_size=128MB",
                "-c",
                "min_wal_size=32MB",
            ],
            "healthcheck": {
                "test": ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                "interval": "1s",
                "timeout": "3s",
                "retries": 60,
            },
        }
        services[f"redis{index}"] = {
            "image": "redis:7",
            "ports": [{"target": 6379, "published": "0", "host_ip": "127.0.0.1"}],
            "tmpfs": ["/data:rw,noexec,nosuid,size=128m"],
            "mem_limit": "256m",
            "memswap_limit": "256m",
            "cpus": 0.5,
            "pids_limit": 128,
            "command": ["redis-server", "--save", "", "--appendonly", "no"],
            "healthcheck": {
                "test": ["CMD", "redis-cli", "ping"],
                "interval": "1s",
                "timeout": "3s",
                "retries": 60,
            },
        }
    return {"services": services}


def invoke(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    stdout: int | None = subprocess.PIPE,
    timeout: float | None = 120,
    termination_grace_seconds: int = 10,
) -> subprocess.CompletedProcess[str]:
    """Terminate this command's process group before its owner removes services."""
    with subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=stdout,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    ) as child:
        try:
            output, _stderr = child.communicate(timeout=timeout)
        except BaseException:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.communicate(timeout=termination_grace_seconds)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate()
            raise
        return subprocess.CompletedProcess(command, child.returncode, output or "", "")


def checked(
    command: list[str], *, timeout: int = 120, env: dict[str, str] | None = None
) -> str:
    result = invoke(command, timeout=timeout, env=env)
    if result.returncode:
        raise Refused(
            f"Local service command failed (exit {result.returncode}): {result.stdout.strip()}\nInspect Docker and rerun the local target."
        )
    return result.stdout.strip()


DOCKER_SELECTION_KEYS = (
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)


def docker_environment(*, environ: dict[str, str]) -> dict[str, str]:
    """Resolve CLI precedence, then pin its Unix endpoint (Docker CLI env reference)."""
    # https://docs.docker.com/reference/cli/docker/#environment-variables
    context = environ.get("DOCKER_CONTEXT")
    host = environ.get("DOCKER_HOST")
    if context or not host:
        endpoint = checked(
            [
                "docker",
                "context",
                "inspect",
                *([context] if context else []),
                "--format",
                "{{.Endpoints.docker.Host}}",
            ],
            env=environ,
        )
    else:
        endpoint = host
    address = urlsplit(endpoint)
    if (
        address.scheme != "unix"
        or address.netloc
        or not Path(address.path).is_absolute()
    ):
        raise Refused(
            "Local suites require a local Docker socket. Select your local Docker context and rerun."
        )
    selected = dict(environ, DOCKER_HOST=endpoint)
    for key in (
        "DOCKER_CONTEXT",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    ):
        selected.pop(key, None)
    return selected


@contextmanager
def pinned_docker_environment(*, environ: dict[str, str]) -> Iterator[dict[str, str]]:
    """Keep delegated helpers and their subprocesses on the admitted endpoint."""
    previous = {key: os.environ.get(key) for key in DOCKER_SELECTION_KEYS}
    try:
        for key in DOCKER_SELECTION_KEYS:
            if key in environ:
                os.environ[key] = environ[key]
            else:
                os.environ.pop(key, None)
        yield environ
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def check_docker(*, environ: dict[str, str] | None = None) -> dict[str, str]:
    selected = docker_environment(
        environ=dict(os.environ) if environ is None else environ
    )
    result = invoke(
        ["bash", str(ROOT / "scripts/candidate-docker-gate.sh"), "--check-disk"],
        env=selected,
    )
    if result.returncode:
        raise Refused(
            result.stdout.strip()
            + "\nReclaim unused Docker data with docker system prune, then reclaim the Docker VM disk with fstrim; rerun after the disk guard passes. Review what prune will remove first."
        )
    return selected


def published_port(value: str) -> int:
    try:
        host, text = value.strip().rsplit(":", 1)
        port = int(text)
        if host != "127.0.0.1":
            raise ValueError("non-loopback binding")
        require_loopback(host=host, port=port)
        return port
    except ValueError as exc:
        raise Refused(
            "Docker did not publish a unique loopback port. "
            f"Port readback ({len(value)} characters): {value[:512]!r}. "
            "Inspect the local Docker port binding and rerun."
        ) from exc


# Inspect only public binding/ownership fields, never Config.Env or credentials.
PORT_INSPECT = (
    '{"id":{{json .Id}},'
    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"ports":{{json .NetworkSettings.Ports}}}'
)


def binding_port(
    value: str, *, container: str, project: str, service: str, target: int
) -> int | None:
    record = json.loads(value)
    if not isinstance(record, dict) or any(
        record.get(key) != expected
        for key, expected in (
            ("id", container),
            ("project", project),
            ("service", service),
        )
    ):
        raise Refused(
            "Docker binding ownership changed. Inspect the disposable project and rerun."
        )
    ports = record.get("ports")
    if ports is None:
        return None
    if not isinstance(ports, dict):
        raise ValueError("missing NetworkSettings.Ports")
    rows = ports.get(f"{target}/tcp") or []
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid port bindings")
    candidates = set()
    for row in rows:
        if row.get("HostIp") == "127.0.0.1" and row.get("HostPort") not in (
            None,
            "",
            "0",
        ):
            candidates.add(published_port(f"127.0.0.1:{row['HostPort']}"))
    if len(candidates) > 1:
        raise Refused(
            "Docker published ambiguous loopback bindings. Inspect the disposable project and rerun."
        )
    return next(iter(candidates), None)


def port_observation(command: list[str], *, timeout: float) -> dict[str, object]:
    try:
        result = invoke(command, timeout=timeout, termination_grace_seconds=1)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": type(exc).__name__}
    return {
        "exit": result.returncode,
        "output": result.stdout[:8192],
        "characters": len(result.stdout),
        "truncated": len(result.stdout) > 8192,
    }


def owned_published_port(
    *,
    compose: list[str],
    container: str,
    project: str,
    service: str,
    target: int,
) -> int:
    """Wait only for the selected container's mapping; never use Compose's summary."""
    deadline = time.monotonic() + 5
    observation: dict[str, object] = {}
    try:
        if len(container) != 64 or any(
            char not in "0123456789abcdef" for char in container
        ):
            raise Refused(
                "Docker did not identify one owned container. Inspect the disposable project and rerun."
            )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused(
                    "Docker did not report an owned nonzero loopback binding within five seconds. Inspect the retained port diagnostics and rerun."
                )
            observation = port_observation(
                ["docker", "inspect", "--format", PORT_INSPECT, container],
                timeout=min(2, remaining),
            )
            if observation.get("exit") == 0 and not observation.get("truncated"):
                try:
                    port = binding_port(
                        str(observation["output"]),
                        container=container,
                        project=project,
                        service=service,
                        target=target,
                    )
                except (ValueError, TypeError) as exc:
                    raise Refused(
                        "Docker returned malformed binding metadata. Inspect the retained port diagnostics and rerun."
                    ) from exc
                if port is not None:
                    return port
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    except Refused:
        # Captured while the owned container still exists, before finally cleanup.
        summary = port_observation([*compose, "port", service, str(target)], timeout=2)
        print(
            "LOCAL_PORT_DIAGNOSTIC "
            + json.dumps(
                {
                    "container": container[:128],
                    "project": project,
                    "service": service,
                    "target": target,
                    "network_settings_ports": observation,
                    "compose_port": summary,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise


def assert_project_absent(project: str) -> None:
    for kind in ("container", "network", "volume"):
        flags = ["-a"] if kind == "container" else []
        remaining = checked(
            [
                "docker",
                kind,
                "ls",
                *flags,
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + project,
            ]
        )
        if remaining:
            raise Refused(
                f"Local project {project} still owns {kind} resources. Run docker compose -p {project} down -v before retrying."
            )


def remove_project(*, compose: list[str], project: str) -> None:
    """Remove Compose's named and anonymous volumes, then verify absence."""
    errors: list[str] = []
    volumes: set[str] = set()
    try:
        containers = checked(
            [
                "docker",
                "container",
                "ls",
                "-aq",
                "--filter",
                "label=com.docker.compose.project=" + project,
            ]
        ).splitlines()
        if containers:
            records = json.loads(checked(["docker", "inspect", *containers]))
            for row in records:
                for mount in row["Mounts"]:
                    if mount["Type"] == "volume":
                        volumes.add(mount["Name"])
    except (
        Refused,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        errors.append("Could not record owned volumes: " + str(exc))
    try:
        result = invoke(
            [*compose, "down", "--volumes", "--remove-orphans", "--timeout", "10"],
            timeout=90,
        )
        if result.returncode:
            errors.append(
                f"Compose cleanup exited {result.returncode}: {result.stdout.strip()}"
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append("Compose cleanup failed: " + str(exc))
    try:
        assert_project_absent(project)
        remaining = (
            set(checked(["docker", "volume", "ls", "-q"]).splitlines()) & volumes
        )
        if remaining:
            errors.append(
                "Owned anonymous volumes remain: " + ", ".join(sorted(remaining))
            )
    except (Refused, OSError, subprocess.TimeoutExpired) as exc:
        errors.append(str(exc))
    if errors:
        raise Refused(
            "; ".join(errors)
            + f". Inspect and remove only project {project}'s resources before retrying."
        )
    print(f"Local project cleanup PASSED: {project}", flush=True)


def memory_owner():
    spec = importlib.util.spec_from_file_location(
        "local_memory_postgres", ROOT / "scripts/test-egress/docker.py"
    )
    if spec is None or spec.loader is None:
        raise Refused(
            "PostgreSQL storage checker is missing. Restore scripts/test-egress/docker.py and rerun."
        )
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    return owner


def service_environment(
    *, plan: list[dict[str, int]], environ: dict[str, str]
) -> dict[str, str]:
    env = dict(environ)
    for key in (
        *DATABASE_URLS,
        "PYTEST_XDIST_WORKER",
        "PYTEST_XDIST_WORKER_COUNT",
        "AWEB_SERVER_TEST_WORKERS",
    ):
        env.pop(key, None)
    first = plan[0]
    pg = str(first["postgres_port"])
    redis = f"redis://127.0.0.1:{first['redis_port']}/0"
    env.update(
        AWEB_TEST_SERVICES="1",
        PGHOST="127.0.0.1",
        PGPORT=pg,
        PGUSER="postgres",
        PGPASSWORD="postgres",
        PGDATABASE="postgres",
        TEST_DB_HOST="127.0.0.1",
        TEST_DB_PORT=pg,
        TEST_DB_USER="postgres",
        TEST_DB_PASSWORD="postgres",
        TEST_DATABASE_URL=f"postgresql://postgres:postgres@127.0.0.1:{pg}/postgres",
        REDIS_URL=redis,
        AWEB_REDIS_URL=redis,
        AWID_REDIS_URL=redis,
        AWEB_LOCAL_TEST_SERVICES=json.dumps(plan),
    )
    return env


@contextmanager
def local_services(
    *, workers: int, project: str, environ: dict[str, str]
) -> Iterator[dict[str, str]]:
    validate_workers(workers)
    check_inherited_database(environ)
    selected = check_docker(environ=environ)
    with (
        pinned_docker_environment(environ=selected),
        tempfile.TemporaryDirectory(prefix="aw-local-services-") as directory,
    ):
        config = Path(directory) / "compose.json"
        config.write_text(json.dumps(compose_configuration(workers=workers)))
        compose = ["docker", "compose", "-p", project, "-f", str(config)]
        print(f"Local test project: {project}", flush=True)
        try:
            checked(
                [*compose, "up", "-d", "--wait", "--wait-timeout", "90"], timeout=240
            )
            plan = []
            for index in range(workers):
                container = checked([*compose, "ps", "-q", f"postgres{index}"])
                memory_owner().require_memory_postgres(container)
                plan.append(
                    {
                        "postgres_port": owned_published_port(
                            compose=compose,
                            container=container,
                            project=project,
                            service=f"postgres{index}",
                            target=5432,
                        ),
                        "redis_port": owned_published_port(
                            compose=compose,
                            container=checked([*compose, "ps", "-q", f"redis{index}"]),
                            project=project,
                            service=f"redis{index}",
                            target=6379,
                        ),
                    }
                )
            yield service_environment(plan=plan, environ=selected)
        finally:
            # Ignore repeat signals while removing only this invocation's project.
            previous = {
                sig: signal.signal(sig, signal.SIG_IGN)
                for sig in (signal.SIGINT, signal.SIGTERM)
            }
            try:
                remove_project(compose=compose, project=project)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)


def run_logged_suite(
    command: list[str], *, environ: dict[str, str], log: Path
) -> subprocess.CompletedProcess[bytes]:
    """Drain inherited output through EOF before service cleanup (docs/local-server-tests.md)."""
    descriptor = os.open(
        log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    with (
        os.fdopen(descriptor, "wb") as output,
        subprocess.Popen(
            command,
            cwd=ROOT,
            env=environ,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        ) as child,
    ):
        assert child.stdout is not None
        try:
            while chunk := os.read(child.stdout.fileno(), 65536):
                output.write(chunk)
                output.flush()
            child.wait()
        except BaseException:
            # Make/egress wrappers may exit before pytest; communicate waits for
            # every inherited pipe writer so pytest can finalize its own JUnit.
            previous = {
                sig: signal.signal(sig, signal.SIG_IGN)
                for sig in (signal.SIGINT, signal.SIGTERM)
            }
            try:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    # No owned group remains; still drain output buffered in its pipe.
                    if child.poll() is None:
                        raise
                try:
                    tail, _stderr = child.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    tail, _stderr = child.communicate()
                output.write(tail or b"")
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
            raise
    return subprocess.CompletedProcess(command, child.returncode)


def run_suites(
    *, suite: Suite, workers: int, arguments: list[str], environ: dict[str, str]
) -> int:
    selected = (Suite.SERVER, Suite.REGISTRY) if suite is Suite.ALL else (suite,)
    if Suite.SERVER in selected:
        prepared = invoke(
            ["make", "prepare-server-node"],
            env=environ,
            stdout=None,
            timeout=None,
        )
        if prepared.returncode:
            print(
                "Local Node preparation failed. Run make prepare-server-node, resolve its error, then rerun make test-server-local.",
                file=sys.stderr,
            )
            return prepared.returncode
    reports = (
        Path(
            environ.get(
                "LOCAL_TEST_REPORT_DIR",
                str(ROOT / "test-results" / ("server-local-" + uuid.uuid4().hex[:12])),
            )
        )
        .expanduser()
        .resolve()
    )
    reports.mkdir(parents=True, mode=0o700, exist_ok=False)
    for item in selected:
        directory = reports / item.value
        directory.mkdir(mode=0o700)
        if item in (Suite.NAAPP_LIB, Suite.LOGS):
            package = "naapp-lib" if item is Suite.NAAPP_LIB else "naapp/logs"
            command = ["make", "test-naapp", f"NAAPP_PACKAGES={package}"]
        else:
            target = "test-server" if item is Suite.SERVER else "test-awid"
            command = [
                "make", target, f"SERVER_TEST_WORKERS={workers if item is Suite.SERVER else 0}",
            ]
        options = [
            *arguments,
            "-p",
            "local_pytest_progress",
            "--junitxml=" + str(directory / "cases.xml"),
            "--durations=0",
            "--durations-min=0",
        ]
        env = dict(
            environ,
            PYTEST_ADDOPTS=shlex.join(options),
            PYTHONPATH=os.pathsep.join(
                filter(
                    None,
                    (str(Path(__file__).resolve().parent), environ.get("PYTHONPATH")),
                )
            ),
            PYTHONUNBUFFERED="1",
            AWEB_LOCAL_PROGRESS_DIR=str(directory),
        )
        print(
            f"Local {item.value} live output: {directory / 'pytest.log'}; worker state: {directory / 'worker-*.json'}; JUnit: {directory / 'cases.xml'}",
            flush=True,
        )
        try:
            result = run_logged_suite(
                command,
                environ=env,
                log=directory / "pytest.log",
            )
        except Interrupted as exc:
            print(
                f"Local {item.value} interrupted ({exc.number}); retained evidence: {directory}",
                flush=True,
            )
            raise
        print(
            f"Local {item.value} exit={result.returncode}; evidence: {directory}",
            flush=True,
        )
        if result.returncode:
            return result.returncode
    return 0


def interrupted(number: int, _frame: object) -> None:
    raise Interrupted(number)


def main() -> int:
    previous = {
        sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        workers = int(os.environ.get("LOCAL_TEST_WORKERS", "4"))
        suite = Suite(os.environ.get("LOCAL_TEST_SUITE", "all"))
        arguments = pytest_selection(
            os.environ.get("PYTEST_ADDOPTS", "")
        ) + pytest_selection(os.environ.get("LOCAL_PYTEST_ARGS", ""))
        validate_workers(workers)
        check_inherited_database(dict(os.environ))
        with (
            suite_slot(
                scope=pytest_scope(arguments),
                label=SuiteLabel.REGISTRY
                if suite is Suite.REGISTRY
                else SuiteLabel.SERVER,
                root=ROOT,
            ),
            local_services(
                workers=workers if suite in (Suite.ALL, Suite.SERVER) else 1,
                project="aw-local-" + uuid.uuid4().hex[:12],
                environ=dict(os.environ),
            ) as env,
        ):
            return run_suites(
                suite=suite, workers=workers, arguments=arguments, environ=env
            )
    except Interrupted as exc:
        return 128 + exc.number
    except (Refused, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Local tests refused: {exc}", file=sys.stderr)
        return 2
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())

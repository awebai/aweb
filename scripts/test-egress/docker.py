#!/usr/bin/env python3
"""Run Go/Python/Node suites on an internal Docker network with a fail-on-query DNS sink.

Image preparation can download dependencies; the test runner has no external route.
Evidence survives cleanup. No host credentials or identity directories are mounted.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
_worker_spec = importlib.util.spec_from_file_location(
    "server_worker_services", ROOT / "server/tests/worker_services.py"
)
_worker_module = importlib.util.module_from_spec(_worker_spec)
_worker_spec.loader.exec_module(_worker_module)
service_plan = _worker_module.service_plan

_image_spec = importlib.util.spec_from_file_location(
    "package_image", Path(__file__).with_name("package_image.py")
)
_image_module = importlib.util.module_from_spec(_image_spec)
_image_spec.loader.exec_module(_image_module)
prepare_image = _image_module.prepare_image


# One runner's memory: the suite's processes plus one more GiB for each
# parallel server worker process.
RUNNER_MEMORY_MIB = 8192
WORKER_PROCESS_MIB = 1024


def runner_memory_mib(server_workers=0):
    return RUNNER_MEMORY_MIB + WORKER_PROCESS_MIB * server_workers


def runner_args(token, dns_ip, image, cpus, server_workers=0, name="runner"):
    """One suite runner. Its CPU cap is the gate's budget, never more."""
    worker_env = (
        ["-e", f"AWEB_SERVER_TEST_WORKERS={server_workers}"] if server_workers else []
    )
    return [
        "run",
        "-d",
        "--init",
        "--user",
        "1000:1000",
        "--network",
        token,
        "--dns",
        dns_ip,
        "--dns-search",
        ".",
        "--add-host",
        "127.0.0.1.nip.io:127.0.0.1",
        "--add-host",
        "signer.example.com:127.0.0.1",
        "--name",
        f"{token}-{name}",
        "--cpus",
        str(cpus),
        "--memory",
        f"{runner_memory_mib(server_workers)}m",
        "--pids-limit",
        "2048",
        "-e",
        "PGHOST=127.0.0.1",
        "-e",
        "PGUSER=postgres",
        "-e",
        "PGPASSWORD=postgres",
        "-e",
        "REDIS_URL=redis://127.0.0.1:6379/0",
        *worker_env,
        image,
        "sleep",
        "infinity",
    ]


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def postgres_args(runner, port=5432, parallel=False):
    # Disposable databases must not wait on the host disk's WAL fsync. Bound
    # both RAM and WAL growth, and prohibit swapping the tmpfs back to disk.
    # The first pair keeps the serial suites' cap; further workers are smaller.
    memory = (
        f"{_worker_module.WORKER_POSTGRES_MIB}m"
        if parallel and port != 5432
        else f"{_worker_module.PRIMARY_POSTGRES_MIB}m"
    )
    port_args = ["-c", f"port={port}"] if parallel else []
    return [
        "run",
        "-d",
        "--network",
        "container:" + runner,
        "--cpus",
        "1",
        "--memory",
        memory,
        "--memory-swap",
        memory,
        "--pids-limit",
        "512",
        "--tmpfs",
        "/var/lib/postgresql/data:rw,noexec,nosuid,size=1g",
        "-e",
        "PGDATA=/var/lib/postgresql/data/pgdata",
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "postgres:17",
        "-c",
        "max_wal_size=128MB",
        "-c",
        "min_wal_size=32MB",
        *port_args,
    ]


def redis_args(runner, port=6379, parallel=False):
    primary = port == 6379
    memory = (
        f"{_worker_module.PRIMARY_REDIS_MIB}m"
        if primary
        else f"{_worker_module.WORKER_REDIS_MIB}m"
    )
    limits = (
        [
            "--cpus",
            "1" if primary else ".25",
            "--memory",
            memory,
            "--memory-swap",
            memory,
            "--pids-limit",
            "512" if primary else "128",
        ]
        if parallel
        else ["--cpus", "1", "--memory", memory, "--pids-limit", "512"]
    )
    command = ["redis-server", "--port", str(port)] if parallel else []
    return [
        "run",
        "-d",
        "--network",
        "container:" + runner,
        *limits,
        "redis:7",
        *command,
    ]


def wait_for_redis(container, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "exec", container, "redis-cli", "-p", str(port), "ping"],
            capture_output=True,
            text=True,
            timeout=min(2, max(0.001, deadline - time.monotonic())),
        )
        if result.returncode == 0 and result.stdout.strip() == "PONG":
            return
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise RuntimeError("worker Redis did not become ready")


def wait_for_postgres(container, port=5432):
    # The entrypoint's temporary initialization server has no TCP listener.
    for _ in range(60):
        if (
            subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-p",
                    str(port),
                    "-U",
                    "postgres",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ):
            return
        time.sleep(0.5)
    raise RuntimeError("Postgres did not become ready")


def postgres_storage(container, port=5432):
    data = docker(
        "exec",
        container,
        "psql",
        "-p",
        str(port),
        "-At",
        "-U",
        "postgres",
        "-d",
        "postgres",
        "-c",
        "SHOW data_directory",
    )
    result = {}
    for name, path in [("data", data), ("wal", data + "/pg_wal")]:
        resolved = docker("exec", container, "readlink", "-f", path)
        filesystem = docker("exec", container, "stat", "-f", "-c", "%T", resolved)
        result[name] = {"path": resolved, "filesystem": filesystem}
    result["swap_max"] = docker(
        "exec", container, "cat", "/sys/fs/cgroup/memory.swap.max"
    )
    return result


def require_memory_postgres(container, port=5432):
    storage = postgres_storage(container, port)
    for name in ("data", "wal"):
        if storage[name]["filesystem"] != "tmpfs":
            raise RuntimeError(f"Postgres {name} must be on tmpfs: {storage[name]}")
    if storage["swap_max"] != "0":
        raise RuntimeError(
            f"Postgres swap must be disabled: memory.swap.max={storage['swap_max']}"
        )
    return storage


# Suites whose conftest binds each xdist worker to its own service pair
# (server/tests/worker_services.py); they run with the budget's worker count.
PARALLEL_SUITES = ("test-server", "test-naapp-lib")
# The Secrets package's measured two-shard partition (scripts/secrets_shards.py)
# runs on two owned service pairs whenever the budget allows parallel workers.
SHARDED_SUITE = "test-naapp-secrets"
SHARD_PAIRS = 2


def budget_cpus():
    spec = importlib.util.spec_from_file_location(
        "release_budget", ROOT / "scripts/vm-gate/vm_gate/budget.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.budget_from(os.environ)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--image", help="already prepared source/dependency image")
    parser.add_argument(
        "--cpus",
        type=int,
        help="each runner's CPU cap; default: the gate budget (GATE_CPUS or the engine)",
    )
    parser.add_argument(
        "--server-workers",
        type=int,
        default=0,
        help="parallel server workers, each with its own Postgres and Redis (0: serial)",
    )
    parser.add_argument(
        "--collect-summary",
        action="store_true",
        help="collect the command's candidate summary from the runner",
    )
    parser.add_argument(
        "--suites",
        nargs="+",
        help="isolated candidate unit suites, run concurrently, one runner each",
    )
    parser.add_argument(
        "--command",
        nargs=argparse.REMAINDER,
        help="guard qualification command instead of make targets",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        default=[
            "test-server",
            "test-awid",
            "test-cli",
            "test-channel",
            "test-channel-core",
            "test-pi-extension",
        ],
    )
    args = parser.parse_args()
    try:
        service_plan(args.server_workers)
    except ValueError as error:
        parser.error(str(error))
    if args.suites and args.command:
        parser.error("--suites and --command are exclusive")
    if args.suites and len(set(args.suites)) != len(args.suites):
        parser.error("each suite runs once")
    if args.cpus is None:
        args.cpus = budget_cpus()
    if args.cpus < 1:
        parser.error("--cpus must be positive")
    if sys.platform == "darwin":
        sys.path.insert(0, str(ROOT / "scripts"))
        from local_suite_slots import Scope, SuiteLabel, suite_slot

        with suite_slot(scope=Scope.WHOLE, label=SuiteLabel.PORTABLE, root=ROOT):
            return run_suite(args)
    return run_suite(args)


def start_runner(token, dns_ip, image, cpus, server_workers, name, pairs, evidence):
    """One runner and its own Postgres and Redis pairs, in its own network
    namespace: every service a suite reaches on 127.0.0.1 belongs to it.
    Returns the runner, its service rows and every container it created."""
    containers = []
    runner = docker(*runner_args(token, dns_ip, image, cpus, server_workers, name))
    containers.append(runner)
    parallel = pairs > 1
    services = []
    try:
        for plan in service_plan(pairs if parallel else 0):
            port = plan["postgres_port"]
            pg = docker(*postgres_args(runner, port, parallel))
            containers.append(pg)
            redis = docker(*redis_args(runner, plan["redis_port"], parallel))
            containers.append(redis)
            wait_for_postgres(pg, port)
            storage = require_memory_postgres(pg, port)
            if parallel:
                wait_for_redis(redis, plan["redis_port"])
            # Preserve the production role-default and memory-only storage controls.
            docker(
                "exec",
                pg,
                "psql",
                "-p",
                str(port),
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-d",
                "postgres",
                "-c",
                "ALTER ROLE postgres SET search_path = pg_catalog",
            )
            for database in ("postgres", "template1"):
                docker(
                    "exec",
                    pg,
                    "psql",
                    "-p",
                    str(port),
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-U",
                    "postgres",
                    "-d",
                    database,
                    "-c",
                    "CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public",
                )
            row = {**plan, "postgres": pg, "redis": redis, "storage": storage}
            if parallel:
                row["readbacks"] = {}
                for role, container in [("postgres", pg), ("redis", redis)]:
                    observed = json.loads(docker("inspect", container))[0]
                    limits = observed["HostConfig"]
                    if limits["NetworkMode"] != "container:" + runner or limits.get(
                        "PortBindings"
                    ):
                        raise RuntimeError(
                            "worker service escaped its unpublished runner namespace"
                        )
                    row["readbacks"][role] = {
                        "command": observed["Config"]["Cmd"],
                        "limits": {
                            key: limits[key]
                            for key in (
                                "NanoCpus",
                                "Memory",
                                "MemorySwap",
                                "PidsLimit",
                                "NetworkMode",
                            )
                        },
                    }
            services.append(row)
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "postgres-storage.json").write_text(
            json.dumps(services[0]["storage"], indent=2) + "\n"
        )
        if parallel:
            (evidence / "worker-services.json").write_text(
                json.dumps(services, indent=2) + "\n"
            )
        (evidence / "runner.json").write_text(docker("inspect", runner))
    except BaseException:
        remove(containers)
        raise
    return runner, services, containers


def remove(containers):
    for container in reversed(containers):
        subprocess.run(
            ["docker", "rm", "-f", "-v", container],
            stdout=subprocess.DEVNULL,
            check=True,
        )


def suite_services(name, server_workers):
    """(runner workers, service pairs, exec environment) for one suite."""
    if name in PARALLEL_SUITES:
        return server_workers, server_workers, []
    if name == SHARDED_SUITE and server_workers:
        shards = [
            {key: plan[key] for key in ("postgres_port", "redis_port")}
            for plan in service_plan(SHARD_PAIRS)
        ]
        return 0, SHARD_PAIRS, ["-e", "AWEB_SECRETS_SHARD_SERVICES=" + json.dumps(shards)]
    return 0, 0, []


def run_isolated_suite(name, args, token, dns_ip, image, evidence, owned):
    """Runs one suite in its own runner; returns its exit status."""
    directory = evidence / name
    workers, pairs, command_env = suite_services(name, args.server_workers)
    started = time.monotonic()
    runner, _, containers = start_runner(
        token, dns_ip, image, args.cpus, workers, name, pairs, directory
    )
    owned.extend(containers)
    with (directory / "suite.log").open("w") as log:
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-e",
                "CANDIDATE_LOG_DIR=/tmp",
                *command_env,
                runner,
                "bash",
                "scripts/candidate-suite.sh",
                "--isolated-suite",
                name,
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    status = result.returncode
    try:
        docker("cp", f"{runner}:/tmp/summary.tsv", str(directory / "summary.tsv"))
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"TEST SUMMARY COPY FAILED for {name}: {error}", flush=True)
        status = status or 1
    print(
        f"unit suite {name}: exit {status} in {time.monotonic() - started:.0f}s",
        flush=True,
    )
    return status


def run_concurrent_suites(args, token, dns_ip, image, evidence, owned):
    with ThreadPoolExecutor(max_workers=len(args.suites)) as pool:
        futures = {
            name: pool.submit(
                run_isolated_suite, name, args, token, dns_ip, image, evidence, owned
            )
            for name in args.suites
        }
    status = 0
    with (evidence / "summary.tsv").open("w") as combined:
        for name in args.suites:
            try:
                result = futures[name].result()
            except Exception as error:  # A suite that cannot start fails the stage.
                print(f"unit suite {name}: could not run: {error!r}", flush=True)
                result = 70
            summary = evidence / name / "summary.tsv"
            if summary.is_file():
                combined.write(summary.read_text())
            if result:
                status = status or result
                log = evidence / name / "suite.log"
                if log.is_file():
                    print(
                        f"--- {name} (last 100 lines) ---\n"
                        + "\n".join(log.read_text().splitlines()[-100:]),
                        flush=True,
                    )
    return status


def run_command(args, token, dns_ip, image, evidence, owned):
    runner, services, containers = start_runner(
        token,
        dns_ip,
        image,
        args.cpus,
        args.server_workers,
        "runner",
        args.server_workers,
        evidence,
    )
    owned.extend(containers)
    command_env = ["-e", "CANDIDATE_LOG_DIR=/tmp"] if args.collect_summary else []
    with (evidence / "suite.log").open("w") as log:
        result = subprocess.run(
            [
                "docker",
                "exec",
                *command_env,
                runner,
                *(args.command or ["make", "TEST_EGRESS_RUNNER=", *args.targets]),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    print(
        f"Test child exit status: {result.returncode}; evidence: {evidence}",
        flush=True,
    )
    if result.returncode:
        print(
            "\n".join((evidence / "suite.log").read_text().splitlines()[-100:]),
            flush=True,
        )
    status = result.returncode
    if args.collect_summary:
        try:
            docker("cp", f"{runner}:/tmp/summary.tsv", str(evidence / "summary.tsv"))
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"TEST SUMMARY COPY FAILED: {error}", flush=True)
            status = status or 1
    return status


def run_suite(args):
    args.evidence.mkdir(parents=True, exist_ok=False)
    evidence = args.evidence.resolve()
    (evidence / "source-sha").write_text(
        subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        )
    )
    (evidence / "source-status").write_text(
        subprocess.check_output(
            ["git", "-C", str(ROOT), "status", "--short"], text=True
        )
    )
    token = "aw-egress-" + uuid.uuid4().hex[:12]
    image = args.image or token
    containers = []
    network = None
    try:
        if not args.image:
            prepare_image(ROOT, evidence, image)
        # Pull service images before entering isolation.
        for service in ("postgres:17", "redis:7"):
            subprocess.run(
                ["docker", "image", "inspect", service],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            docker("pull", service)
        network = docker("network", "create", "--internal", token)
        dns = docker(
            "run",
            "-d",
            "--network",
            token,
            "--name",
            token + "-dns",
            "--cpus",
            ".5",
            "--memory",
            "128m",
            "--pids-limit",
            "128",
            "-v",
            f"{evidence}:/evidence",
            image,
            "python3",
            "scripts/test-egress/egress_dns.py",
            "--log",
            "/evidence/dns-denied.log",
        )
        containers.append(dns)
        info = json.loads(docker("inspect", dns))[0]
        dns_ip = info["NetworkSettings"]["Networks"][token]["IPAddress"]
        if not (evidence / "dns-denied.log").exists():
            # The sink creates its log at start; give it the same bounded wait.
            for _ in range(50):
                if (evidence / "dns-denied.log").exists():
                    break
                time.sleep(0.1)
        if not (evidence / "dns-denied.log").exists():
            raise RuntimeError("DNS sink did not start")
        if docker("inspect", "--format", "{{.State.Running}}", dns) != "true":
            raise RuntimeError("DNS sink exited")
        # Retain inspect evidence proving that runners have only the internal network.
        (evidence / "network.json").write_text(docker("network", "inspect", token))
        if args.suites:
            status = run_concurrent_suites(args, token, dns_ip, image, evidence, containers)
        else:
            status = run_command(args, token, dns_ip, image, evidence, containers)
        if docker("inspect", "--format", "{{.State.Running}}", dns) != "true":
            raise RuntimeError("DNS sink exited during tests")
        report = evidence / "dns-denied.log.reported"
        if report.exists():
            print(
                "TEST DNS REFUSED (reserved/allowlisted, no upstream):\n"
                + report.read_text()
            )
        denied = (evidence / "dns-denied.log").read_text()
        if denied:
            print("TEST DNS EGRESS DENIED:\n" + denied, flush=True)
            status = status or 1
        return status
    finally:
        remove(containers)
        if network:
            subprocess.run(
                ["docker", "network", "rm", network],
                stdout=subprocess.DEVNULL,
                check=True,
            )
        if not args.image:
            subprocess.run(
                ["docker", "image", "rm", image], stdout=subprocess.DEVNULL, check=False
            )


if __name__ == "__main__":
    raise SystemExit(main())

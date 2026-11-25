#!/usr/bin/env python3
"""Run Go/Python/Node suites on an internal Docker network with a fail-on-query DNS sink.

Image preparation can download dependencies; the test runner has no external route.
Evidence survives cleanup. No host credentials or identity directories are mounted.
"""

import argparse
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


def runner_args(token, dns_ip, image, cpu_shares, server_workers=0, name="runner"):
    """One suite runner, with its suite's cgroup weight (--cpu-shares); no CPU cap."""
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
        "--cpu-shares",
        str(cpu_shares),
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


def postgres_args(runner, cpu_shares, port=5432, parallel=False):
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
        "--cpu-shares",
        str(cpu_shares),
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


def redis_args(runner, cpu_shares, port=6379, parallel=False):
    primary = port == 6379
    memory = (
        f"{_worker_module.PRIMARY_REDIS_MIB}m"
        if primary
        else f"{_worker_module.WORKER_REDIS_MIB}m"
    )
    limits = (
        [
            "--memory",
            memory,
            "--memory-swap",
            memory,
            "--pids-limit",
            "512" if primary else "128",
        ]
        if parallel
        else ["--memory", memory, "--pids-limit", "512"]
    )
    command = ["redis-server", "--port", str(port)] if parallel else []
    return [
        "run",
        "-d",
        "--network",
        "container:" + runner,
        "--cpu-shares",
        str(cpu_shares),
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


_budget_spec = importlib.util.spec_from_file_location(
    "release_budget", ROOT / "scripts/vm-gate/vm_gate/budget.py"
)
_budget = importlib.util.module_from_spec(_budget_spec)
_budget_spec.loader.exec_module(_budget)
# Where each suite runner finds the one aw the unit stage built.
RUNNER_AW = "/tmp/aw-cli/aw"


def unit_plan(suites, environ=os.environ):
    """Unit's CPU share divided among its suites by their measured work.

    The share is GATE_UNIT_CPUS (and GATE_UNIT_MEMORY_MIB), which the gate
    passes from its plan; standalone, the measured budget.
    """
    work = json.loads((ROOT / "candidate-gate/measured-work.json").read_text())
    missing = [suite for suite in suites if suite not in work["unit_suites"]]
    if missing:
        raise ValueError(f"no measured work for unit suites {missing}")
    if environ.get("GATE_UNIT_CPUS"):
        cpus = float(environ["GATE_UNIT_CPUS"])
        memory_mib = int(environ["GATE_UNIT_MEMORY_MIB"])
    else:
        cpus, memory_mib, _ = _budget.budget_from(environ)
    return _budget.unit_plan(
        cpus,
        memory_mib,
        {suite: work["unit_suites"][suite] for suite in suites},
        runs=work["unit_runs"],
        service_memory_mib=_worker_module.service_memory_mib,
        max_workers=_worker_module.MAX_WORKERS,
    )


def lane_cpu_shares():
    """The weight of the lane this runs in (the gate passes it), else Docker's default."""
    return int(os.environ.get("AWEB_CANDIDATE_SIBLING_CPU_SHARES", "1024"))


def unit_requests(plan, suites):
    """How many of unit's workers each suite takes, and how many run at once.

    A parallel suite takes its xdist workers, a serial suite one; together
    they never exceed unit's workers. Suites with equal requests start
    heaviest first, by measured CPU-seconds.
    """
    capacity = sum(plan["workers"].values()) + plan["serial_slots"]
    ordered = sorted(suites, key=lambda suite: -plan["cpu_shares"][suite])
    return capacity, {suite: plan["workers"].get(suite, 1) for suite in ordered}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--image", help="already prepared source/dependency image")
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
        "--aw-binary",
        type=Path,
        help="the one aw every suite runner uses (AW_TEST_CLI_BINARY)",
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
    if sys.platform == "darwin":
        sys.path.insert(0, str(ROOT / "scripts"))
        from local_suite_slots import Scope, SuiteLabel, suite_slot

        with suite_slot(scope=Scope.WHOLE, label=SuiteLabel.PORTABLE, root=ROOT):
            return run_suite(args)
    return run_suite(args)


def start_runner(token, dns_ip, image, cpu_shares, server_workers, name, pairs, evidence):
    """One runner and its own Postgres and Redis pairs, in its own network
    namespace: every service a suite reaches on 127.0.0.1 belongs to it.
    Returns the runner, its service rows and every container it created."""
    containers = []
    runner = docker(*runner_args(token, dns_ip, image, cpu_shares, server_workers, name))
    containers.append(runner)
    parallel = pairs > 1
    services = []
    try:
        for plan in service_plan(pairs if parallel else 0):
            port = plan["postgres_port"]
            pg = docker(*postgres_args(runner, cpu_shares, port, parallel))
            containers.append(pg)
            redis = docker(*redis_args(runner, cpu_shares, plan["redis_port"], parallel))
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


def run_isolated_suite(name, plan, args, token, dns_ip, image, evidence, owned):
    """Runs one suite in its own runner, weighted by its measured work; returns its exit."""
    directory = evidence / name
    weight = plan["cpu_shares"][name]
    # One worker is a serial run; more are xdist workers with their own services.
    workers = plan["workers"].get(name, 1)
    xdist = workers if workers > 1 else 0
    started = time.monotonic()
    runner, _, containers = start_runner(
        token, dns_ip, image, weight, xdist, name, xdist, directory
    )
    owned.extend(containers)
    command_env = []
    if args.aw_binary:
        docker("exec", "--user", "0", runner, "mkdir", "-p", str(Path(RUNNER_AW).parent))
        docker("cp", str(args.aw_binary), f"{runner}:{RUNNER_AW}")
        command_env = ["-e", f"AW_TEST_CLI_BINARY={RUNNER_AW}"]
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
        f"unit suite {name}: exit {status} in {time.monotonic() - started:.0f}s"
        f" (weight {weight}, {workers} workers)",
        flush=True,
    )
    return status


def run_concurrent_suites(args, token, dns_ip, image, evidence, owned):
    """Every suite within unit's workers: the running suites never take more."""
    plan = unit_plan(args.suites)
    (evidence / "unit-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    print(f"unit plan: {json.dumps(plan, sort_keys=True)}", flush=True)
    capacity, requests = unit_requests(plan, args.suites)
    results = _budget.run_within(
        capacity,
        requests,
        lambda name: run_isolated_suite(
            name, plan, args, token, dns_ip, image, evidence, owned
        ),
    )
    status = 0
    with (evidence / "summary.tsv").open("w") as combined:
        for name in args.suites:
            result = results[name]
            if isinstance(result, Exception):
                # A suite that cannot start fails the stage.
                print(f"unit suite {name}: could not run: {result!r}", flush=True)
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
        lane_cpu_shares(),
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

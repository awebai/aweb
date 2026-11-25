"""The opt-in runner and each worker must select disjoint real service endpoints."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "isolated_services", ROOT / "scripts/test-egress/docker.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ServerWorkerTests(unittest.TestCase):
    def test_actual_launch_vectors_match_every_worker_environment(self):
        services_module = runner._worker_module
        for count in (2, 9):
            pg_ports, redis_ports = set(), set()
            for services in runner.service_plan(count):
                worker = services["worker"]
                env = {
                    "PYTEST_XDIST_WORKER": worker,
                    "PYTEST_XDIST_WORKER_COUNT": str(count),
                    "AWEB_SERVER_TEST_WORKERS": str(count),
                }
                services_module.configure_worker_environment(env)
                pg = runner.postgres_args("owned-runner", 5901, services["postgres_port"], True)
                redis = runner.redis_args("owned-runner", 5901, services["redis_port"], True)
                self.assertIn("port=" + env["TEST_DB_PORT"], pg)
                self.assertEqual(
                    redis[redis.index("--port") + 1], str(services["redis_port"])
                )
                self.assertEqual(
                    env["REDIS_URL"], f"redis://127.0.0.1:{services['redis_port']}/0"
                )
                self.assertEqual(env["AWID_REDIS_URL"], env["REDIS_URL"])
                self.assertEqual(env["AWEB_REDIS_URL"], env["REDIS_URL"])
                primary = worker == "gw0"
                pg_memory = (
                    services_module.PRIMARY_POSTGRES_MIB
                    if primary
                    else services_module.WORKER_POSTGRES_MIB
                )
                redis_memory = (
                    services_module.PRIMARY_REDIS_MIB
                    if primary
                    else services_module.WORKER_REDIS_MIB
                )
                self.assertEqual(pg[pg.index("--memory") + 1], f"{pg_memory}m")
                self.assertEqual(pg[pg.index("--memory-swap") + 1], f"{pg_memory}m")
                self.assertIn("/var/lib/postgresql/data:rw,noexec,nosuid,size=1g", pg)
                self.assertEqual(redis[redis.index("--memory") + 1], f"{redis_memory}m")
                self.assertEqual(
                    redis[redis.index("--memory-swap") + 1], f"{redis_memory}m"
                )
                for args in (pg, redis):
                    self.assertEqual(
                        args[args.index("--network") + 1], "container:owned-runner"
                    )
                    # The suite's services carry its weight and no CPU cap.
                    self.assertEqual(args[args.index("--cpu-shares") + 1], "5901")
                    self.assertNotIn("--cpus", args)
                    self.assertNotIn("-p", args)
                    self.assertNotIn("--publish", args)
                pg_ports.add(env["TEST_DB_PORT"])
                redis_ports.add(env["REDIS_URL"])
            self.assertEqual(len(pg_ports), count)
            self.assertEqual(len(redis_ports), count)
            self.assertEqual(
                services_module.service_memory_mib(count),
                sum(
                    (
                        services_module.PRIMARY_POSTGRES_MIB
                        + services_module.PRIMARY_REDIS_MIB
                    )
                    if plan["worker"] == "gw0"
                    else (
                        services_module.WORKER_POSTGRES_MIB
                        + services_module.WORKER_REDIS_MIB
                    )
                    for plan in runner.service_plan(count)
                ),
            )
            args = runner.runner_args("owned-network", "172.20.0.2", "owned-image", 5901, count)
            self.assertIn(f"AWEB_SERVER_TEST_WORKERS={count}", args)
            self.assertEqual(args[args.index("--cpu-shares") + 1], "5901")
            self.assertNotIn("--cpus", args)
            self.assertFalse(any("docker.sock" in arg for arg in args))

    def test_serial_environment_and_resources_stay_unchanged(self):
        env = {"REDIS_URL": "redis://fixture/0", "TEST_DB_PORT": "5999"}
        before = env.copy()
        runner._worker_module.configure_worker_environment(env)
        self.assertEqual(env, before)
        self.assertEqual(len(runner.service_plan(0)), 1)
        args = runner.postgres_args("owned-runner", 481)
        self.assertEqual(args[args.index("--memory") + 1], "2048m")
        self.assertEqual(args[args.index("--memory-swap") + 1], "2048m")
        self.assertEqual(runner.redis_args("owned-runner", 481)[-1], "redis:7")
        self.assertFalse(
            any(
                "AWEB_SERVER_TEST_WORKERS" in arg
                for arg in runner.runner_args("net", "172.20.0.2", "image", 481)
            )
        )

    def test_unit_share_is_divided_by_measured_work(self):
        suites = [
            "test-server", "test-awid", "test-naapp-lib", "test-naapp-secrets", "test-cli",
        ]
        work = json.loads((ROOT / "candidate-gate/measured-work.json").read_text())
        # The release's aweb share on merak gives unit 3.65 CPUs.
        env = {
            "GATE_UNIT_CPUS": "3.65",
            "GATE_UNIT_MEMORY_MIB": "18000",
            "GATE_CPU_MAPPING": "runc-1.3",
        }
        plan = runner.unit_plan(suites, env)
        self.assertEqual(plan["cpus"], 3.65)
        budget = runner._budget
        for suite in suites:
            self.assertEqual(
                budget.weight_of(plan["cpu_shares"][suite], "runc-1.3"),
                budget.cpu_weight(work["unit_suites"][suite]),
            )
        self.assertGreaterEqual(plan["workers"]["test-server"], 2)
        self.assertGreaterEqual(plan["serial_slots"], 1)
        with self.assertRaisesRegex(ValueError, "no measured work"):
            runner.unit_plan(["test-unmeasured"], env)

    def test_the_suites_run_within_units_workers_heaviest_first(self):
        plan = {
            "workers": {"test-server": 3, "test-naapp-lib": 1},
            "serial_slots": 2,
            "cpu_shares": {"test-server": 5901, "test-naapp-lib": 1676,
                           "test-awid": 481, "test-naapp-secrets": 1934, "test-cli": 874},
        }
        capacity, requests = runner.unit_requests(plan, list(plan["cpu_shares"]))
        self.assertEqual(capacity, 3 + 1 + 2)
        self.assertEqual(requests["test-server"], 3)
        self.assertEqual(requests["test-naapp-lib"], 1)
        self.assertEqual(requests["test-awid"], 1)
        # Equal requests start by measured work, heaviest first.
        ones = [name for name in requests if requests[name] == 1]
        self.assertEqual(ones, ["test-naapp-secrets", "test-naapp-lib", "test-cli", "test-awid"])

    def test_a_one_worker_or_oversized_plan_is_refused(self):
        for workers in (1, -1, runner._worker_module.MAX_WORKERS + 1):
            with self.subTest(workers=workers):
                with self.assertRaises(ValueError):
                    runner.service_plan(workers)

    def test_missing_or_wrong_service_plan_refuses_instead_of_sharing(self):
        for worker, count, supplied in [
            ("gw0", "7", "0"),
            ("gw7", "7", "7"),
            ("gw0", "2", "7"),
            ("gw0", "1", "1"),
            ("gw0", "", ""),
        ]:
            with self.subTest(worker=worker, count=count, supplied=supplied):
                with self.assertRaisesRegex(RuntimeError, "owned worker service plan"):
                    runner._worker_module.configure_worker_environment(
                        {
                            "PYTEST_XDIST_WORKER": worker,
                            "PYTEST_XDIST_WORKER_COUNT": count,
                            "AWEB_SERVER_TEST_WORKERS": supplied,
                        }
                    )

    def test_real_conftest_binds_before_pgdbm_and_test_module_imports(self):
        code = """import json,os
import tests.conftest
from pgdbm.fixtures.conftest import DEFAULT_TEST_CONFIG
from tests import test_agent_wake
print(json.dumps({'pg_port':DEFAULT_TEST_CONFIG.port,'redis':test_agent_wake.REDIS_URL,'env':os.environ['REDIS_URL']}))
"""
        with tempfile.TemporaryDirectory() as home:
            for index in (0, 8):
                env = {
                    "PATH": os.defpath,
                    "HOME": home,
                    "PYTHONPATH": os.pathsep.join(
                        str(ROOT / name)
                        for name in ("server", "server/src", "awid/src")
                    ),
                    "PYTEST_XDIST_WORKER": f"gw{index}",
                    "PYTEST_XDIST_WORKER_COUNT": "9",
                    "AWEB_SERVER_TEST_WORKERS": "9",
                }
                result = subprocess.run(
                    [sys.executable, "-B", "-c", code],
                    cwd=ROOT / "server",
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads(result.stdout)
                self.assertEqual(data["pg_port"], 5432 + index)
                self.assertEqual(data["redis"], f"redis://127.0.0.1:{6379 + index}/0")
                self.assertEqual(data["env"], data["redis"])

    def test_unit_stage_hands_every_suite_the_one_aw(self):
        """The real unit recipe gives docker.py the prebuilt aw and every suite."""
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / "docker-py-argv.json"
            shim = Path(tmp) / "python3"
            shim.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = scripts/test-egress/docker.py ]; then\n'
                "  shift\n"
                f"  exec {shlex_quote(sys.executable)} -c 'import json,sys; json.dump(sys.argv[1:], open(sys.argv[1], \"w\"))' {shlex_quote(str(capture))} \"$@\"\n"
                "fi\n"
                f'exec {shlex_quote(sys.executable)} "$@"\n'
            )
            shim.chmod(0o755)
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith(("GATE_", "MAKE", "MFLAGS"))
            }
            env.update(
                PATH=f"{tmp}{os.pathsep}{env['PATH']}",
                GATE_CPUS="12",
                GATE_MEMORY_MIB="56000",
                CANDIDATE_LOG_DIR=tmp,
            )
            result = subprocess.run(
                ["make", "-s", "_candidate-unit-suites"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            argv = json.loads(capture.read_text())
        self.assertEqual(argv[argv.index("--aw-binary") + 1], f"{tmp}/unit-aw/aw")
        self.assertNotIn("--server-workers", argv)
        suites = argv[argv.index("--suites") + 1 :]
        self.assertEqual(suites[0], "test-server")
        self.assertIn("test-naapp-secrets", suites)
        self.assertEqual(len(suites), len(set(suites)))


def shlex_quote(value):
    import shlex

    return shlex.quote(value)


if __name__ == "__main__":
    unittest.main()

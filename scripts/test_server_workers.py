"""The opt-in runner and each worker must select disjoint real service endpoints."""

import importlib.util
import json
import os
import shlex
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
    def test_cli_auth_stack_collects_with_the_unit_stage_environment(self):
        env = os.environ.copy()
        env.update(
            PYTHONPATH="tests",
            UV_OFFLINE="1",
            PYTHONPYCACHEPREFIX="/tmp/pycache",
        )
        for name in ("PYTEST_XDIST_WORKER", "PYTEST_XDIST_WORKER_COUNT"):
            env.pop(name, None)
        result = subprocess.run(
            [
                "uv",
                "run",
                "--offline",
                "--no-sync",
                "pytest",
                "-q",
                "../cli/tests/test_request_auth_v2_stack.py",
                "--collect-only",
            ],
            cwd=ROOT / "server",
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("4 tests collected", result.stdout)

    def test_actual_launch_vectors_match_all_seven_worker_environments(self):
        pg_ports, redis_ports = set(), set()
        for services in runner.service_plan(7):
            worker = services["worker"]
            env = {
                "PYTEST_XDIST_WORKER": worker,
                "PYTEST_XDIST_WORKER_COUNT": "7",
                "AWEB_SERVER_TEST_WORKERS": "7",
            }
            runner._worker_module.configure_worker_environment(env)
            pg = runner.postgres_args("owned-runner", services["postgres_port"], True)
            redis = runner.redis_args("owned-runner", services["redis_port"], True)
            self.assertIn("port=" + env["TEST_DB_PORT"], pg)
            self.assertEqual(
                redis[redis.index("--port") + 1], str(services["redis_port"])
            )
            self.assertEqual(
                env["REDIS_URL"], f"redis://127.0.0.1:{services['redis_port']}/0"
            )
            self.assertEqual(env["AWID_REDIS_URL"], env["REDIS_URL"])
            self.assertEqual(env["AWEB_REDIS_URL"], env["REDIS_URL"])
            pg_memory = "2g" if worker == "gw0" else "1280m"
            self.assertEqual(pg[pg.index("--memory") + 1], pg_memory)
            self.assertEqual(pg[pg.index("--memory-swap") + 1], pg_memory)
            self.assertIn("/var/lib/postgresql/data:rw,noexec,nosuid,size=1g", pg)
            redis_memory = "1g" if worker == "gw0" else "128m"
            self.assertEqual(redis[redis.index("--memory") + 1], redis_memory)
            self.assertEqual(redis[redis.index("--memory-swap") + 1], redis_memory)
            self.assertEqual(
                redis[redis.index("--pids-limit") + 1],
                "512" if worker == "gw0" else "128",
            )
            for args in (pg, redis):
                self.assertEqual(
                    args[args.index("--network") + 1], "container:owned-runner"
                )
                self.assertNotIn("-p", args)
                self.assertNotIn("--publish", args)
            pg_ports.add(env["TEST_DB_PORT"])
            redis_ports.add(env["REDIS_URL"])
        self.assertEqual(len(pg_ports), 7)
        self.assertEqual(len(redis_ports), 7)
        args = runner.runner_args(
            "owned-network", "172.20.0.2", "owned-image", "ccx33", 7
        )
        self.assertIn("AWEB_SERVER_TEST_WORKERS=7", args)
        self.assertFalse(any("docker.sock" in arg for arg in args))

    def test_serial_environment_and_resources_stay_unchanged(self):
        env = {"REDIS_URL": "redis://fixture/0", "TEST_DB_PORT": "5999"}
        before = env.copy()
        runner._worker_module.configure_worker_environment(env)
        self.assertEqual(env, before)
        self.assertEqual(len(runner.service_plan(0)), 1)
        args = runner.postgres_args("owned-runner")
        self.assertEqual(args[args.index("--memory") + 1], "2g")
        self.assertEqual(args[args.index("--memory-swap") + 1], "2g")
        self.assertEqual(runner.redis_args("owned-runner")[-1], "redis:7")
        self.assertFalse(
            any(
                "AWEB_SERVER_TEST_WORKERS" in arg
                for arg in runner.runner_args("net", "172.20.0.2", "image")
            )
        )

    def test_missing_or_wrong_service_plan_refuses_instead_of_sharing(self):
        for worker, count, supplied in [
            ("gw0", "7", "0"),
            ("gw7", "7", "7"),
            ("gw0", "2", "7"),
        ]:
            with self.subTest(worker=worker, count=count, supplied=supplied):
                with self.assertRaisesRegex(RuntimeError, "owned seven-worker"):
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
            for index in (0, 6):
                env = {
                    "PATH": os.defpath,
                    "HOME": home,
                    "PYTHONPATH": os.pathsep.join(
                        str(ROOT / name)
                        for name in ("server", "server/src", "awid/src")
                    ),
                    "PYTEST_XDIST_WORKER": f"gw{index}",
                    "PYTEST_XDIST_WORKER_COUNT": "7",
                    "AWEB_SERVER_TEST_WORKERS": "7",
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

    def test_unit_default_uses_selected_host_profile_and_portable_override(self):
        gate = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        launch = gate[gate.index("docker run --rm --init \\") :]
        launch = launch[: launch.index('  2>&1 | ')]
        capture = (
            "docker() { "
            + shlex.quote(sys.executable)
            + " -c 'import json,sys; print(json.dumps(sys.argv[1:]))' \"$@\"; }\n"
        )
        for supplied, override, profile, workers in [
            (None, None, "portable", "0"),
            ("ccx33", None, "ccx33", "7"),
            ("ccx33", "portable", "portable", "0"),
        ]:
            env = {
                k: v
                for k, v in os.environ.items()
                if k not in {"AWEB_GATE_UNIT_PROFILE", "CANDIDATE_UNIT_PROFILE"}
            }
            if supplied:
                env["AWEB_GATE_UNIT_PROFILE"] = supplied
            # Exercise the real outer-container argv as well as the Make entry:
            # an env-i host setting is otherwise lost at the Docker boundary.
            forwarded = subprocess.run(
                ["bash", "-c", capture + launch],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(forwarded.returncode, 0, forwarded.stderr)
            argv = json.loads(forwarded.stdout)
            container_env = dict(
                argv[i + 1].split("=", 1) for i, item in enumerate(argv) if item == "-e"
            )
            env.pop("AWEB_GATE_UNIT_PROFILE", None)
            if "AWEB_GATE_UNIT_PROFILE" in container_env:
                env["AWEB_GATE_UNIT_PROFILE"] = container_env["AWEB_GATE_UNIT_PROFILE"]
            command = ["make", "-n", "_candidate-unit-suites"]
            if override:
                command.append("CANDIDATE_UNIT_PROFILE=" + override)
            result = subprocess.run(
                command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=10
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "--profile " + profile + " --server-workers " + workers, result.stdout
            )
            self.assertIn(
                "--command bash scripts/candidate-suite.sh --isolated-suites",
                result.stdout,
            )

    def test_canonical_make_entry_selects_workers_only_when_requested(self):
        for workers, expected in [("0", False), ("7", True)]:
            result = subprocess.run(
                ["make", "-n", "test-server", "SERVER_TEST_WORKERS=" + workers],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = [line for line in result.stdout.splitlines() if "pytest -q" in line]
            self.assertEqual(len(lines), 1)
            self.assertEqual(
                "-n 7 --dist loadscope --max-worker-restart=0" in lines[0], expected
            )


if __name__ == "__main__":
    unittest.main()

"""Pure endpoint/configuration controls; native cleanup proof lives in test-egress."""

import json
import os
import subprocess
import sys
import tempfile
from unittest.mock import patch
import unittest

import test_server_local as local


class LocalControls(unittest.TestCase):
    def test_host_database_and_nonlocal_endpoints_refuse(self):
        for env in (
            {"TEST_DATABASE_URL": "postgresql://localhost:5432/test"},
            {"DATABASE_URL": "postgresql://elsewhere:5544/test"},
            {"PGHOST": "db.example", "PGPORT": "5544"},
            {"TEST_DB_PORT": "5432"},
        ):
            with self.subTest(env=env), self.assertRaisesRegex(local.Refused, "Unset"):
                local.check_inherited_database(env)
        local.check_inherited_database({})
        local.check_inherited_database(
            {"TEST_DATABASE_URL": "postgresql://127.0.0.1:5544/test"}
        )

    def test_unusable_ports_and_socket_queries_refuse(self):
        for url in (
            "postgresql://localhost/test",
            "postgresql://127.0.0.1:5544/test?host=remote",
            "postgresql:///test",
            "postgresql://localhost:bad/test",
        ):
            with self.subTest(url=url), self.assertRaises(local.Refused):
                local.check_inherited_database({"DATABASE_URL": url})

    def test_disposable_config_is_loopback_memory_only(self):
        config = local.compose_configuration(workers=4)
        self.assertEqual(len(config["services"]), 8)
        for name, service in config["services"].items():
            self.assertEqual(service["ports"][0]["host_ip"], "127.0.0.1")
            self.assertEqual(service["ports"][0]["published"], "0")
            self.assertEqual(service["mem_limit"], service["memswap_limit"])
            if name.startswith("postgres"):
                self.assertEqual(service["image"], "postgres:17")
                self.assertIn(
                    "/var/lib/postgresql/data:rw,noexec,nosuid,size=1g",
                    service["tmpfs"],
                )
            else:
                self.assertEqual(service["image"], "redis:7")
        json.dumps(config)

    def test_worker_limit_and_pytest_parallel_override_refuse(self):
        for value in (0, 5, -1):
            with self.assertRaisesRegex(local.Refused, "1.*4"):
                local.validate_workers(value)
        for args in ("-n 8", "-n8", "--numprocesses=8", "--dist load"):
            with self.assertRaisesRegex(local.Refused, "LOCAL_TEST_WORKERS"):
                local.pytest_selection(args)
        self.assertEqual(
            local.pytest_selection("tests/test_mail.py -k 'mail or chat'"),
            ["tests/test_mail.py", "-k", "mail or chat"],
        )

    def test_endpoint_readback_cannot_select_host_database(self):
        for value in ("0.0.0.0:5544", "127.0.0.1:5432", "remote:5544", "127.0.0.1:0"):
            with self.subTest(value=value), self.assertRaises(local.Refused):
                local.published_port(value)
        self.assertEqual(local.published_port("127.0.0.1:5544\n"), 5544)

    def test_rejected_port_readback_retains_bounded_escaped_evidence(self):
        responses = (
            "",
            "invalid IP:0\n",
            "warning: readback diagnostic\n127.0.0.1:5544\n",
            "127.0.0.1:5544\n127.0.0.1:5545\n",
            "0.0.0.0:5544\n",
            "x" * 600,
        )
        for response in responses:
            with self.subTest(response=response):
                with self.assertRaises(local.Refused) as raised:
                    local.published_port(response)
                message = str(raised.exception)
                self.assertIn(repr(response[:512]), message)
                self.assertIn(f"{len(response)} characters", message)
                self.assertNotIn("\n", message)
                self.assertLess(len(message), 800)
                self.assertTrue(
                    message.endswith("Inspect the local Docker port binding and rerun.")
                )
        self.assertEqual(local.published_port("127.0.0.1:5544\n"), 5544)

    def test_local_worker_map_binds_each_worker_and_refuses_shared_ports(self):
        owner = local.memory_owner()._worker_module
        plan = [{"postgres_port": 15000 + i, "redis_port": 16000 + i} for i in range(4)]
        for index in range(4):
            env = {
                "AWEB_LOCAL_TEST_SERVICES": json.dumps(plan),
                "PYTEST_XDIST_WORKER": f"gw{index}",
                "PYTEST_XDIST_WORKER_COUNT": "4",
            }
            owner.configure_worker_environment(env)
            self.assertEqual(env["TEST_DB_PORT"], str(15000 + index))
            self.assertEqual(env["REDIS_URL"], f"redis://127.0.0.1:{16000 + index}/0")
            self.assertIn(str(15000 + index), env["TEST_DATABASE_URL"])
        plan[1]["postgres_port"] = plan[0]["postgres_port"]
        with self.assertRaisesRegex(RuntimeError, "Re-run make test-server-local"):
            owner.configure_worker_environment(
                {
                    "AWEB_LOCAL_TEST_SERVICES": json.dumps(plan),
                    "PYTEST_XDIST_WORKER": "gw0",
                    "PYTEST_XDIST_WORKER_COUNT": "4",
                }
            )

    def test_real_entry_refuses_host_database_before_docker(self):
        result = subprocess.run(
            [sys.executable, str(local.ROOT / "scripts/test_server_local.py")],
            env={**os.environ, "TEST_DATABASE_URL": "postgresql://localhost:5432/test"},
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Unset inherited database settings", result.stderr)
        self.assertNotIn("Local test project:", result.stdout)

    def test_remote_context_overrides_local_host_before_daemon_access(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(
                os.environ,
                DOCKER_CONFIG=directory,
                DOCKER_CONTEXT="remote-proof",
                DOCKER_HOST="unix:///var/run/docker.sock",
            )
            created = subprocess.run(
                [
                    "docker",
                    "--config",
                    directory,
                    "context",
                    "create",
                    "remote-proof",
                    "--docker",
                    "host=ssh://unused.invalid",
                ],
                env={
                    k: v
                    for k, v in env.items()
                    if k not in ("DOCKER_CONTEXT", "DOCKER_HOST")
                },
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            native = local.invoke

            def metadata_only(command, **kwargs):
                if command[:3] != ["docker", "context", "inspect"]:
                    self.fail(
                        "daemon/project operation occurred before remote-context refusal: "
                        + repr(command)
                    )
                return native(command, **kwargs)

            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(local, "invoke", side_effect=metadata_only),
            ):
                with self.assertRaisesRegex(
                    local.Refused,
                    "Local suites require a local Docker socket. Select your local Docker context and rerun.",
                ):
                    local.check_docker()

    def test_local_context_and_explicit_host_follow_cli_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {
                key: value
                for key, value in os.environ.items()
                if key not in local.DOCKER_SELECTION_KEYS
            }
            env["DOCKER_CONFIG"] = directory
            for name, endpoint in (
                ("local-proof", "unix:///tmp/local-proof.sock"),
                ("remote-proof", "tcp://unused.invalid:2375"),
            ):
                created = subprocess.run(
                    [
                        "docker",
                        "context",
                        "create",
                        name,
                        "--docker",
                        "host=" + endpoint,
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(created.returncode, 0, created.stderr)
            selected = local.docker_environment(
                environ={
                    **env,
                    "DOCKER_CONTEXT": "local-proof",
                    "DOCKER_HOST": "tcp://unused.invalid:2375",
                }
            )
            self.assertEqual(selected["DOCKER_HOST"], "unix:///tmp/local-proof.sock")
            self.assertNotIn("DOCKER_CONTEXT", selected)
            switched = subprocess.run(
                ["docker", "context", "use", "remote-proof"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(switched.returncode, 0, switched.stderr)
            selected_host = local.docker_environment(
                environ={**env, "DOCKER_HOST": "unix:///tmp/explicit.sock"}
            )
            self.assertEqual(selected_host["DOCKER_HOST"], "unix:///tmp/explicit.sock")
            with self.assertRaisesRegex(local.Refused, "local Docker socket"):
                local.docker_environment(environ=env)
            subprocess.run(
                ["docker", "context", "use", "local-proof"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            self.assertEqual(
                local.docker_environment(environ=env)["DOCKER_HOST"],
                "unix:///tmp/local-proof.sock",
            )

    def test_admitted_endpoint_is_inherited_and_restored_after_failure(self):
        before = {key: os.environ.get(key) for key in local.DOCKER_SELECTION_KEYS}
        selected = {**os.environ, "DOCKER_HOST": "unix:///tmp/admitted.sock"}
        selected.pop("DOCKER_CONTEXT", None)
        with self.assertRaisesRegex(RuntimeError, "fixture exit"):
            with local.pinned_docker_environment(environ=selected):
                result = local.invoke(
                    [
                        sys.executable,
                        "-c",
                        "import os,json; print(json.dumps({k:os.environ.get(k) for k in ('DOCKER_HOST','DOCKER_CONTEXT')}))",
                    ]
                )
                self.assertEqual(
                    json.loads(result.stdout),
                    {
                        "DOCKER_HOST": "unix:///tmp/admitted.sock",
                        "DOCKER_CONTEXT": None,
                    },
                )
                suite = local.service_environment(
                    plan=[{"postgres_port": 15000, "redis_port": 16000}],
                    environ=selected,
                )
                self.assertEqual(suite["DOCKER_HOST"], selected["DOCKER_HOST"])
                self.assertNotIn("DOCKER_CONTEXT", suite)
                raise RuntimeError("fixture exit")
        self.assertEqual(
            {key: os.environ.get(key) for key in local.DOCKER_SELECTION_KEYS}, before
        )


if __name__ == "__main__":
    unittest.main()

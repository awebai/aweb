"""Pure endpoint/configuration controls; native cleanup proof lives in test-egress."""

import json
import os
import subprocess
import sys
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


if __name__ == "__main__":
    unittest.main()

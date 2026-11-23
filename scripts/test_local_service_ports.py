"""Owned Docker binding controls; no daemon or product services are used."""

import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

import test_server_local as local


class Ports(unittest.TestCase):
    def test_unbound_first_compose_summary_does_not_hide_owned_binding(self):
        def command(argv, **kwargs):
            if "ps" in argv:
                output = ("a" if argv[-1].startswith("postgres") else "b") * 64
            elif "port" in argv:
                # Compose's first exposed-port summary row has no published binding.
                summary = [
                    {"IP": "", "PublicPort": 0},
                    {"IP": "127.0.0.1", "PublicPort": 55432},
                ]
                first = summary[0]
                output = f"{first['IP'] or 'invalid IP'}:{first['PublicPort']}"
            elif "inspect" in argv:
                service = "postgres0" if argv[-1] == "a" * 64 else "redis0"
                target = "5432/tcp" if service == "postgres0" else "6379/tcp"
                output = json.dumps(
                    {
                        "id": argv[-1],
                        "project": "aw-local-test",
                        "service": service,
                        "ports": {
                            target: [
                                {"HostIp": "", "HostPort": "0"},
                                {
                                    "HostIp": "127.0.0.1",
                                    "HostPort": "55432"
                                    if service == "postgres0"
                                    else "56379",
                                },
                            ]
                        },
                    }
                )
            else:
                output = ""
            return subprocess.CompletedProcess(argv, 0, output, "")

        with (
            patch.object(local, "invoke", side_effect=command),
            patch.object(local, "check_docker", return_value={}),
            patch.object(local, "memory_owner", return_value=Mock()),
            patch.object(local, "remove_project") as cleanup,
        ):
            with local.local_services(
                workers=1, project="aw-local-test", environ={}
            ) as env:
                plan = json.loads(env["AWEB_LOCAL_TEST_SERVICES"])
                self.assertEqual(plan, [{"postgres_port": 55432, "redis_port": 56379}])
            cleanup.assert_called_once()

    def binding(self, rows, **extra):
        return json.dumps(
            {
                "id": "a" * 64,
                "project": "aw-local-test",
                "service": "postgres0",
                "ports": {"5432/tcp": rows},
                **extra,
            }
        )

    def read(self, value):
        return local.binding_port(
            value,
            container="a" * 64,
            project="aw-local-test",
            service="postgres0",
            target=5432,
        )

    def test_only_owned_unambiguous_nonzero_loopback_binding(self):
        for rows in (
            None,
            [],
            [{"HostIp": "127.0.0.1", "HostPort": "0"}],
            [{"HostIp": "0.0.0.0", "HostPort": "55432"}],
            [{"HostIp": "192.0.2.1", "HostPort": "55432"}],
        ):
            with self.subTest(rows=rows):
                self.assertIsNone(self.read(self.binding(rows)))
        self.assertIsNone(self.read(self.binding(None, ports=None)))
        good = [{"HostIp": "127.0.0.1", "HostPort": "55432"}]
        self.assertEqual(self.read(self.binding(good)), 55432)
        for value in (
            self.binding(good, project="other"),
            self.binding(good, service="redis0"),
            self.binding(good, id="b" * 64),
            self.binding(good + [{"HostIp": "127.0.0.1", "HostPort": "55433"}]),
            self.binding([{"HostIp": "127.0.0.1", "HostPort": "5432"}]),
        ):
            with self.subTest(value=value), self.assertRaises(local.Refused):
                self.read(value)

    def test_delayed_binding_waits_without_restarting_or_using_summary(self):
        responses = [
            self.binding(None),
            self.binding([{"HostIp": "127.0.0.1", "HostPort": "55432"}]),
        ]

        def command(argv, **kwargs):
            self.assertEqual(argv[:2], ["docker", "inspect"])
            self.assertLessEqual(kwargs["timeout"], 2)
            return subprocess.CompletedProcess(argv, 0, responses.pop(0), "")

        with (
            patch.object(local, "invoke", side_effect=command) as invoke,
            patch.object(local.time, "sleep") as sleep,
        ):
            self.assertEqual(
                local.owned_published_port(
                    compose=["docker", "compose"],
                    container="a" * 64,
                    project="aw-local-test",
                    service="postgres0",
                    target=5432,
                ),
                55432,
            )
            self.assertEqual(invoke.call_count, 2)
            sleep.assert_called_once()

    def test_exhaustion_captures_both_readbacks_before_cleanup(self):
        events = []

        def command(argv, **kwargs):
            if "ps" in argv:
                output = "a" * 64
            elif "inspect" in argv:
                events.append("inspect")
                output = self.binding(None)
            elif "port" in argv:
                events.append("compose-port")
                output = "invalid IP:0\n"
            else:
                output = ""
            return subprocess.CompletedProcess(argv, 0, output, "")

        captured = io.StringIO()

        def cleanup(**kwargs):
            self.assertIn("LOCAL_PORT_DIAGNOSTIC", captured.getvalue())
            events.append("cleanup")

        with (
            contextlib.redirect_stderr(captured),
            patch.object(local, "invoke", side_effect=command),
            patch.object(local, "check_docker", return_value={}),
            patch.object(local, "memory_owner", return_value=Mock()),
            patch.object(local, "remove_project", side_effect=cleanup),
            patch.object(local.time, "monotonic", side_effect=[0, 0, 6, 6]),
            patch.object(local.time, "sleep"),
        ):
            with self.assertRaisesRegex(local.Refused, "within five seconds"):
                with local.local_services(
                    workers=1, project="aw-local-test", environ={}
                ):
                    self.fail("must not start suite")
        self.assertEqual(events, ["inspect", "compose-port", "cleanup"])
        record = json.loads(captured.getvalue().removeprefix("LOCAL_PORT_DIAGNOSTIC "))
        self.assertEqual(record["container"], "a" * 64)
        self.assertEqual(record["compose_port"]["output"], "invalid IP:0\n")
        self.assertEqual(
            json.loads(record["network_settings_ports"]["output"])["ports"],
            {"5432/tcp": None},
        )

    def test_diagnostic_bound_and_native_failure(self):
        with patch.object(
            local,
            "invoke",
            return_value=subprocess.CompletedProcess([], 7, "x" * 9000, ""),
        ):
            record = local.port_observation(["docker", "inspect"], timeout=2)
        self.assertEqual(
            record,
            {"exit": 7, "output": "x" * 8192, "characters": 9000, "truncated": True},
        )
        with patch.object(
            local, "invoke", side_effect=subprocess.TimeoutExpired("docker", 2)
        ):
            self.assertEqual(
                local.port_observation(["docker", "inspect"], timeout=2),
                {"error": "TimeoutExpired"},
            )


if __name__ == "__main__":
    unittest.main()

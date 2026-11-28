#!/usr/bin/env python3
"""Container-free controls for the host published-port property."""

import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from http.client import RemoteDisconnected
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "boundaries", ROOT / "scripts/e2e/test_candidate_gate_docker_boundaries.py"
)
boundaries = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundaries)


class PublishedPortPropertyTests(unittest.TestCase):
    def exercise(
        self,
        outcome,
        *,
        stolen=False,
        lost=False,
        stopped=False,
        startup_error=None,
        persistent=False,
        later_error=None,
    ):
        containers = {}
        removed = []
        responses = []
        requests = 0

        def docker(*args, check=True, **kwargs):
            code, out, err = 0, "", ""
            if args[1] == "run":
                name = args[args.index("--name") + 1]
                response = args[args.index("--env") + 1].split("=", 1)[1]
                original = not containers
                containers[name] = (original, response)
                if original:
                    responses.append(response)
                if not original and outcome in ("refused", "unrelated-error"):
                    code = 1
                    err = (
                        "port is already allocated"
                        if outcome == "refused"
                        else "image not found"
                    )
                out = name
            elif args[1] == "port":
                out = "127.0.0.1:32768\n"
            elif args[1] == "inspect":
                name = args[-1]
                if name not in containers:
                    code, err = 1, "no such container"
                else:
                    original, _ = containers[name]
                    bindings = [{"HostIp": "127.0.0.1", "HostPort": "32768"}]
                    if not original and outcome != "mapped":
                        bindings = []
                    if original and lost and len(containers) > 1:
                        bindings = []
                    out = json.dumps(
                        [
                            {
                                "State": {
                                    "Running": not (
                                        original and stopped and len(containers) > 1
                                    )
                                },
                                "NetworkSettings": {"Ports": {"80/tcp": bindings}},
                            }
                        ]
                    )
            elif args[1] == "rm":
                removed.append(args[-1])
            elif args[1:3] == ("container", "inspect"):
                code = 1 if args[-1] in removed else 0
            result = subprocess.CompletedProcess(args, code, out, err)
            if code and check:
                raise subprocess.CalledProcessError(code, args, out, err)
            return result

        def http(port):
            nonlocal requests
            requests += 1
            self.assertEqual(str(port), "32768")
            if startup_error is not None and (requests == 1 or persistent):
                raise startup_error
            if later_error is not None and len(containers) > 1 and requests == 2:
                raise later_error
            return (
                "competitor\n"
                if stolen and len(containers) > 1
                else responses[0] + "\n"
            )

        boundary = boundaries.HostPublishedPortTests(
            "test_docker_assigned_published_port_is_reserved_by_its_service"
        )
        try:
            with (
                patch.object(boundaries, "run", side_effect=docker),
                patch.object(boundaries, "read_published_response", side_effect=http),
                patch("sys.stdout", new_callable=io.StringIO),
                patch.dict(boundaries.os.environ, {}, clear=True),
            ):
                boundary.test_docker_assigned_published_port_is_reserved_by_its_service()
        finally:
            expected = set(containers)
            expected.update(
                name.replace("aweb-publish-original-", "aweb-publish-competitor-", 1)
                for name in containers
            )
            self.assertEqual(set(removed), expected)

    def test_refused_competitor_and_success_without_mapping_are_valid(self):
        for outcome in ("refused", "unmapped"):
            with self.subTest(outcome=outcome):
                self.exercise(outcome)

    def test_binding_the_taken_port_or_serving_competitor_response_fails(self):
        for outcome, stolen in (("mapped", False), ("unmapped", True)):
            with (
                self.subTest(outcome=outcome, stolen=stolen),
                self.assertRaises(AssertionError),
            ):
                self.exercise(outcome, stolen=stolen)

    def test_lost_mapping_stopped_owner_and_unrelated_failure_are_not_valid(self):
        for kwargs in ({"lost": True}, {"stopped": True}):
            with self.subTest(**kwargs), self.assertRaises(AssertionError):
                self.exercise("unmapped", **kwargs)
        with self.assertRaises(AssertionError):
            self.exercise("unrelated-error")

    def test_startup_reset_or_refusal_is_retried(self):
        for error in (ConnectionResetError, ConnectionRefusedError):
            with self.subTest(error=error):
                self.exercise("refused", startup_error=error("startup"))

    def test_persistent_startup_disconnect_still_fails_at_the_original_deadline(self):
        # Time advances only when the reader sleeps between attempts.
        for error in (RemoteDisconnected, ConnectionResetError, ConnectionRefusedError):
            now = 0.0

            def clock():
                return now

            def sleep(seconds):
                nonlocal now
                now += seconds

            with (
                self.subTest(error=error),
                patch.object(
                    boundaries, "read_published_response", side_effect=error("startup")
                ),
                self.assertRaisesRegex(
                    AssertionError,
                    "original host publication never became reachable: startup",
                ),
            ):
                boundaries.read_until_reachable("32768", clock=clock, sleep=sleep)
            self.assertGreaterEqual(now, 10)
            self.assertLess(now, 10.2)

    def test_disconnect_after_readiness_is_not_retried(self):
        for error in (RemoteDisconnected, ConnectionResetError, ConnectionRefusedError):
            with self.subTest(error=error), self.assertRaises(error):
                self.exercise("refused", later_error=error("after readiness"))


class HostPublishedPortWiringTests(unittest.TestCase):
    def test_host_result_survives_until_runner_including_failure(self):
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        start = source.index("# The published socket belongs to the Docker host")
        block = source[start : source.index("\nfi", start) + 3]
        for pending, code in (
            ("checks integration", 7),
            ("checks", 0),
            ("integration", 7),
        ):
            with (
                self.subTest(pending=pending, code=code),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                python = root / "python3"
                python.write_text(
                    '#!/bin/sh\nprintf "host proof %s\\n" "$*"\nexit "$PROBE_EXIT"\n'
                )
                python.chmod(0o755)
                env = dict(
                    os.environ,
                    PATH=str(root) + os.pathsep + os.environ["PATH"],
                    pending=pending,
                    resource_label="test-label",
                    checkout="/exact checkout",
                    LOG_DIR=tmp,
                    PROBE_EXIT=str(code),
                )
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        "set -eu\n"
                        + block
                        + '\necho runner-reached "$host_port_status"',
                    ],
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=5,
                )
                if pending.startswith("checks"):
                    evidence = (root / "host-published-port.log").read_text()
                    self.assertIn(
                        "/exact checkout/scripts/e2e/test_candidate_gate_docker_boundaries.py",
                        evidence,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertIn(f"runner-reached {code}", result.stdout)
                else:
                    self.assertEqual(result.returncode, 0)
                    self.assertFalse((root / "host-published-port.log").exists())


if __name__ == "__main__":
    unittest.main()

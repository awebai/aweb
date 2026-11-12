#!/usr/bin/env python3
"""Container-free controls for the host published-port property."""
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "boundaries", ROOT / "scripts/e2e/test_candidate_gate_docker_boundaries.py")
boundaries = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundaries)


class PublishedPortPropertyTests(unittest.TestCase):
    def exercise(self, outcome, *, stolen=False, lost=False, stopped=False):
        containers = {}
        removed = []
        responses = []

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
                    err = "port is already allocated" if outcome == "refused" else "image not found"
                out = name
            elif args[1] == "port":
                out = "127.0.0.1:32768\n"
            elif args[1] == "inspect":
                name = args[-1]
                original, _ = containers[name]
                bindings = [{"HostIp": "127.0.0.1", "HostPort": "32768"}]
                if not original and outcome != "mapped":
                    bindings = []
                if original and lost and len(containers) > 1:
                    bindings = []
                out = json.dumps([{
                    "State": {"Running": not (original and stopped and len(containers) > 1)},
                    "NetworkSettings": {"Ports": {"80/tcp": bindings}},
                }])
            elif args[1] == "rm":
                removed.append(args[-1])
            elif args[1:3] == ("container", "inspect"):
                code = 1 if args[-1] in removed else 0
            result = subprocess.CompletedProcess(args, code, out, err)
            if code and check:
                raise subprocess.CalledProcessError(code, args, out, err)
            return result

        def http(port):
            self.assertEqual(str(port), "32768")
            return "competitor\n" if stolen and len(containers) > 1 else responses[0] + "\n"

        boundary = boundaries.HostPublishedPortTests(
            "test_docker_assigned_published_port_is_reserved_by_its_service")
        try:
            with patch.object(boundaries, "run", side_effect=docker), \
                    patch.object(boundaries, "read_published_response", side_effect=http), \
                    patch.dict(boundaries.os.environ, {}, clear=True):
                boundary.test_docker_assigned_published_port_is_reserved_by_its_service()
        finally:
            self.assertEqual(set(removed), set(containers))

    def test_refused_competitor_and_success_without_mapping_are_valid(self):
        for outcome in ("refused", "unmapped"):
            with self.subTest(outcome=outcome):
                self.exercise(outcome)

    def test_binding_the_taken_port_or_serving_competitor_response_fails(self):
        for outcome, stolen in (("mapped", False), ("unmapped", True)):
            with self.subTest(outcome=outcome, stolen=stolen), self.assertRaises(AssertionError):
                self.exercise(outcome, stolen=stolen)

    def test_lost_mapping_stopped_owner_and_unrelated_failure_are_not_valid(self):
        for kwargs in ({"lost": True}, {"stopped": True}):
            with self.subTest(**kwargs), self.assertRaises(AssertionError):
                self.exercise("unmapped", **kwargs)
        with self.assertRaises(AssertionError):
            self.exercise("unrelated-error")


class HostPublishedPortWiringTests(unittest.TestCase):
    def test_check_runs_from_selected_checkout_before_runner_and_records_failure(self):
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        start = source.index('# The published socket belongs to the Docker host')
        end = source.index('\nfi', start) + 3
        block = source[start:end]
        self.assertIn('" $pending " == *" checks "*', block)
        self.assertIn('"$checkout/scripts/e2e/test_candidate_gate_docker_boundaries.py"', block)
        self.assertIn('HostPublishedPortTests', block)
        self.assertIn('"$LOG_DIR/host-published-port.log"', block)
        self.assertIn('"$LOG_DIR/checks.log"', block)
        self.assertIn('exit 1', block)
        self.assertLess(source.index('clone selected the wrong SHA'), start)
        self.assertLess(start, source.index('docker run --rm --init'))
        suite = (ROOT / "scripts/candidate-suite.sh").read_text()
        self.assertIn('cat "$log_dir/host-published-port.log"', suite)
        self.assertIn('run _candidate-gate-docker-boundaries', suite)


if __name__ == "__main__":
    unittest.main()

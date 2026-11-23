#!/usr/bin/env python3
"""Folio acceptance admission and resource ownership; no Docker allocation."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FolioGateTests(unittest.TestCase):
    def test_integration_runs_folio_and_propagates_its_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls"
            make = root / "make"
            make.write_text('#!/bin/bash\nprintf "%s\\n" "$1" >> "$CALLS"\n'
                            '[[ "$1" != e2e-folio-wakes ]] || exit 86\n')
            make.chmod(0o755)
            result = subprocess.run(["bash", str(ROOT / "scripts/candidate-suite.sh"), "integration"],
                                    env=dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                                             CALLS=str(calls), CANDIDATE_LOG_DIR=str(root)),
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
            targets = calls.read_text().splitlines()
            self.assertIn("e2e-naapp", targets)
            self.assertIn("e2e-folio-wakes", targets)
            self.assertIn("test-npm-exact-publish", targets)
            self.assertIn("integration\tFAILED", (root / "summary.tsv").read_text())
        recipe = subprocess.check_output(["make", "-n", "e2e-folio-wakes"], cwd=ROOT, text=True)
        self.assertIn("bash scripts/e2e-folio-wakes.sh", recipe)

    def run_harness(self, root, **changes):
        docker = root / "docker"
        docker.write_text('#!/usr/bin/env python3\nimport json, os, sys\n'
                          'with open(os.environ["CALLS"], "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                          'if sys.argv[1] == "ps" and os.environ.get("EXISTING_PROJECT"): print("existing")\n'
                          'if sys.argv[1:3] == ["network", "inspect"]:\n'
                          '    subnets = os.environ.get("SUBNETS", "192.168.208.0/20").split()\n'
                          '    print(json.dumps([{"IPAM": {"Config": [{"Subnet": s} for s in subnets]}}]))\n')
        docker.chmod(0o755)
        env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", CALLS=str(root / "calls"),
                   FOLIO_WAKE_EVIDENCE=str(root / "evidence"))
        for key in ("FOLIO_WAKES_PROJECT", "AWEB_CANDIDATE_RESOURCE_LABEL", "BUILDX_BUILDER"):
            env.pop(key, None)
        env.update(changes)
        result = subprocess.run(["bash", str(ROOT / "scripts/e2e-folio-wakes.sh")],
                                env=env, text=True, capture_output=True)
        calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
        return result, calls

    def test_candidate_projects_are_scoped_and_shared_builder_survives(self):
        for label in ("candidate-alpha", "candidate-beta"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                result, calls = self.run_harness(Path(directory), AWEB_CANDIDATE_RESOURCE_LABEL=label,
                                                 BUILDX_BUILDER="shared-gate-builder")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                project = label + "-folio"
                compose = [args for args in calls if args[0] == "compose"]
                self.assertTrue(compose)
                self.assertTrue(all(args[1:3] == ["-p", project] for args in compose))
                build = next(args for args in compose if "build" in args)
                self.assertEqual(build[-2:], ["--builder", "shared-gate-builder"])
                self.assertFalse(any(args[:2] in (["buildx", "create"], ["buildx", "rm"]) for args in calls))
                seed = next(args for args in calls if args[0] == "create")
                self.assertIn(project + "-fixture:/fixture", seed)
                self.assertIn(project + "-aweb", seed)
                self.assertIn("label=com.docker.compose.project=" + project, calls[0])

    def test_standalone_owns_its_builder_and_refuses_an_existing_project(self):
        with tempfile.TemporaryDirectory() as directory:
            result, calls = self.run_harness(Path(directory), FOLIO_WAKES_PROJECT="local-folio")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            create = next(args for args in calls if args[:2] == ["buildx", "create"])
            builder = create[create.index("--name") + 1]
            self.assertIn(["buildx", "rm", builder], calls)
            self.assertIn("memory=2g,cpu-period=100000,cpu-quota=200000", create)
        with tempfile.TemporaryDirectory() as directory:
            result, calls = self.run_harness(Path(directory), FOLIO_WAKES_PROJECT="occupied-folio",
                                             EXISTING_PROJECT="1")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("occupied-folio project already exists", result.stderr)
            self.assertEqual(len(calls), 1, "Must not allocate or clean another run's project")

    def test_the_client_starts_folio_with_the_stack_networks_own_subnet(self):
        with tempfile.TemporaryDirectory() as directory:
            result, calls = self.run_harness(Path(directory), FOLIO_WAKES_PROJECT="local-folio",
                                             SUBNETS="192.168.208.0/20 fd00:1::/64")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(["network", "inspect", "local-folio_default"], calls)
            client = next(args for args in calls if args[0] == "compose" and "run" in args)
            self.assertIn("FOLIO_WAKES_STACK_SUBNET=192.168.208.0/20", client)

    def test_a_network_without_exactly_one_ipv4_subnet_stops_the_run_and_is_removed(self):
        for subnets in ("fd00:1::/64", "172.30.0.0/16 172.31.0.0/16"):
            with self.subTest(subnets=subnets), tempfile.TemporaryDirectory() as directory:
                result, calls = self.run_harness(Path(directory), SUBNETS=subnets)
                self.assertNotEqual(result.returncode, 0)
                compose = [args for args in calls if args[0] == "compose"]
                self.assertFalse(any("run" in args for args in compose))
                self.assertIn("down", compose[-1])

    def compose_config(self, *files, **changes):
        env = {name: value for name, value in os.environ.items() if name != "FOLIO_WAKES_STACK_SUBNET"}
        env.update(FOLIO_WAKES_ORIGIN="https://folio-wakes.test:8765", FOLIO_WAKES_APP_KEY_FILES="{}", **changes)
        args = ["docker", "compose", "-p", "proof", "--project-directory", str(ROOT)]
        for file in files:
            args += ["-f", str(ROOT / "scripts/e2e" / file)]
        return subprocess.run([*args, "config", "--format", "json"], env=env, text=True, capture_output=True)

    def test_folio_starts_only_with_its_stack_network_as_operator_network(self):
        stack, overlay = "folio-wakes.compose.yml", "folio-wakes-subnet.compose.yml"
        base = self.compose_config(stack)
        self.assertEqual(base.returncode, 0, base.stderr)
        folio = json.loads(base.stdout)["services"]["folio"]["environment"]
        self.assertNotIn("FOLIO_HOOK_INTERNAL_CIDR", folio)
        refused = self.compose_config(stack, overlay)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("FOLIO_WAKES_STACK_SUBNET", refused.stderr)
        started = self.compose_config(stack, overlay, FOLIO_WAKES_STACK_SUBNET="192.168.208.0/20")
        self.assertEqual(started.returncode, 0, started.stderr)
        folio = json.loads(started.stdout)["services"]["folio"]["environment"]
        self.assertEqual(folio["FOLIO_HOOK_INTERNAL_CIDR"], "192.168.208.0/20")
        self.assertEqual(folio["FOLIO_HOOK_INTERNAL_DESTINATIONS"], "allowed")


if __name__ == "__main__":
    unittest.main()

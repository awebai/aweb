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
            self.assertNotIn("test-npm-exact-publish", targets)
            self.assertIn("integration\tFAILED", (root / "summary.tsv").read_text())
        recipe = subprocess.check_output(["make", "-n", "e2e-folio-wakes"], cwd=ROOT, text=True)
        self.assertIn("bash scripts/e2e-folio-wakes.sh", recipe)

    def run_harness(self, root, **changes):
        docker = root / "docker"
        docker.write_text('#!/usr/bin/env python3\nimport json, os, sys\n'
                          'with open(os.environ["CALLS"], "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                          'if sys.argv[1] == "ps" and os.environ.get("EXISTING_PROJECT"): print("existing")\n')
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


if __name__ == "__main__":
    unittest.main()

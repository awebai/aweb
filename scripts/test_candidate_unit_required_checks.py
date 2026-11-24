"""The actual unit stage runs the source controls before product tests."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "test-identity-primitives",
    "test-vector-provenance",
    "test-sot-source-inventories",
    "test-python-locks",
    "lint-naapp-contracts",
]


class UnitRequiredChecksTests(unittest.TestCase):
    def exercise(self, stages="unit", failure=""):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            make = binary / "make"
            make.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$1" >> "$CALLS"\n'
                '[ "$1" != "$FAIL_TARGET" ] || exit 23\n'
            )
            make.chmod(0o755)
            docker = binary / "docker"
            docker.write_text("#!/bin/sh\nexit 0\n")
            docker.chmod(0o755)
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"])
            env.update(
                CANDIDATE_LOG_DIR=str(root),
                CALLS=str(root / "calls"),
                FAIL_TARGET=failure,
                BUILDX_BUILDER="fixture-only",
            )
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/candidate-suite.sh"), stages],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return (
                result,
                (root / "calls").read_text().splitlines(),
                (root / "summary.tsv").read_text(),
                (root / "unit.log").read_text(),
            )

    def test_unit_runs_all_five_before_node_setup_and_isolated_suites(self):
        result, calls, summary, log = self.exercise()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            calls, REQUIRED + ["_candidate-node-deps", "_candidate-unit-suites"]
        )
        self.assertIn("unit\tPASSED\tunit.log", summary)
        for target in REQUIRED:
            self.assertIn("=== candidate: " + target + " ===", log)

    def test_each_source_failure_is_reported_and_product_work_still_runs(self):
        for target in REQUIRED:
            with self.subTest(target=target):
                result, calls, summary, log = self.exercise(failure=target)
                self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
                self.assertEqual(
                    calls, REQUIRED + ["_candidate-node-deps", "_candidate-unit-suites"]
                )
                self.assertIn("unit\tFAILED\tunit.log", summary)
                self.assertIn(f"unit/{target}\tFAILED\tunit.log", summary)
                self.assertIn("=== candidate: " + target + " ===", log)

    def test_later_artifact_stage_reuses_the_successful_unit_node_setup(self):
        result, calls, summary, _ = self.exercise("unit artifacts")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            calls[:7], REQUIRED + ["_candidate-node-deps", "_candidate-unit-suites"]
        )
        self.assertEqual(calls.count("_candidate-node-deps"), 1)
        self.assertIn("artifacts\tPASSED\tartifacts.log", summary)


if __name__ == "__main__":
    unittest.main()

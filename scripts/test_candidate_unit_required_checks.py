"""The actual unit stage must refuse before expensive setup on a cheap failure."""

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
    "lint-naapp",
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

    def test_each_cheap_failure_is_unit_failure_before_node_or_product_work(self):
        for index, target in enumerate(REQUIRED):
            with self.subTest(target=target):
                result, calls, summary, log = self.exercise(failure=target)
                self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
                self.assertEqual(calls, REQUIRED[: index + 1])
                self.assertIn("unit\tFAILED\tunit.log", summary)
                self.assertIn("=== candidate: " + target + " ===", log)

    def test_artifacts_run_first_and_unit_reuses_their_node_setup(self):
        result, calls, summary, _ = self.exercise("unit artifacts")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            calls[-6:], REQUIRED + ["_candidate-unit-suites"]
        )
        self.assertEqual(calls[:2], ["_candidate-node-deps", "build"])
        self.assertEqual(calls.count("_candidate-node-deps"), 1)
        self.assertEqual([row.split("\t")[0] for row in summary.splitlines()],
                         ["artifacts", "unit"])
        self.assertIn("artifacts\tPASSED\tartifacts.log", summary)
        self.assertIn("unit\tPASSED\tunit.log", summary)


if __name__ == "__main__":
    unittest.main()

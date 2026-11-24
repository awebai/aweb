"""The real candidate suite runs the static stage first and stops on its failure."""

from collections import Counter
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALL = "static checks user-paths unit artifacts integration"


class StaticStageTests(unittest.TestCase):
    def exercise(self, stages=ALL, failure=""):
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
            (root / "host-published-port.log").write_text("host preflight\n")
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"])
            env.pop("CANDIDATE_HOST_PORT_STATUS", None)
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
                timeout=20,
            )
            rows = [
                line.split("\t")
                for line in (root / "summary.tsv").read_text().splitlines()
            ]
            return result, (root / "calls").read_text().splitlines(), rows

    def static_targets(self):
        result, _, rows = self.exercise("static")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        targets = [row[0].split("/", 1)[1] for row in rows if row[0].startswith("static/")]
        self.assertTrue(targets)
        return targets

    def test_static_targets_run_before_any_other_stage_target(self):
        static = self.static_targets()
        result, calls, rows = self.exercise()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls[: len(static)], static)
        self.assertEqual([row[0] for row in rows if "/" not in row[0]], ALL.split())
        self.assertTrue(all(row[1] == "PASSED" for row in rows))

    def test_failed_static_target_stops_the_run_after_static_completes(self):
        static = self.static_targets()
        for target in static:
            with self.subTest(target=target):
                result, calls, rows = self.exercise(failure=target)
                self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
                # Every static result is still collected; nothing else starts.
                self.assertEqual(calls, static)
                verdicts = {row[0]: row[1] for row in rows}
                self.assertEqual(verdicts["static"], "FAILED")
                self.assertEqual(verdicts[f"static/{target}"], "FAILED")
                for stage in ALL.split()[1:]:
                    self.assertEqual(verdicts[stage], "NOT-RUN")
                    self.assertIn(f"candidate: {stage} NOT-RUN", result.stdout)
                self.assertIn("candidate suite FAILED", result.stdout)

    def test_failure_in_a_later_stage_does_not_stop_the_others(self):
        result, calls, rows = self.exercise(failure="check-product-table-writes")
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        verdicts = {row[0]: row[1] for row in rows}
        self.assertEqual(verdicts["static"], "PASSED")
        self.assertEqual(verdicts["checks"], "FAILED")
        for stage in ("user-paths", "unit", "artifacts", "integration"):
            self.assertEqual(verdicts[stage], "PASSED")

    def test_no_target_runs_twice_in_a_full_gate(self):
        result, calls, _ = self.exercise()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        repeated = [target for target, count in Counter(calls).items() if count > 1]
        self.assertEqual(repeated, [])

    def test_ci_type_check_runs_mypy_and_no_style_linter(self):
        recipe = subprocess.run(
            ["make", "-n", "typecheck-naapp"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(recipe.returncode, 0, recipe.stderr)
        self.assertIn("mypy", recipe.stdout)
        self.assertNotIn("ruff", recipe.stdout)


if __name__ == "__main__":
    unittest.main()

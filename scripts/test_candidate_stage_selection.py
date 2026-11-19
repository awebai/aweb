"""Stage admission uses real shell/Make entry points, without service doubles."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
OWNER = ROOT / "scripts/vm-gate/vm_gate/aweb_stages.py"
ALL = "checks user-paths unit artifacts integration"


class StageSelectionTests(unittest.TestCase):
    def test_default_and_all_select_every_stage(self):
        for arguments in ([], ["all"], [ALL]):
            result = subprocess.run(
                ["python3", str(OWNER), *arguments], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), ALL)

    def test_all_keeps_artifact_mutations_before_parallel_unit_and_integration(self):
        result = subprocess.run(
            ["python3", str(OWNER), "--batches", "all"], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["checks", "user-paths", "artifacts", "unit integration"],
        )

    def test_single_selected_lane_stays_a_complete_stage(self):
        for selection in ("unit", "integration", "unit artifacts"):
            result = subprocess.run(
                ["python3", str(OWNER), "--batches", selection],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), selection.split())

    def test_explicit_subset_is_partial(self):
        result = subprocess.run(
            ["python3", str(OWNER), "--coverage", "checks unit"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "partial")

    def test_bad_selection_refuses_before_real_make_can_start(self):
        for selection in ("unit checks", "checks checks", "unknown", "all unit"):
            with (
                self.subTest(selection=selection),
                tempfile.TemporaryDirectory() as temp,
            ):
                root = Path(temp)
                (root / "Makefile").write_text(
                    ".DEFAULT:\n\t@touch stage-started\n\t@exit 97\n"
                )
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/candidate-suite.sh"), selection],
                    cwd=root,
                    env=dict(os.environ, CANDIDATE_LOG_DIR=str(root)),
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("Choose all or an ordered subset", result.stderr)
                self.assertFalse((root / "stage-started").exists())


if __name__ == "__main__":
    unittest.main()

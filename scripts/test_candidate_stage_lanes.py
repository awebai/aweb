"""Real child processes qualify the gate's readiness and completion barriers."""

import os
from pathlib import Path
import subprocess
import signal
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StageLaneTests(unittest.TestCase):
    def execute(self, *, unit_status=0, integration_status=0, preparation_status=0):
        with tempfile.TemporaryDirectory(prefix="candidate-lanes-") as temporary:
            root = Path(temporary)
            (root / "ready.py").write_text(
                "import sys\n"
                + f"sys.path.insert(0, {str(ROOT / 'scripts/test-egress')!r})\n"
                + "from docker import notify_isolated_unit_ready\n"
                + "notify_isolated_unit_ready()\n"
            )
            (root / "Makefile").write_text(
                "ready:\n\t@python3 " + str(root / "ready.py") + "\n"
            )
            body = r"""
set -euo pipefail
log_dir="$1"
source "$2/scripts/candidate-stage-lanes.sh"
stages='unit integration'
prepare_stage() { :; }
unit() {
  if [[ "$PREPARATION_STATUS" != 0 ]]; then return "$PREPARATION_STATUS"; fi
  printf 'unit source frozen\n' > "$log_dir/frozen"
  make --no-print-directory -s -f "$log_dir/Makefile" ready
  # This is an event barrier, not a sleep: serial execution deadlocks here.
  read -r reply < "$log_dir/integration-started"
  [[ "$reply" == started ]]
  printf 'unit finished\n'
  return "$UNIT_STATUS"
}
integration() {
  [[ -f "$log_dir/frozen" ]]
  printf 'started\n' > "$log_dir/integration-started"
  printf 'integration finished\n'
  return "$INTEGRATION_STATUS"
}
mkfifo "$log_dir/integration-started"
run_parallel_stages
"""
            process = subprocess.Popen(
                ["bash", "-c", body, "lane-test", str(root), str(ROOT)],
                env={
                    **os.environ,
                    "UNIT_STATUS": str(unit_status),
                    "INTEGRATION_STATUS": str(integration_status),
                    "PREPARATION_STATUS": str(preparation_status),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
                raise
            result = subprocess.CompletedProcess(
                process.args, process.returncode, stdout, stderr
            )
            files = {p.name: p.read_text() for p in root.iterdir() if p.is_file()}
            return result, files

    def test_isolated_unit_and_integration_overlap_and_both_finish(self):
        result, files = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(files["unit.result"].split("\t")[:2], ["unit", "PASSED"])
        self.assertEqual(
            files["integration.result"].split("\t")[:2], ["integration", "PASSED"]
        )
        self.assertEqual(files["unit.log"], "unit finished\n")
        self.assertEqual(files["integration.log"], "integration finished\n")

    def test_unit_failure_does_not_hide_integration_result(self):
        result, files = self.execute(unit_status=23)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files["unit.result"].split("\t")[1], "FAILED")
        self.assertEqual(files["integration.result"].split("\t")[1], "PASSED")

    def test_integration_failure_does_not_hide_unit_result(self):
        result, files = self.execute(integration_status=37)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files["unit.result"].split("\t")[1], "PASSED")
        self.assertEqual(files["integration.result"].split("\t")[1], "FAILED")

    def test_ledger_records_both_lanes_after_one_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "unit.log").write_text("unit failure")
            (root / "integration.log").write_text("integration passed")
            (root / "summary.tsv").write_text(
                "unit\tFAILED\tunit.log\t1s\nintegration\tPASSED\tintegration.log\t1s\n"
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    """
source "$1/scripts/candidate-stage-lanes.sh"
LOG_DIR="$2"; pending='unit integration'; run_log="$2/unit.log"
record() { printf '%s %s\n' "$1" "$2"; }
record_completed_stages
""",
                    "records",
                    str(ROOT),
                    str(root),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                result.stdout.splitlines(), ["unit failed", "integration passed"]
            )

    def test_failed_preparation_cannot_release_integration(self):
        result, files = self.execute(preparation_status=19)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files["unit.result"].split("\t")[1], "FAILED")
        self.assertNotIn("integration.result", files)
        self.assertIn("Inspect unit.log", result.stderr)


if __name__ == "__main__":
    unittest.main()

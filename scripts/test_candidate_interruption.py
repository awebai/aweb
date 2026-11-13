"""Real gate recording/TERM behavior with a small child, without Docker."""
import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CandidateInterruption(unittest.TestCase):
    def invoke(self, *, status=143, signal_number=None, run_id="test-run", empty_log=False, repeat=False, corrupt_summary=False, cleanup_control=False, parent_only=False, late_summary=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        logs = root / "stage-logs"
        logs.mkdir()
        (root / "ledger-logs").mkdir()
        ledger = root / "ledger.tsv"
        ledger.touch()
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        tail = source[source.index("# The child owns Docker cleanup."):]
        if repeat:
            tail = tail.replace('finalize_candidate "$status"', 'finalize_candidate "$status"; finalize_candidate "$status"')
        child = '''#!/usr/bin/env bash
set -euo pipefail
run_candidate() {
 if [[ "$CLEANUP_CONTROL" == 1 ]]; then
  cleanup_control() {
   trap '' INT TERM
   if [[ -n \"${fake_stage:-}\" ]]; then kill -TERM \"$fake_stage\" 2>/dev/null || true; wait \"$fake_stage\" || true; fi
   printf 'child cleanup started\\n'
   sleep .1
   if [[ \"$LATE_SUMMARY\" == 1 ]]; then printf 'checks\\tPASSED\\tchecks.log\\t1s\\t\\n' > \"$LOG_DIR/summary.tsv\"; fi
   printf 'child cleanup finished\\n'
   touch "$LOG_DIR/child-cleaned"
   printf 'candidate gate cleanup PASSED\\n' > "$LOG_DIR/wrapper-verdict.log"
   exit "$1"
  }
  trap 'cleanup_control 143' TERM
  trap 'cleanup_control 130' INT
 fi
 printf '%s\\n' "$CONTROL_RUN_ID" > "$LOG_DIR/run-id"
 printf 'checks\\tPASSED\\tchecks.log\\t1s\\t\\nartifacts\\tPASSED\\tartifacts.log\\t2s\\t\\n' > "$LOG_DIR/summary.tsv"
 if [[ "$EMPTY_LOG" == 0 ]]; then printf 'real completed checks\\n' > "$LOG_DIR/checks.log"; else : > "$LOG_DIR/checks.log"; fi
 printf 'real completed artifacts\\n' > "$LOG_DIR/artifacts.log"
 printf 'integration incomplete\\n' > "$LOG_DIR/integration.log"
 if [[ "$CORRUPT_SUMMARY" == 1 ]]; then printf 'checks\\tPASSED\\twrong.log\\t1s\\n' > "$LOG_DIR/summary.tsv"; fi
 if [[ "$CLEANUP_CONTROL" == 1 ]]; then printf 'checks\\tPASSED\\tchecks.log\\t1s\\t\\n' > "$LOG_DIR/summary.tsv"; fi
 touch "$LOG_DIR/ready"
 if [[ "$CONTROL_STATUS" == 0 ]]; then
  printf 'integration\\tPASSED\\tintegration.log\\t1s\\t\\n' >> "$LOG_DIR/summary.tsv"
 fi
 if [[ "$CONTROL_SIGNAL" != 0 ]]; then sleep 30 & fake_stage=$!; wait "$fake_stage"; fi
 printf 'candidate gate cleanup PASSED\\n' > "$LOG_DIR/wrapper-verdict.log"
 exit "$CONTROL_STATUS"
}
'''
        program = root / "control.sh"
        program.write_text(child + tail)
        env = dict(os.environ, ROOT=str(ROOT), LOG_DIR=str(logs), LEDGER_LOGS=str(root / "ledger-logs"),
                   LEDGER=str(ledger), KEY="tree-inputs", SOURCE_SHA="a" * 40, OWNER="control",
                   pending="checks artifacts integration", run_id="test-run", CONTROL_RUN_ID=run_id,
                   CONTROL_STATUS=str(status), CONTROL_SIGNAL=str(signal_number or 0), EMPTY_LOG=str(int(empty_log)), CORRUPT_SUMMARY=str(int(corrupt_summary)), CLEANUP_CONTROL=str(int(cleanup_control)), LATE_SUMMARY=str(int(late_summary)))
        env.pop("AWEB_GATE_RUN_REGISTRY", None)  # Private fixtures do not attest outer gate cleanup.
        process = subprocess.Popen(["bash", str(program)], env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        if signal_number:
            deadline = time.monotonic() + 3
            while not (logs / "ready").exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue((logs / "ready").exists())
            os.kill(process.pid, signal_number) if parent_only else os.killpg(process.pid, signal_number)
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=3)
        rows = [line.split("\t") for line in ledger.read_text().splitlines()]
        return process.returncode, rows, logs, stdout + stderr

    def test_cleanup_survives_group_term(self):
        self.cleanup_assertions(signal.SIGTERM)

    def test_cleanup_survives_parent_only_term(self):
        self.cleanup_assertions(signal.SIGTERM, parent_only=True)

    def test_cleanup_survives_group_int(self):
        self.cleanup_assertions(signal.SIGINT)

    def test_interrupted_summary_survives_late_child_summary_write(self):
        self.cleanup_assertions(signal.SIGTERM, late_summary=True)

    def cleanup_assertions(self, signum, parent_only=False, late_summary=False):
        code, rows, logs, output = self.invoke(signal_number=signum, cleanup_control=True, parent_only=parent_only, late_summary=late_summary)
        self.assertEqual(code, 128 + signum, output)
        self.assertEqual([(r[1], r[2]) for r in rows], [("checks", "passed")])
        self.assertTrue((logs / "child-cleaned").exists(), "child cleanup did not complete")
        run_log = Path(rows[0][5]).parent / "tree-inputs-run-test-run.log"
        self.assertIn("child cleanup finished", run_log.read_text())
        self.assertIn("run\tINTERRUPTED\t", (logs / "summary.tsv").read_text())
        self.assertIn("cleanup=passed", (logs / "interruption.tsv").read_text())

    def test_child_interrupted_status_preserves_only_completed_stages(self):
        for status in (130, 143):
            with self.subTest(status=status):
                code, rows, logs, output = self.invoke(status=status)
                self.assertEqual(code, status, output)
                self.assertEqual([(r[1], r[2]) for r in rows], [("checks", "passed"), ("artifacts", "passed")])
                self.assertIn("run\tINTERRUPTED\t", (logs / "summary.tsv").read_text())
                self.assertTrue(all(Path(r[5]).stat().st_size for r in rows))

    def test_real_term_keeps_raw_status_and_passed_rows(self):
        code, rows, logs, output = self.invoke(signal_number=signal.SIGTERM)
        self.assertEqual(code, 143, output)
        self.assertEqual([r[1] for r in rows], ["checks", "artifacts"])
        self.assertEqual((logs / "summary.tsv").read_text().count("run\tINTERRUPTED\t"), 1)

    def test_stale_summary_refuses_recording(self):
        code, rows, _, _ = self.invoke(run_id="old-run")
        self.assertEqual(code, 143)
        self.assertEqual(rows, [])

    def test_empty_stage_log_cannot_supply_pass(self):
        code, rows, _, _ = self.invoke(empty_log=True)
        self.assertEqual(code, 143)
        self.assertNotIn("checks", [r[1] for r in rows])

    def test_duplicate_finalization_does_not_duplicate_rows(self):
        code, rows, logs, output = self.invoke(repeat=True)
        self.assertEqual(code, 143, output)
        self.assertEqual([r[1] for r in rows], ["checks", "artifacts"])
        self.assertEqual((logs / "summary.tsv").read_text().count("run\tINTERRUPTED\t"), 1)

    def test_wrong_summary_log_reference_cannot_supply_pass(self):
        code, rows, _, _ = self.invoke(corrupt_summary=True)
        self.assertEqual(code, 143)
        self.assertEqual(rows, [])

    def test_normal_success_and_failure_still_record(self):
        code, rows, _, output = self.invoke(status=0)
        self.assertEqual(code, 0, output)
        self.assertEqual([r[2] for r in rows], ["passed"] * 3)
        code, rows, _, output = self.invoke(status=1)
        self.assertEqual(code, 1, output)
        self.assertEqual([(r[1], r[2]) for r in rows], [("checks", "passed"), ("artifacts", "passed"), ("integration", "failed")])

    def test_reused_artifacts_still_prepare_integration_inputs(self):
        # First retain the actual interrupted artifacts row; the resumed suite
        # starts in a fresh directory with none of its disposable outputs.
        _, rows, _, _ = self.invoke()
        self.assertIn(("artifacts", "passed"), [(r[1], r[2]) for r in rows])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            make = bin_dir / "make"
            make.write_text("#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$CALLS\"\n"
                            "case \"$1\" in _candidate-node-deps) touch node-output;; build) touch cli-output;; "
                            "test-e2e) test -f node-output && test -f cli-output;; esac\n")
            make.chmod(0o755)
            logs = root / "logs"
            logs.mkdir()
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                       CALLS=str(root / "calls"), CANDIDATE_LOG_DIR=str(logs))
            result = subprocess.run(["bash", str(ROOT / "scripts/candidate-suite.sh"), "integration"],
                                    cwd=root, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = (root / "calls").read_text().splitlines()
            self.assertEqual(calls[:2], ["_candidate-node-deps", "build"])
            self.assertIn("test-e2e", calls)
            self.assertFalse(any(c.startswith("_candidate-artifact-") for c in calls))


if __name__ == "__main__":
    unittest.main()

"""Real gate recording/TERM behavior with a small child, without Docker."""

import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class CandidateInterruption(unittest.TestCase):
    def invoke(
        self,
        *,
        status=143,
        signal_number=None,
        run_id="test-run",
        empty_log=False,
        repeat=False,
        corrupt_summary=False,
        target_summary=False,
        cleanup_control=False,
        during_cleanup="",
        parent_only=False,
        late_summary=False,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        logs = root / "stage-logs"
        (root / "ledger-logs").mkdir()
        ledger = root / "ledger.tsv"
        ledger.touch()
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        tail = source[source.index("# The child owns Docker cleanup.") :]
        if repeat:
            tail = tail.replace(
                'finalize_candidate "$status"',
                'finalize_candidate "$status"; finalize_candidate "$status"',
            )
        child = """#!/usr/bin/env bash
set -euo pipefail
# This fixture exercises signal handling without a Docker data volume.
wait_for_disk() { :; }
run_candidate() {
 if [[ "$CLEANUP_CONTROL" == 1 ]]; then
  cleanup_control() {
   trap '' INT TERM
   if [[ -n \"${fake_stage:-}\" ]]; then kill -TERM \"$fake_stage\" 2>/dev/null || true; wait \"$fake_stage\" || true; fi
   printf 'child cleanup started\\n'
   sleep .1
   if [[ \"$LATE_SUMMARY\" == 1 ]]; then printf 'checks\\tPASSED\\tchecks.log\\t1s\\t\\nartifacts\\tPASSED\\tartifacts.log\\t2s\\t\\n' > \"$LOG_DIR/summary.tsv\"; fi
   printf 'child cleanup finished\\n'
   touch "$LOG_DIR/child-cleaned"
   printf 'candidate gate cleanup PASSED\\n' | tee "$LOG_DIR/wrapper-verdict.log"
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
 mkdir -p "$LOG_DIR/test-egress"
 for number in {1..200}; do printf 'full child traceback line %s\\n' "$number"; done > "$LOG_DIR/test-egress/suite.log"
 if [[ "$CORRUPT_SUMMARY" == 1 ]]; then printf 'checks\\tPASSED\\twrong.log\\t1s\\n' > "$LOG_DIR/summary.tsv"; fi
 if [[ "$CLEANUP_CONTROL" == 1 ]]; then printf 'checks\\tPASSED\\tchecks.log\\t1s\\t\\n' > "$LOG_DIR/summary.tsv"; fi
 if [[ "$CONTROL_STATUS" == 0 ]]; then
  printf 'integration\\tPASSED\\tintegration.log\\t1s\\t\\n' >> "$LOG_DIR/summary.tsv"
 fi
 if [[ "$TARGET_SUMMARY" == 1 ]]; then
  printf 'checks\\tFAILED\\tchecks.log\\t1s\\nartifacts\\tPASSED\\tartifacts.log\\t2s\\n' > "$LOG_DIR/summary.tsv"
  printf 'checks/check-product-table-writes\\tFAILED\\tchecks.log\\t1s\\texit 23\\nartifacts/build\\tPASSED\\tartifacts.log\\t2s\\n' >> "$LOG_DIR/summary.tsv"
  printf 'integration/e2e-naapp\\tSKIPPED\\tintegration.log\\t0s\\tbuild FAILED\\n' >> "$LOG_DIR/summary.tsv"
 fi
 if [[ -n "$DURING_CLEANUP" ]]; then
  source "$ROOT/scripts/candidate-cleanup.sh"
  resource_label=fixture runner_name=runner IMAGE=image
  suite_projects=(fixture)
  work="$LOG_DIR/aweb-candidate-work.fixture"
  touch "$LOG_DIR/owned-resources.tsv" "$LOG_DIR/host-before.json"
  docker() {
   case "$1 ${2:-}" in
    "container inspect")
     touch "$LOG_DIR/ready"
     while [[ ! -e "$LOG_DIR/release" ]]; do sleep .01; done
     if [[ "$DURING_CLEANUP" == "absent" ]]; then exit 1; fi
     return 1 ;;
    "image inspect") return 1 ;;
    "info ") [[ "$DURING_CLEANUP" == passed ]] ;;
   esac
  }
  # The measurement and Docker commands are stand-ins. Cleanup and the
  # wrapper's signal handling, verdict writer and ledger are real.
  python3() { return 0; }
  cleanup 0
 fi
 if [[ "$CONTROL_SIGNAL" != 0 ]]; then
  sleep 30 & fake_stage=$!
  # Publish readiness only after cleanup can name the live child.
  touch "$LOG_DIR/ready"
  wait "$fake_stage"
 else
  touch "$LOG_DIR/ready"
 fi
 printf 'candidate gate cleanup PASSED\\n' | tee "$LOG_DIR/wrapper-verdict.log"
 exit "$CONTROL_STATUS"
}
"""
        program = root / "control.sh"
        program.write_text(child + tail)
        env = dict(
            os.environ,
            ROOT=str(ROOT),
            LOG_DIR=str(logs),
            LEDGER_LOGS=str(root / "ledger-logs"),
            LEDGER=str(ledger),
            KEY="tree-inputs",
            SOURCE_SHA="a" * 40,
            OWNER="control",
            pending="checks artifacts integration",
            run_id="test-run",
            CONTROL_RUN_ID=run_id,
            CONTROL_STATUS=str(status),
            CONTROL_SIGNAL=str(signal_number or 0),
            EMPTY_LOG=str(int(empty_log)),
            CORRUPT_SUMMARY=str(int(corrupt_summary)),
            TARGET_SUMMARY=str(int(target_summary)),
            CLEANUP_CONTROL=str(int(cleanup_control)),
            DURING_CLEANUP=during_cleanup,
            LATE_SUMMARY=str(int(late_summary)),
        )
        env.pop(
            "AWEB_GATE_RUN_REGISTRY", None
        )  # Private fixtures do not attest outer gate cleanup.
        process = subprocess.Popen(
            ["bash", str(program)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        if signal_number:
            deadline = time.monotonic() + 3
            while (
                not (logs / "ready").exists()
                and process.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertTrue((logs / "ready").exists())
            os.kill(process.pid, signal_number) if parent_only else os.killpg(
                process.pid, signal_number
            )
            if during_cleanup:
                (logs / "release").touch()
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

    def test_term_during_cleanup_controls_reuse(self):
        gate = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        lookup = gate[gate.index("recorded() {") : gate.index("run_candidate() {")]
        for verdict in ("failed", "absent", "passed"):
            with self.subTest(verdict=verdict):
                code, rows, logs, output = self.invoke(
                    status=0,
                    signal_number=signal.SIGTERM,
                    parent_only=True,
                    during_cleanup=verdict,
                )
                self.assertEqual(code, 143, output)
                self.assertIn(
                    f"cleanup={verdict}", (logs / "interruption.tsv").read_text()
                )
                result = subprocess.run(
                    ["bash", "-ec", lookup + "\nexit 99"],
                    env=dict(
                        os.environ,
                        TREE="tree",
                        KEY="tree-inputs",
                        LEDGER=str(logs.parent / "ledger.tsv"),
                        REQUESTED="checks artifacts integration",
                    ),
                    capture_output=True,
                    text=True,
                )
                expected = "passed" if verdict == "passed" else "failed"
                self.assertEqual([r[2] for r in rows if r[1] == "cleanup"], [expected])
                self.assertEqual(result.returncode, 0 if expected == "passed" else 1)
                if expected == "passed":
                    self.assertIn("no stages run", result.stdout)
                else:
                    self.assertIn("already FAILED cleanup", result.stderr)
                    self.assertFalse(
                        any(r[1] != "cleanup" and r[2] == "passed" for r in rows)
                    )

    def test_interrupted_summary_survives_late_child_summary_write(self):
        self.cleanup_assertions(signal.SIGTERM, late_summary=True)

    def cleanup_assertions(self, signum, parent_only=False, late_summary=False):
        code, rows, logs, output = self.invoke(
            signal_number=signum,
            cleanup_control=True,
            parent_only=parent_only,
            late_summary=late_summary,
        )
        self.assertEqual(code, 128 + signum, output)
        self.assertEqual(
            [(r[1], r[2]) for r in rows], [("cleanup", "passed"), ("checks", "passed")]
        )
        self.assertTrue(
            (logs / "child-cleaned").exists(), "child cleanup did not complete"
        )
        run_log = Path(rows[0][5]).parent / "tree-inputs-run-test-run.log"
        self.assertIn("child cleanup finished", run_log.read_text())
        self.assertIn("run\tINTERRUPTED\t", (logs / "summary.tsv").read_text())
        self.assertIn("cleanup=passed", (logs / "interruption.tsv").read_text())

    def test_child_interrupted_status_preserves_only_completed_stages(self):
        for status in (130, 143):
            with self.subTest(status=status):
                code, rows, logs, output = self.invoke(status=status)
                self.assertEqual(code, status, output)
                self.assertEqual(
                    [(r[1], r[2]) for r in rows],
                    [
                        ("cleanup", "passed"),
                        ("checks", "passed"),
                        ("artifacts", "passed"),
                    ],
                )
                self.assertIn("run\tINTERRUPTED\t", (logs / "summary.tsv").read_text())
                self.assertTrue(all(Path(r[5]).stat().st_size for r in rows))

    def test_real_term_without_cleanup_blocks_reuse(self):
        code, rows, logs, output = self.invoke(signal_number=signal.SIGTERM)
        self.assertEqual(code, 143, output)
        self.assertEqual([r[1:3] for r in rows], [["cleanup", "failed"]])
        self.assertEqual(
            (logs / "summary.tsv").read_text().count("run\tINTERRUPTED\t"), 1
        )

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
        self.assertEqual([r[1] for r in rows], ["cleanup", "checks", "artifacts"])
        self.assertEqual(
            (logs / "summary.tsv").read_text().count("run\tINTERRUPTED\t"), 1
        )

    def test_wrong_summary_log_reference_cannot_supply_pass(self):
        code, rows, _, _ = self.invoke(corrupt_summary=True)
        self.assertEqual(code, 143)
        self.assertEqual([r[1:3] for r in rows], [["cleanup", "passed"]])

    def test_normal_success_and_failure_still_record(self):
        code, rows, _, output = self.invoke(status=0)
        self.assertEqual(code, 0, output)
        self.assertEqual([r[2] for r in rows], ["passed"] * 3)
        code, rows, _, output = self.invoke(status=1)
        self.assertEqual(code, 1, output)
        self.assertEqual(
            [(r[1], r[2]) for r in rows],
            [("checks", "passed"), ("artifacts", "passed"), ("integration", "failed")],
        )

    def test_target_rows_survive_failure_and_interruption(self):
        for status in (1, 143):
            with self.subTest(status=status):
                code, rows, _, output = self.invoke(status=status, target_summary=True)
                self.assertEqual(code, status, output)
                by_entry = {row[1]: row for row in rows}
                self.assertEqual(by_entry["artifacts"][2], "passed")
                self.assertEqual(by_entry["checks/check-product-table-writes"][2], "failed")
                self.assertEqual(by_entry["artifacts/build"][2], "passed")
                skipped = by_entry["integration/e2e-naapp"]
                self.assertEqual(skipped[2], "skipped")
                self.assertEqual(skipped[9], "build FAILED, 0s")
                self.assertTrue(all(Path(row[5]).is_file() for row in rows))

    def test_full_child_log_and_summary_survive_in_ledger_evidence(self):
        for status in (0, 1, 143):
            with self.subTest(status=status):
                code, _, logs, output = self.invoke(status=status)
                self.assertEqual(code, status, output)
                retained = logs.parent / "ledger-logs/tree-inputs-evidence-test-run"
                self.assertTrue((retained / "test-egress/suite.log").is_file())
                self.assertTrue((retained / "summary.tsv").is_file())
                self.assertEqual(
                    (retained / "test-egress/suite.log").read_bytes(),
                    (logs / "test-egress/suite.log").read_bytes(),
                )
                self.assertEqual(
                    (retained / "summary.tsv").read_bytes(),
                    (logs / "summary.tsv").read_bytes(),
                )

    def test_docker_proof_command_resolves_from_supervisor_directory(self):
        import test_candidate_gate_ledger as proof

        class CapturedCommandError(Exception):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "fixture"
            (fixture / "scripts").mkdir(parents=True)
            expected = fixture / "scripts/candidate-docker-gate.sh"
            expected.write_text("exit 0\n")
            evidence = root / "evidence"
            evidence.mkdir()
            with (
                patch.object(proof, "checked", return_value="a" * 40),
                patch.object(
                    proof.subprocess, "Popen", side_effect=CapturedCommandError
                ) as launch,
                self.assertRaises(CapturedCommandError),
            ):
                proof.interrupted_docker_proof(fixture, evidence, {})
            target = Path(launch.call_args.args[0][-1])
            resolved = (
                target if target.is_absolute() else evidence / "supervised" / target
            )
            self.assertTrue(
                resolved.is_file(),
                "proof gate command does not resolve from supervisor cwd",
            )
            self.assertEqual(resolved, expected)

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
            make.write_text(
                '#!/bin/sh\nprintf \'%s\\n\' "$1" >> "$CALLS"\n'
                'case "$1" in _candidate-node-deps) touch node-output;; build) touch cli-output;; '
                "test-e2e) test -f node-output && test -f cli-output;; esac\n"
            )
            make.chmod(0o755)
            logs = root / "logs"
            logs.mkdir()
            env = dict(
                os.environ,
                PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                CALLS=str(root / "calls"),
                CANDIDATE_LOG_DIR=str(logs),
            )
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/candidate-suite.sh"), "integration"],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = (root / "calls").read_text().splitlines()
            self.assertEqual(calls[:2], ["_candidate-node-deps", "build"])
            self.assertIn("test-e2e", calls)
            self.assertFalse(any(c.startswith("_candidate-artifact-") for c in calls))


if __name__ == "__main__":
    unittest.main()

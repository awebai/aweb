"""The journey's revocation probe, run from its own file with a fake clock and aw."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest

PROBE = Path(__file__).with_name("lib") / "revocation-probe.sh"
REFUSAL = (
    '{"error":{"code":"http_error","http_status":401,"reason":"certificate_revoked"}}'
)

# The fake clock is a file: aw attempts spend time on it, pauses add to it.
FAKES = r"""
monotonic_seconds() { cat "$CLOCK"; }
probe_sleep() { echo $(( $(cat "$CLOCK") + $1 )) >"$CLOCK"; }
# Only the attempt in flight moves the clock while the probe waits for it.
probe_poll() { sleep 0.01; }
run_aw_in() {
  local n
  n=$(( $(cat "$ATTEMPTS") + 1 )); echo "$n" >"$ATTEMPTS"
  echo $(( $(cat "$CLOCK") + ATTEMPT_TAKES )) >"$CLOCK"
  if (( n >= REFUSE_AT )); then printf '%s\n' "$REFUSAL"; return 1; fi
  printf '{"status":"delivered"}\n'
}
"""


class RevocationProbe(unittest.TestCase):
    def probe(self, *, attempt_takes, refuse_at, window=120):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "clock").write_text("0\n")
            (root / "attempts").write_text("0\n")
            script = "\n".join(
                [
                    "set -euo pipefail",
                    f"source {shlex.quote(str(PROBE))}",
                    FAKES,
                    f'probe_revocation "$DIR" 0 {window}',
                    'cat "$DIR/verdict"',
                ]
            )
            result = subprocess.run(
                ["bash", "-c", script],
                env=dict(
                    os.environ,
                    DIR=str(root),
                    CLOCK=str(root / "clock"),
                    ATTEMPTS=str(root / "attempts"),
                    ATTEMPT_TAKES=str(attempt_takes),
                    REFUSE_AT=str(refuse_at),
                    REFUSAL=REFUSAL,
                    BOB_DIR=str(root),
                ),
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            seconds = root / "seconds"
            return (
                result.stdout.strip(),
                int(seconds.read_text()) if seconds.exists() else None,
                (root / "refusal.json").read_text().strip()
                if (root / "refusal.json").exists()
                else None,
            )

    def test_a_refusal_within_the_window_is_recorded(self):
        verdict, seconds, refusal = self.probe(attempt_takes=2, refuse_at=3)
        self.assertEqual(verdict, "refused")
        self.assertLessEqual(seconds, 125)
        self.assertEqual(refusal, REFUSAL)

    def test_a_correct_refusal_completing_after_the_window_is_late(self):
        # The 401 is right, but the attempt that returns it ends at 126 s.
        verdict, seconds, refusal = self.probe(attempt_takes=126, refuse_at=1)
        self.assertEqual(verdict, "late")
        self.assertGreater(seconds, 125)
        self.assertIsNone(refusal)

    def test_a_member_never_refused_is_accepted_at_the_deadline(self):
        verdict, _, _ = self.probe(attempt_takes=1, refuse_at=10**6)
        self.assertEqual(verdict, "accepted")

    def test_stopping_ends_the_probe_and_its_attempt_in_flight(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_file = root / "attempt.pid"
            script = "\n".join(
                [
                    "set -euo pipefail",
                    f"source {shlex.quote(str(PROBE))}",
                    # A real attempt in flight: a child process the probe started.
                    'run_aw_in() { sleep 30 & echo $! >"$PID_FILE"; wait; }',
                    'start_revocation_probe "$DIR" "$(monotonic_seconds)" 120',
                    'for _ in $(seq 1 100); do [[ -s "$PID_FILE" ]] && break; sleep 0.05; done',
                    "started=$(monotonic_seconds)",
                    "stop_revocation_probe",
                    'echo "stopped in $(( $(monotonic_seconds) - started ))s"',
                ]
            )
            result = subprocess.run(
                ["bash", "-c", script],
                env=dict(
                    os.environ, DIR=str(root), PID_FILE=str(pid_file), BOB_DIR=str(root)
                ),
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("stopped in 0s", result.stdout)
            attempt = int(pid_file.read_text())
            # The in-flight command is gone, not orphaned.
            for _ in range(50):
                try:
                    os.kill(attempt, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                os.kill(attempt, 9)
                self.fail(
                    f"the attempt in flight ({attempt}) survived stop_revocation_probe"
                )


if __name__ == "__main__":
    unittest.main()

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

# The fake clock is a file of milliseconds: aw attempts spend time on it and
# pauses add to it. Only the attempt in flight moves it while the probe waits.
FAKE_CLOCK = r"""
monotonic_ms() { cat "$CLOCK"; }
probe_sleep() { awk -v at="$(cat "$CLOCK")" -v s="$1" 'BEGIN { printf "%d\n", at + s * 1000 }' >"$CLOCK.next"; mv "$CLOCK.next" "$CLOCK"; }
probe_poll() { sleep 0.01; }
"""
FAKE_AW = r"""
run_aw_in() {
  local n
  n=$(( $(cat "$ATTEMPTS") + 1 )); echo "$n" >"$ATTEMPTS"
  echo $(( $(cat "$CLOCK") + ATTEMPT_TAKES_MS )) >"$CLOCK"
  if (( n >= REFUSE_AT )); then printf '%s\n' "$REFUSAL"; return 1; fi
  printf '{"status":"delivered"}\n'
}
"""
# An attempt that outlives the deadline: it moves the clock past it, then stays
# in flight as a child process. A resistant one ignores TERM.
IN_FLIGHT_AW = r"""
run_aw_in() {
  echo $(( $(cat "$CLOCK") + 200000 )) >"$CLOCK"
  if [[ -n "${RESISTANT:-}" ]]; then
    bash -c 'trap "" TERM; while :; do sleep 0.05; done' &
  else
    sleep 30 &
  fi
  echo $! >"$PID_FILE"
  wait
}
"""


def alive(pid):
    try:
        state = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True
        ).stdout.strip()
    except OSError:
        return False
    return bool(state) and not state.startswith("Z")


class RevocationProbe(unittest.TestCase):
    def run_bash(self, root, body, **env):
        script = "\n".join(
            ["set -euo pipefail", f"source {shlex.quote(str(PROBE))}", body]
        )
        started = time.monotonic()
        result = subprocess.run(
            ["bash", "-c", script],
            env=dict(os.environ, DIR=str(root), BOB_DIR=str(root), **env),
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result, time.monotonic() - started

    def probe(self, *, anchor_ms, attempt_takes_ms, refuse_at, window=120):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "clock").write_text(f"{anchor_ms}\n")
            (root / "attempts").write_text("0\n")
            result, _ = self.run_bash(
                root,
                FAKE_CLOCK
                + FAKE_AW
                + f'probe_revocation "$DIR" {anchor_ms} {window}\ncat "$DIR/verdict"',
                CLOCK=str(root / "clock"),
                ATTEMPTS=str(root / "attempts"),
                ATTEMPT_TAKES_MS=str(attempt_takes_ms),
                REFUSE_AT=str(refuse_at),
                REFUSAL=REFUSAL,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            elapsed = root / "elapsed-ms"
            return result.stdout.strip(), int(
                elapsed.read_text()
            ) if elapsed.exists() else None

    def test_a_refusal_within_the_window_is_recorded(self):
        verdict, elapsed = self.probe(anchor_ms=0, attempt_takes_ms=2000, refuse_at=3)
        self.assertEqual(verdict, "refused")
        self.assertLessEqual(elapsed, 125000)

    def test_a_correct_refusal_completing_after_the_window_is_late(self):
        verdict, elapsed = self.probe(anchor_ms=0, attempt_takes_ms=126000, refuse_at=1)
        self.assertEqual(verdict, "late")
        self.assertGreater(elapsed, 125000)

    def test_a_fraction_of_a_second_late_is_late(self):
        # Removed at 100.1 s, refused at 225.9 s: whole seconds would say 125.
        verdict, elapsed = self.probe(
            anchor_ms=100100, attempt_takes_ms=125800, refuse_at=1
        )
        self.assertEqual(verdict, "late")
        self.assertEqual(elapsed, 125800)

    def test_the_probe_clock_has_subsecond_precision(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, _ = self.run_bash(
                Path(temporary),
                "a=$(monotonic_ms); sleep 0.3; b=$(monotonic_ms); echo $((b - a))",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            # 0.3 s apart, whatever the second boundaries: never 0 or a whole 1000.
            self.assertTrue(250 <= int(result.stdout) < 900, result.stdout)

    def test_a_member_never_refused_is_accepted_at_the_deadline(self):
        verdict, _ = self.probe(anchor_ms=0, attempt_takes_ms=1000, refuse_at=10**6)
        self.assertEqual(verdict, "accepted")

    def test_an_attempt_in_flight_at_the_deadline_is_ended_before_late(self):
        for resistant in ("", "1"):
            with (
                self.subTest(resistant=bool(resistant)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                (root / "clock").write_text("0\n")
                result, seconds = self.run_bash(
                    root,
                    FAKE_CLOCK
                    + IN_FLIGHT_AW
                    + 'probe_revocation "$DIR" 0 120\ncat "$DIR/verdict"',
                    CLOCK=str(root / "clock"),
                    PID_FILE=str(root / "attempt.pid"),
                    RESISTANT=resistant,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "late")
                attempt = int((root / "attempt.pid").read_text())
                # Gone when the verdict is written, not later.
                if alive(attempt):
                    os.kill(attempt, 9)
                    self.fail(
                        f"attempt {attempt} still ran when the probe reported late"
                    )
                self.assertLess(seconds, 15)

    def test_stopping_ends_the_whole_probe_group_and_releases_it(self):
        for resistant in ("", "1"):
            with (
                self.subTest(resistant=bool(resistant)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                pid_file = root / "attempt.pid"
                attempt_aw = (
                    'run_aw_in() { bash -c \'trap "" TERM; while :; do sleep 0.05; done\' & echo $! >"$PID_FILE"; wait; }'
                    if resistant
                    else 'run_aw_in() { sleep 30 & echo $! >"$PID_FILE"; wait; }'
                )
                result, seconds = self.run_bash(
                    root,
                    "\n".join(
                        [
                            attempt_aw,
                            'start_revocation_probe "$DIR" "$(monotonic_ms)" 120',
                            'for _ in $(seq 1 200); do [[ -s "$PID_FILE" ]] && break; sleep 0.05; done',
                            "stop_revocation_probe",
                            'echo "owner=${REVOCATION_PROBE_PID:-none}"',
                        ]
                    ),
                    PID_FILE=str(pid_file),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("owner=none", result.stdout)
                attempt = int(pid_file.read_text())
                if alive(attempt):
                    os.kill(attempt, 9)
                    self.fail(f"attempt {attempt} outlived stop_revocation_probe")
                # TERM, then KILL after a 2 s grace, with room for process start.
                self.assertLess(seconds, 15)


if __name__ == "__main__":
    unittest.main()

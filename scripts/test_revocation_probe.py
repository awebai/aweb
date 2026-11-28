"""The journey's revocation probe (scripts/lib/revocation_probe.py)."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location(
    "revocation_probe", Path(__file__).with_name("lib") / "revocation_probe.py"
)
probe_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe_module)

REFUSAL = (
    b'{"error":{"code":"http_error","http_status":401,"reason":"certificate_revoked"}}'
)


class FakeClock:
    def __init__(self, at_ms):
        self.at = at_ms

    def now(self):
        return self.at

    def sleep(self, seconds):
        self.at += round(seconds * 1000)


class Verdicts(unittest.TestCase):
    def probe(self, *, anchor_ms, takes_ms, refuse_at, window=120, timed_out_at=None):
        clock = FakeClock(anchor_ms)
        timeouts = []

        def send(n, timeout):
            timeouts.append(timeout)
            clock.at += takes_ms
            if timed_out_at is not None and n >= timed_out_at:
                return None
            return (1, REFUSAL) if n >= refuse_at else (0, b'{"status":"delivered"}')

        with tempfile.TemporaryDirectory() as directory:
            verdict = probe_module.probe(
                directory, anchor_ms, window, send, clock=clock.now, pause=clock.sleep
            )
            elapsed = Path(directory, "elapsed-ms")
            refusal = Path(directory, "refusal.json")
            return (
                verdict,
                int(elapsed.read_text()) if elapsed.exists() else None,
                refusal.read_bytes() if refusal.exists() else None,
                timeouts,
            )

    def test_a_refusal_within_the_window_is_refused(self):
        verdict, elapsed, refusal, timeouts = self.probe(
            anchor_ms=0, takes_ms=2000, refuse_at=3
        )
        self.assertEqual(verdict, "refused")
        self.assertLessEqual(elapsed, 125000)
        self.assertEqual(refusal, REFUSAL)
        # Each attempt's timeout is the budget left at its start: attempts take
        # 2 s and pauses 5 s, so 125, 118 and 111 s.
        self.assertEqual(timeouts, [125, 118, 111])

    def test_a_correct_refusal_completing_after_the_window_is_late(self):
        verdict, elapsed, refusal, _ = self.probe(
            anchor_ms=0, takes_ms=126000, refuse_at=1
        )
        self.assertEqual((verdict, refusal), ("late", None))
        self.assertGreater(elapsed, 125000)

    def test_a_fraction_of_a_second_late_is_late(self):
        # Removed at 100.1 s, refused at 225.9 s: whole seconds would say 125.
        verdict, elapsed, refusal, _ = self.probe(
            anchor_ms=100100, takes_ms=125800, refuse_at=1
        )
        self.assertEqual((verdict, elapsed, refusal), ("late", 125800, None))

    def test_an_attempt_ended_at_its_timeout_is_late(self):
        verdict, _, refusal, _ = self.probe(
            anchor_ms=0, takes_ms=1000, refuse_at=99, timed_out_at=2
        )
        self.assertEqual((verdict, refusal), ("late", None))

    def test_a_member_never_refused_is_accepted_at_the_deadline(self):
        verdict, _, _, _ = self.probe(anchor_ms=0, takes_ms=1000, refuse_at=10**6)
        self.assertEqual(verdict, "accepted")

    def test_the_probe_clock_has_subsecond_precision(self):
        first = probe_module.monotonic_ms()
        time.sleep(0.3)
        # 0.3 s apart, whatever the second boundaries: never 0 or a whole 1000.
        self.assertTrue(250 <= probe_module.monotonic_ms() - first < 900)


class Commands(unittest.TestCase):
    def run_probe(self, directory, command, window, env=None):
        anchor = probe_module.monotonic_ms() - (window + 5) * 1000 + 1500
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("lib") / "revocation_probe.py"),
                "--dir",
                directory,
                "--anchor-ms",
                str(anchor),
                "--window",
                str(window),
                "--cwd",
                directory,
                "--",
                *command,
            ],
            capture_output=True,
            timeout=30,
            env=dict(os.environ, **(env or {})),
        )
        return result, Path(directory)

    def test_a_real_refusal_is_recorded_with_its_output(self):
        with tempfile.TemporaryDirectory() as directory:
            command = ["sh", "-c", 'printf "%s" "$REFUSAL"; exit 1', "attempt"]
            result, root = self.run_probe(
                directory, command, window=120, env={"REFUSAL": REFUSAL.decode()}
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "verdict").read_text(), "refused\n")
            self.assertEqual((root / "refusal.json").read_bytes(), REFUSAL)
            self.assertEqual(
                (root / "refused-subject").read_text(), "after-revocation-1\n"
            )

    def test_an_attempt_outliving_the_budget_is_ended_and_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory, "attempt.pid")
            command = ["sh", "-c", f'echo $$ >"{pid_file}"; exec sleep 30', "attempt"]
            started = time.monotonic()
            result, root = self.run_probe(directory, command, window=1)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual((root / "verdict").read_text(), "late\n")
            # Ended at its timeout, long before its own 30 s. The exact budget
            # each attempt gets is test_a_refusal_within_the_window_is_refused's;
            # a wall-clock bound near 1.5 s would measure the host's load.
            self.assertLess(time.monotonic() - started, 20)
            # Observed absent: no such process; any other error surfaces.
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)


if __name__ == "__main__":
    unittest.main()

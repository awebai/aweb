"""The process-group runner the TypeScript dist self-test uses (scripts/lib/bounded_group.py)."""

import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

RUNNER = Path(__file__).with_name("lib") / "bounded_group.py"


def gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


class BoundedGroup(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dir = Path(temporary.name)
        self.verdict = self.dir / "verdict"

    def command(self, seconds, script):
        return [
            sys.executable,
            str(RUNNER),
            "--seconds",
            str(seconds),
            "--verdict",
            str(self.verdict),
            "--",
            "sh",
            "-c",
            script,
        ]

    def run_bounded(self, seconds, script):
        started = time.monotonic()
        # The caller captures the group's output: a descendant holding the
        # pipe would hold this call too.
        result = subprocess.run(
            self.command(seconds, script), capture_output=True, text=True, timeout=30
        )
        return result, time.monotonic() - started

    def pid(self, name):
        return int((self.dir / name).read_text())

    def test_a_group_that_finishes_keeps_the_leaders_status(self):
        result, _ = self.run_bounded(5, "exit 3")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(self.verdict.read_text(), "exit 3\n")

    def test_the_leader_exit_waits_for_its_group_within_the_deadline(self):
        script = f'(sleep 0.5; echo done >"{self.dir}/child") & exit 0'
        result, elapsed = self.run_bounded(10, script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.verdict.read_text(), "exit 0\n")
        self.assertTrue((self.dir / "child").is_file())
        self.assertGreaterEqual(elapsed, 0.5)

    def test_a_descendant_holding_the_captured_pipe_is_ended_at_the_deadline(self):
        script = f"sh -c 'echo $$ >\"{self.dir}/child\"; exec sleep 30' & exit 0"
        result, elapsed = self.run_bounded(1, script)
        self.assertEqual(result.returncode, 254, result.stderr)
        self.assertEqual(self.verdict.read_text(), "timeout\n")
        self.assertIn("bounded_group: TIMEOUT after 1", result.stderr)
        # Ended at the 1 s deadline, long before its own 30 s; a tighter
        # wall-clock bound would measure the host's load.
        self.assertLess(elapsed, 20)
        self.assertTrue(gone(self.pid("child")))

    def test_a_hung_leader_is_ended_at_the_deadline(self):
        result, _ = self.run_bounded(1, f'echo $$ >"{self.dir}/leader"; exec sleep 30')
        self.assertEqual(result.returncode, 254, result.stderr)
        self.assertEqual(self.verdict.read_text(), "timeout\n")
        self.assertTrue(gone(self.pid("leader")))

    def test_a_child_exiting_254_is_not_a_timeout(self):
        result, _ = self.run_bounded(5, "exit 254")
        self.assertEqual(result.returncode, 254)
        self.assertEqual(self.verdict.read_text(), "exit 254\n")
        self.assertNotIn("TIMEOUT", result.stderr)

    def test_an_interrupted_runner_ends_its_group_then_dies_of_the_signal(self):
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=signum.name):
                child = self.dir / "child"
                child.unlink(missing_ok=True)
                runner = subprocess.Popen(
                    self.command(30, f'echo $$ >"{child}"; exec sleep 30'),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                until = time.monotonic() + 10
                while not child.is_file() or not child.read_text().strip():
                    self.assertLess(time.monotonic(), until, "the child never started")
                    time.sleep(0.02)
                runner.send_signal(signum)
                _, stderr = runner.communicate(timeout=20)
                self.assertEqual(runner.returncode, -signum, stderr)
                self.assertEqual(
                    self.verdict.read_text(), f"interrupted {signum.name}\n"
                )
                self.assertTrue(gone(int(child.read_text())))


spec = importlib.util.spec_from_file_location("bounded_group", RUNNER)
bounded_group = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded_group)


class Transitions(unittest.TestCase):
    """In-process controls at the runner's two handoffs, around a real launch."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dir = Path(temporary.name)
        for signum in bounded_group.STOP_SIGNALS:
            self.addCleanup(signal.signal, signum, signal.getsignal(signum))

    def test_a_stop_during_launch_ends_the_launched_group(self):
        child = self.dir / "child"
        real = subprocess.Popen

        def launch_then_stop(*args, **kwargs):
            launched = real(*args, **kwargs)
            # Wait until the command runs, then stop the runner before it has
            # recorded what it launched.
            until = time.monotonic() + 10
            while not child.is_file() or not child.read_text().strip():
                self.assertLess(time.monotonic(), until, "the command never started")
                time.sleep(0.02)
            os.kill(os.getpid(), signal.SIGTERM)
            return launched

        with patch.object(
            bounded_group.subprocess, "Popen", side_effect=launch_then_stop
        ):
            verdict = bounded_group.run(
                30, ["sh", "-c", f'echo $$ >"{child}"; exec sleep 30']
            )
        self.assertEqual(verdict, ("interrupted", signal.SIGTERM))
        self.assertTrue(gone(int(child.read_text())))

    def record_group_calls(self, on_absent=None):
        calls = []
        real = os.killpg

        def killpg(pgid, signum):
            try:
                real(pgid, signum)
            except ProcessLookupError:
                calls.append((signum, "ESRCH"))
                if on_absent:
                    on_absent()
                raise
            calls.append((signum, "ok"))

        return calls, patch.object(bounded_group.os, "killpg", side_effect=killpg)

    def assert_untouched_after_absence(self, calls):
        absent = calls.index((0, "ESRCH"))
        self.assertEqual(
            calls[absent + 1 :],
            [],
            f"the group was used after it was observed empty: {calls}",
        )

    def test_an_observed_empty_group_is_never_signalled_again(self):
        calls, recording = self.record_group_calls()
        with recording:
            verdict = bounded_group.run(10, ["sh", "-c", "exit 0"])
        self.assertEqual(verdict, ("exit", 0))
        self.assert_untouched_after_absence(calls)

    def test_a_stop_as_the_group_empties_does_not_reuse_its_number(self):
        calls, recording = self.record_group_calls(
            on_absent=lambda: os.kill(os.getpid(), signal.SIGTERM)
        )
        with recording:
            verdict = bounded_group.run(10, ["sh", "-c", "exit 0"])
        self.assertEqual(verdict, ("interrupted", signal.SIGTERM))
        self.assert_untouched_after_absence(calls)


if __name__ == "__main__":
    unittest.main()

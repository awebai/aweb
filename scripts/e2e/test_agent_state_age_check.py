"""agent_state_age_check.py's ownership of its calls (aweb-acwd.25.1): one
deadline from launch, observation included, and every call ended with its
group on every path. Real child processes stand where the CLI stands: what
is tested is the check's ownership, not the CLI.

    python3 -I scripts/e2e/test_agent_state_age_check.py
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import agent_state_age_check as check  # noqa: E402

SLEEPER = [sys.executable, "-c", "import time; time.sleep(600)"]


class CallTests(unittest.TestCase):
    def test_an_observation_that_never_holds_uses_the_one_deadline_and_ends_the_group(self):
        call = check.Call(SLEEPER, budget=2)
        began = time.monotonic()
        seen = check.terminated_in_progress(call, lambda: False)
        elapsed = time.monotonic() - began
        # No second budget after the observation: the deadline plus the end's reserve at most.
        self.assertLess(elapsed, 2 + 30)
        self.assertFalse(seen["caught_in_progress"])
        self.assertTrue(seen["group_gone"])
        self.assertIn("passed its deadline", seen["stderr"])

    def test_an_observation_that_raises_ends_the_group_and_fails_the_case_with_the_error(self):
        call = check.Call(SLEEPER, budget=60)

        def started():
            raise RuntimeError("the observation broke")

        seen = check.terminated_in_progress(call, started)
        self.assertFalse(seen["caught_in_progress"])
        self.assertEqual(seen["error"], "RuntimeError: the observation broke")
        self.assertTrue(seen["group_gone"])
        self.assertIsNone(check.Call.current)

    def test_a_vanishing_file_is_not_yet_rather_than_an_error(self):
        missing = Path("/nonexistent/acwd25/state.tar.age.partial")
        self.assertFalse(check.holds(check.partial_has_bytes(missing)))

    def test_a_call_that_finished_before_it_was_caught_fails_the_case_cleanly(self):
        call = check.Call([sys.executable, "-c", "pass"], budget=60)
        seen = check.terminated_in_progress(call, lambda: False)
        self.assertFalse(seen["caught_in_progress"])
        self.assertEqual(seen["rc"], 0)
        self.assertTrue(seen["group_gone"])

    def test_an_interrupt_of_the_check_ends_the_call_and_propagates(self):
        call = check.Call(SLEEPER, budget=60)

        def started():
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            check.terminated_in_progress(call, started)
        # The call stays owned for the check's handler, which ends it.
        self.assertIs(check.Call.current, call)
        self.assertTrue(check.stop_in_flight())
        self.assertTrue(check.group_gone(call.process.pid))
        self.assertTrue(call.process.stdout.closed and call.process.stderr.closed)
        self.assertIsNone(check.Call.current)

    def test_a_call_past_its_deadline_is_ended_by_result(self):
        call = check.Call(SLEEPER, budget=1)
        answer = check.Call.result(call)
        self.assertIn("group gone: True", answer.stderr)
        self.assertTrue(check.group_gone(call.process.pid))



class AcquisitionTests(unittest.TestCase):
    def test_an_interrupt_between_launch_and_registration_still_leaves_the_call_owned(self):
        # Deterministic: the interrupt is sent inside Popen, once the process
        # exists and before the call is registered.
        import signal
        import subprocess

        real = subprocess.Popen

        def interrupted(*args, **kwargs):
            process = real(*args, **kwargs)
            os.kill(os.getpid(), signal.SIGINT)
            return process

        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        check.subprocess.Popen = interrupted
        try:
            with self.assertRaises(KeyboardInterrupt):
                check.Call(SLEEPER, budget=60)
        finally:
            check.subprocess.Popen = real
            signal.signal(signal.SIGINT, previous)
        owned = check.Call.current
        self.assertIsNotNone(owned)
        self.assertTrue(owned.end())
        owned.release()

    def test_a_call_whose_output_outlives_its_group_returns_within_its_reserve(self):
        # A grandchild in its own session keeps the call's stdout open: ending
        # the group cannot close it, and the collect must not wait for ever.
        import signal
        import tempfile

        marker = Path(tempfile.mkdtemp()) / "grandchild.pid"
        script = ("import subprocess, sys, time\n"
                  "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'],"
                  " start_new_session=True)\n"
                  f"open({str(marker)!r}, 'w').write(str(p.pid))\n"
                  "time.sleep(600)\n")
        call = check.Call([sys.executable, "-c", script], budget=2)
        began = time.monotonic()
        try:
            answer = call.result()
            self.assertLess(time.monotonic() - began, 2 + 45)
            self.assertIn("could not be collected", answer.stderr)
            self.assertFalse(answer.complete)
            self.assertIsNone(check.Call.current)
        finally:
            if marker.exists():
                try:
                    os.kill(int(marker.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


class VerdictTests(unittest.TestCase):
    """The harness's own outcome decides: a call that passed its deadline, or
    whose cleanup is not accounted for, never makes a case pass, whatever
    its exit code."""

    def test_a_child_that_exits_0_on_the_harness_timeout_is_not_complete(self):
        trap = ("import signal, sys, time\n"
                "signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))\n"
                "time.sleep(600)\n")
        answer = check.Call([sys.executable, "-c", trap], budget=1).result()
        self.assertEqual(answer.returncode, 0)
        self.assertFalse(answer.complete)
        self.assertFalse(check.verdict(True, answer))

    def test_a_call_that_finishes_in_time_is_complete(self):
        answer = check.Call([sys.executable, "-c", "pass"], budget=30).result()
        self.assertTrue(answer.complete)
        self.assertTrue(check.verdict(True, answer))
        self.assertFalse(check.verdict(False, answer))

    def test_a_group_whose_absence_cannot_be_observed_is_unknown_and_its_pipes_still_close(self):
        call = check.Call(SLEEPER, budget=60)
        real = check.os.killpg

        def refused(pgid, sent):
            if sent == 0:
                raise PermissionError(1, "Operation not permitted")
            return real(pgid, sent)

        check.os.killpg = refused
        try:
            self.assertIsNone(check.group_gone(call.process.pid))
            self.assertIsNone(call.end())
        finally:
            check.os.killpg = real
            call.release()
        self.assertTrue(call.process.stdout.closed and call.process.stderr.closed)
        self.assertIsNone(check.Call.current)
        call.process.wait(timeout=10)


class OwnershipOnEveryExitTests(unittest.TestCase):
    def test_an_interrupted_wait_keeps_the_call_owned_until_the_handler_ends_it(self):
        # SIGTERM during an ordinary result(): the call stays registered, the
        # handler's end observes the group, and the receipt matches the
        # observation made before any fixture cleanup.
        import signal
        import threading

        previous = signal.signal(signal.SIGTERM, check.terminate)
        call = check.Call(SLEEPER, budget=60)
        threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
        try:
            with self.assertRaises(check.Terminated):
                call.result()
            self.assertIs(check.Call.current, call)
            self.assertFalse(check.group_gone(call.process.pid))
            receipt = check.stop_in_flight()
            observed = check.group_gone(call.process.pid)
        finally:
            signal.signal(signal.SIGTERM, previous)
            if not check.group_gone(call.process.pid):
                os.killpg(call.process.pid, signal.SIGKILL)
        self.assertTrue(observed)
        self.assertEqual(receipt, observed)
        self.assertIsNone(check.Call.current)
        self.assertTrue(call.process.stdout.closed)

    def test_a_leader_that_exits_with_its_group_still_running_is_not_complete(self):
        # The leader exits 0; a descendant in its group, with its output
        # closed, keeps running: no completion, and the group is ended.
        script = ("import subprocess, sys\n"
                  "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],"
                  " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n")
        call = check.Call([sys.executable, "-c", script], budget=60)
        answer = call.result()
        observed = check.group_gone(call.process.pid)
        if not observed:
            os.killpg(call.process.pid, 9)
        self.assertEqual(answer.returncode, 0)
        self.assertFalse(answer.complete)
        self.assertIn("still running", answer.stderr)
        self.assertTrue(observed)


if __name__ == "__main__":
    unittest.main()

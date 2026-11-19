"""agent_state_age_check.py's ownership of its calls (aweb-acwd.25.1): one
deadline from launch, observation included, and every call ended with its
group on every path. Real child processes stand where the CLI stands: what
is tested is the check's ownership, not the CLI.

    python3 -I scripts/e2e/test_agent_state_age_check.py
"""

from __future__ import annotations

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
        self.assertTrue(check.group_gone(call.process.pid))
        self.assertTrue(call.process.stdout.closed and call.process.stderr.closed)
        self.assertIsNone(check.Call.current)

    def test_a_call_past_its_deadline_is_ended_by_result(self):
        call = check.Call(SLEEPER, budget=1)
        answer = check.Call.result(call)
        self.assertIn("group gone: True", answer.stderr)
        self.assertTrue(check.group_gone(call.process.pid))


if __name__ == "__main__":
    unittest.main()

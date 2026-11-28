"""The planted-defect verdict of the TypeScript dist self-test (scripts/lib/named_negative.py)."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

JUDGE = Path(__file__).with_name("lib") / "named_negative.py"
NAME = "Pi closes a stream at its requested deadline and reconnects"
ASSERTION = "S4c: the stream must close at its deadline"
FAILED_TAP = f"""TAP version 13
not ok 1 - {NAME}
  ---
  error: '{ASSERTION}'
  code: 'ERR_ASSERTION'
  ...
1..1
# tests 1
# fail 1
"""


class NamedNegative(unittest.TestCase):
    def judge(self, status, verdict, tap=FAILED_TAP):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "verdict")
            if verdict is not None:
                path.write_text(verdict + "\n")
            result = subprocess.run(
                [
                    sys.executable,
                    str(JUDGE),
                    "--status",
                    str(status),
                    "--verdict",
                    str(path),
                    "--name",
                    NAME,
                    "--assertion",
                    ASSERTION,
                ],
                input=tap,
                capture_output=True,
                text=True,
                timeout=30,
            )
        return result.returncode, result.stdout.strip()

    def test_the_named_assertion_with_a_matching_exit_verdict_is_the_negative(self):
        self.assertEqual(self.judge(1, "exit 1")[0], 0)

    def test_a_missing_verdict_is_inconclusive(self):
        outcome, reason = self.judge(1, None)
        self.assertEqual((outcome, reason), (2, "the runner wrote no verdict"))

    def test_a_contradictory_verdict_is_inconclusive(self):
        for verdict in ("exit 0", "exit 2", "timeout", "interrupted SIGTERM"):
            with self.subTest(verdict=verdict):
                outcome, reason = self.judge(1, verdict)
                self.assertEqual(outcome, 2)
                self.assertIn("contradicts exit status 1", reason)

    def test_a_passing_run_is_refused(self):
        self.assertEqual(
            self.judge(0, "exit 0", "TAP version 13\nok 1 - x\n# tests 1\n")[0], 1
        )

    def test_another_failure_is_inconclusive(self):
        cases = {
            "another test": FAILED_TAP.replace(
                f"not ok 1 - {NAME}", "not ok 1 - other"
            ),
            "not an assertion": FAILED_TAP.replace(
                "ERR_ASSERTION", "ERR_MODULE_NOT_FOUND"
            ),
            "another message": FAILED_TAP.replace(ASSERTION, "S4c: something else"),
            "more tests": FAILED_TAP.replace("# tests 1", "# tests 2"),
        }
        for case, tap in cases.items():
            with self.subTest(case=case):
                self.assertEqual(self.judge(1, "exit 1", tap)[0], 2)


if __name__ == "__main__":
    unittest.main()

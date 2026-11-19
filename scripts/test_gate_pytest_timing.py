"""The candidate image's pytest options retain every case's phase timings."""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CandidatePytestTimingTest(unittest.TestCase):
    def test_isolated_suite_retains_passing_case_rows_in_parent_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "pytest.ini").write_text("[pytest]\n")
            (directory / "test_case.py").write_text(
                "def test_case():\n    assert True\n"
            )
            program = (
                "from pathlib import Path; import sys; "
                + f"sys.path.insert(0, {str(ROOT / 'scripts/test-egress')!r}); "
                + "from docker import run_logged_suite; "
                + "raise SystemExit(run_logged_suite(evidence=Path('.'), "
                + "command=[sys.executable, '-m', 'pytest', '-q', '--durations=0', "
                + "'--durations-min=0', 'test_case.py']))"
            )
            result = subprocess.run(
                [sys.executable, "-c", program],
                cwd=directory,
                env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            log = (directory / "suite.log").read_text()
            self.assertIn(log, result.stdout)
            for phase in ("setup", "call", "teardown"):
                self.assertRegex(
                    result.stdout, rf"\d+\.\d+s {phase}\s+test_case.py::test_case"
                )

    def run_suite(self, source: str) -> subprocess.CompletedProcess[str]:
        # Read the real image setting, then exercise pytest itself without Docker.
        options = []
        for line in (ROOT / "candidate-gate/Dockerfile").read_text().splitlines():
            if line.startswith("ENV PYTEST_ADDOPTS="):
                options.append(shlex.split(line)[1].split("=", 1)[1])
        self.assertLessEqual(len(options), 1, "keep one image timing owner")
        with tempfile.TemporaryDirectory(prefix="gate-pytest-timing-") as temporary:
            directory = Path(temporary)
            (directory / "pytest.ini").write_text("[pytest]\n")
            (directory / "test_cases.py").write_text(source)
            with (directory / "suite.log").open("w+") as log:
                result = subprocess.run(
                    [sys.executable, "-m", "pytest", "-q", "test_cases.py"],
                    cwd=directory,
                    env={
                        **os.environ,
                        "PYTEST_ADDOPTS": options[0] if options else "",
                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                    },
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=30,
                    text=True,
                )
                log.seek(0)
                result.stdout = log.read()
            return result

    def test_fast_passing_cases_keep_setup_call_and_teardown_timings(self):
        result = self.run_suite("def test_pass():\n    assert True\n")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("1 passed", result.stdout)
        for phase in ("setup", "call", "teardown"):
            self.assertRegex(
                result.stdout, rf"\d+\.\d+s {phase}\s+test_cases.py::test_pass"
            )

    def test_failure_keeps_its_exit_status_and_timings(self):
        result = self.run_suite("def test_fail():\n    assert False\n")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("1 failed", result.stdout)
        self.assertRegex(result.stdout, r"\d+\.\d+s call\s+test_cases.py::test_fail")


if __name__ == "__main__":
    unittest.main()

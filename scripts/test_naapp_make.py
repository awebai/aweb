"""Run the real test-naapp recipe against small package fixtures."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("naapp-lib", "naapp/library", "naapp/logs")


class TestNaappMake(unittest.TestCase):
    def run_target(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            bin_dir = fixture / "bin"
            bin_dir.mkdir()
            uv = bin_dir / "uv"
            uv.write_text(
                '#!/bin/sh\n'
                '[ "$1 $2 $3" = "sync --frozen --project" ] || exit 70\n'
                '[ "$4" != "$FAIL_SYNC" ]\n'
            )
            uv.chmod(0o755)
            for package in PACKAGES:
                project = fixture / package
                project.mkdir(parents=True)
                (project / "uv.lock").write_text("fixture lock\n")
                recipe = f'test:\n\t@echo {package} >> "$$TRACE"\n'
                if package == PACKAGES[0]:
                    if failure == "test":
                        recipe += "\t@exit 27\n"
                    if failure == "lock":
                        recipe += "\t@echo changed >> uv.lock\n"
                (project / "Makefile").write_text(recipe)

            subprocess.run(["git", "init", "-q"], cwd=fixture, check=True)
            subprocess.run(["git", "add", "--", *(f"{p}/uv.lock" for p in PACKAGES)], cwd=fixture, check=True)
            trace = fixture / "test-trace"
            result = subprocess.run(
                ["make", "-f", str(ROOT / "Makefile"), "test-naapp",
                 f"NAAPP_PACKAGES={' '.join(PACKAGES)}", "TEST_EGRESS_RUNNER="],
                cwd=fixture, capture_output=True, text=True, timeout=30,
                env=dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                         TRACE=str(trace), FAIL_SYNC=PACKAGES[0] if failure == "sync" else ""),
            )
            tested = trace.read_text().splitlines() if trace.exists() else []
            return result, tested

    def test_all_packages_run_and_success_is_reported(self):
        result, tested = self.run_target(None)
        self.assertEqual(tested, list(PACKAGES), result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_package_failures_keep_later_packages_running(self):
        for failure in ("test", "lock", "sync"):
            with self.subTest(failure=failure):
                result, tested = self.run_target(failure)
                expected = PACKAGES[1:] if failure == "sync" else PACKAGES
                self.assertEqual(tested, list(expected), result.stdout + result.stderr)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

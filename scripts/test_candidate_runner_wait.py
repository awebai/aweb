"""Exercise the actual runner pipeline's status and signal boundary with processes."""

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RunnerWaitTests(unittest.TestCase):
    def pipeline_tail(self):
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        start = source.index('  2>&1 | tee "$LOG_DIR/gate.log"')
        end = source.index("\nset -e", start)
        return source[start:end]

    def test_term_enters_cleanup_while_runner_is_active(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = (
                """set -uo pipefail
LOG_DIR="$1"
trap 'printf "cleanup\\n" > "$LOG_DIR/cleanup"; exit 143' TERM
runner() { printf 'running\\n'; read -r ignored < "$LOG_DIR/finish"; }
mkfifo "$LOG_DIR/finish"
runner \\
"""
                + self.pipeline_tail()
                + '\nexit "$status"\n'
            )
            process = subprocess.Popen(
                ["bash", "-c", script, "runner-wait", str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                self.assertEqual(process.stdout.readline(), "running\n")
                process.send_signal(signal.SIGTERM)
                # Wait only for the wrapper: a stand-in runner remains blocked,
                # whereas production cleanup removes its owned Docker container.
                self.assertEqual(process.wait(timeout=2), 143)
                self.assertEqual((root / "cleanup").read_text(), "cleanup\n")
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    # The test's private process group already exited.
                    self.assertIsNotNone(process.poll())
                process.communicate(timeout=5)

    def test_successful_tee_preserves_runner_failure_and_success(self):
        for status in (0, 37):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as root:
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'set -uo pipefail\nLOG_DIR="$1"\n'
                        + f"(exit {status}) \\\n"
                        + self.pipeline_tail()
                        + '\nexit "$status"\n',
                        "runner-wait",
                        root,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, status, result.stderr)


if __name__ == "__main__":
    unittest.main()

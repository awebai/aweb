"""Run the worker and EXIT cleanup together without starting the topology."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FederationFailureCleanupTests(unittest.TestCase):
    def run_worker(self, action: str) -> subprocess.CompletedProcess[str]:
        source = (ROOT / "scripts/e2e-federation-authority.sh").read_text()
        cleanup = source[
            source.index("cleanup() {") : source.index("\ntrap cleanup EXIT")
        ]
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir()
            env = dict(os.environ)
            env.pop("AWEB_DATABASE_URL", None)
            env.update(
                RUNTIME=str(runtime),
                COMPOSE_FILE=str(runtime / "docker-compose.yml"),
                AWEB_FED_AUTH_KEEP="0",
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    "set -euo pipefail\n"
                    + cleanup
                    + '\ntrap cleanup EXIT\n"$@" > "$RUNTIME/worker.json"\n',
                    "cleanup-control",
                    sys.executable,
                    str(ROOT / "scripts/federation-authority-worker.py"),
                    action,
                ],
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertFalse(runtime.exists(), result.stderr)
            return result

    def test_worker_exception_survives_runtime_removal(self):
        # Missing configuration raises in the actual worker before any DB access.
        result = self.run_worker("resolve")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('"type":"KeyError"', result.stderr)
        self.assertIn('"detail":"\'AWEB_DATABASE_URL\'"', result.stderr)
        self.assertEqual(result.stdout, "")

    def test_success_keeps_redirected_output_quiet(self):
        result = self.run_worker("identity")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_failure_without_json_keeps_original_status(self):
        result = self.run_worker("unsupported")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("invalid choice", result.stderr)


if __name__ == "__main__":
    unittest.main()

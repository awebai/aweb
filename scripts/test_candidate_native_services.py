"""Native service controls are enabled in both real runner launch vectors."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeServiceEnvironmentTests(unittest.TestCase):
    def test_candidate_runner_enables_native_services(self):
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        start = source.index("docker run --rm --init \\\n")
        end = source.index('  2>&1 | tee "$LOG_DIR/gate.log"', start)
        command = source[start:end].rstrip().removesuffix("\\")
        # Execute the production shell expansion; the external Docker boundary
        # only records argv. This does not qualify Docker or any service test.
        result = subprocess.run(
            ["bash", "-c", "docker() { printf '%s\\0' \"$@\"; }\n" + command],
            env={**os.environ, "AWEB_TEST_SERVICES": "0"},
            capture_output=True,
            check=True,
            timeout=10,
        )
        args = result.stdout.decode().split("\0")
        values = [args[index + 1] for index, arg in enumerate(args[:-1]) if arg == "-e"]
        self.assertEqual(
            [value for value in values if value.startswith("AWEB_TEST_SERVICES=")],
            ["AWEB_TEST_SERVICES=1"],
        )

    def test_isolated_unit_runner_enables_native_services(self):
        spec = importlib.util.spec_from_file_location(
            "native_service_runner", ROOT / "scripts/test-egress/docker.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        args = module.runner_args(
            "owned-network", "172.20.0.2", "owned-image", evidence=Path("/owned/unit")
        )
        values = [args[index + 1] for index, arg in enumerate(args[:-1]) if arg == "-e"]
        self.assertEqual(
            [value for value in values if value.startswith("AWEB_TEST_SERVICES=")],
            ["AWEB_TEST_SERVICES=1"],
        )
        self.assertIn("/owned/unit:/evidence", args)
        self.assertIn("AWEB_UNIT_EVIDENCE_DIR=/evidence", values)

    def test_isolated_dispatch_calls_both_package_owners_and_stops_on_service_failure(
        self,
    ):
        # Records only the make boundary; service correctness needs the native suite.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = root / "make"
            recorder.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$1" >> "$CALLS"\n[ "$1" != "$FAIL_TARGET" ] || exit 23\n'
            )
            recorder.chmod(0o755)
            calls = root / "calls"
            for failed in ("", "test-approval-service"):
                with self.subTest(failed=failed):
                    calls.write_text("")
                    result = subprocess.run(
                        [
                            "bash",
                            str(ROOT / "scripts/candidate-suite.sh"),
                            "--isolated-suites",
                        ],
                        env={
                            **os.environ,
                            "PATH": str(root) + os.pathsep + os.environ["PATH"],
                            "CALLS": str(calls),
                            "FAIL_TARGET": failed,
                        },
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    targets = calls.read_text().splitlines()
                    self.assertEqual(targets.count("test-key-holder"), 1)
                    self.assertEqual(targets.count("test-approval-service"), 1)
                    self.assertEqual(
                        result.returncode, 23 if failed else 0, result.stderr
                    )
                    if failed:
                        self.assertEqual(targets[-1], "test-approval-service")
                        self.assertNotIn("test-cli", targets)


if __name__ == "__main__":
    unittest.main()

"""Check the import context used by real command-test fixtures."""

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIRECTORY = ROOT / "scripts" / "test-egress"


class FixtureImportTests(unittest.TestCase):
    def test_fixture_directory_resolves_dnspython(self):
        result = subprocess.run(
            [
                "uv",
                "run",
                "--offline",
                "--frozen",
                "--project",
                str(ROOT / "server"),
                "python",
                "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "import dns.asyncresolver; print(dns.asyncresolver.__file__)",
                str(FIXTURE_DIRECTORY),
            ],
            cwd=FIXTURE_DIRECTORY,
            text=True,
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            result.stdout.strip().endswith("dns/asyncresolver.py"), result.stdout
        )


if __name__ == "__main__":
    unittest.main()

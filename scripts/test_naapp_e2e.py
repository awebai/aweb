#!/usr/bin/env python3
"""Exercise the real make dispatch and environment contract with small e2e packages."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NaappE2ETest(unittest.TestCase):
    def test_each_package_receives_its_own_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            packages = [Path(temporary) / name for name in ("first", "second")]
            for package in packages:
                package.mkdir()
                (package / "Makefile").write_text(
                    'e2e:\n\t@printf "%s\\n" "NAAPP_E2E_PROJECT=$$NAAPP_E2E_PROJECT" '
                    '"NAAPP_E2E_HOST=$$NAAPP_E2E_HOST" '
                    '"NAAPP_E2E_AWID_PORT=$$NAAPP_E2E_AWID_PORT" '
                    '"NAAPP_E2E_POSTGRES_PORT=$$NAAPP_E2E_POSTGRES_PORT" > allocation.txt\n',
                    encoding="utf-8",
                )
            env = {k: v for k, v in os.environ.items() if not k.startswith("NAAPP_E2E_")}
            env["AWEB_DOCKER_PUBLISHED_HOST"] = "aweb-docker.test"
            env["NAAPP_E2E_ALLOCATIONS"] = "\n".join(
                f"{package} run-{index} {41000 + index * 2} {41001 + index * 2}"
                for index, package in enumerate(packages)
            )
            result = subprocess.run(
                ["make", "e2e-naapp", f"NAAPP_E2E_PACKAGES={' '.join(map(str, packages))}"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for index, package in enumerate(packages):
                allocation = dict(
                    line.split("=", 1)
                    for line in (package / "allocation.txt").read_text().splitlines()
                )
                self.assertEqual(allocation["NAAPP_E2E_PROJECT"], f"run-{index}")
                self.assertEqual(allocation["NAAPP_E2E_HOST"], "aweb-docker.test")
                self.assertEqual(allocation["NAAPP_E2E_AWID_PORT"], str(41000 + index * 2))
                self.assertEqual(allocation["NAAPP_E2E_POSTGRES_PORT"], str(41001 + index * 2))

    def test_missing_allocation_fails_before_starting_a_package(self):
        result = subprocess.run(
            ["make", "e2e-naapp", "NAAPP_E2E_PACKAGES=missing-package"], cwd=ROOT,
            env={**os.environ, "NAAPP_E2E_ALLOCATIONS": "another-package run 41001 41002"},
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing allocation", result.stdout + result.stderr)

    def test_a_failed_package_fails_the_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            (package / "Makefile").write_text('e2e:\n\t@exit 7\n', encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("NAAPP_E2E_")}
            result = subprocess.run(
                ["make", "e2e-naapp", f"NAAPP_E2E_PACKAGES={package}"], cwd=ROOT,
                env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Error 7", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

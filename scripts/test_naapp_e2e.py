#!/usr/bin/env python3
"""Exercise the real make dispatch and environment contract with small e2e packages."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

# The real docker, recorded: each call with the registry origins compose would
# interpolate, then its arguments, as one JSON line.
DOCKER_STUB = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["CALLS"], "a") as calls:
    calls.write(json.dumps([os.environ.get("AWID_PUBLIC_ORIGINS", ""), sys.argv[1:]]) + "\n")
if "config" in sys.argv:
    print(json.dumps({"name": "proof", "services": {"awid": {"image": "awid"}}, "networks": {"default": {}}}))
"""


class NaappE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The real e2e preflight requires this checkout's aw. Prepare the
        # same binary for direct discovery and the named make target.
        subprocess.run(["go", "build", "-o", "aw", "./cmd/aw"],
                       cwd=ROOT / "cli/go", check=True)

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

    def run_package(self, **extra):
        with tempfile.TemporaryDirectory() as temporary:
            stub = Path(temporary) / "docker"
            stub.write_text(DOCKER_STUB, encoding="utf-8")
            stub.chmod(0o755)
            # In the gate pytest runs directly; elsewhere, in the stubbed container.
            uv = Path(temporary) / "uv"
            uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            uv.chmod(0o755)
            calls = Path(temporary) / "calls"
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("NAAPP_E2E_", "CANDIDATE_", "AWID_"))}
            env.update(PATH=f"{temporary}:{env['PATH']}", CALLS=str(calls),
                       NAAPP_E2E_PROJECT="proof", **extra)
            result = subprocess.run(
                ["bash", "scripts/e2e/naapp-e2e.sh", "naapp/library", "LIBRARY_E2E"],
                cwd=ROOT, env=env, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return [json.loads(line) for line in calls.read_text().splitlines()]

    def test_awid_accepts_the_name_the_tests_call_it_by(self):
        name = subprocess.run(
            ["python3", "scripts/candidate-network.py", "hostname", "proof", "awid"],
            cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout.strip()
        for place, extra in (("gate", {"CANDIDATE_RUNNER_NAME": "runner"}), ("elsewhere", {})):
            with self.subTest(place=place):
                ups = [origins for origins, args in self.run_package(**extra) if "up" in args]
                self.assertEqual(len(ups), 1)
                self.assertIn(f"http://{name}:8010", ups[0].split(","))

    def test_outside_the_gate_the_package_and_the_server_have_separate_environments(self):
        runs = [args for _, args in self.run_package() if args[0] == "run"]
        self.assertEqual(len(runs), 1)
        mounted = [value for flag, value in zip(runs[0], runs[0][1:]) if flag == "-v"]
        self.assertIn("/src/naapp/library/.venv", mounted)
        self.assertIn("/src/server/.venv", mounted)
        self.assertFalse([arg for arg in runs[0] if arg.startswith("UV_PROJECT_ENVIRONMENT=")])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Shell-boundary tests for the parameterized real-stack CLI journey."""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def executable(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def source_command(script: Path, body: str) -> list[str]:
    return ["bash", "-c", f"source {shlex.quote(str(script))}; {body}"]


class CliE2EScriptTests(unittest.TestCase):
    def test_skew_wrapper_has_no_varied_side_source_fallback(self):
        wrapper = ROOT / "scripts/e2e/run_cli_server_skew_cell.sh"
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            aw = executable(tmp / "aw", "#!/bin/sh\nexit 0\n")
            wheel = tmp / "aweb-1.26.35-py3-none-any.whl"
            wheel.write_bytes(b"wheel")
            base = os.environ.copy()
            base["AW_SKEW_DIRECTION"] = "a-to-b"
            cases = (
                ({"AWEB_E2E_SERVER_WHEEL": str(wheel)}, "AW_BIN must name the exact resolved aw binary"),
                ({"AW_BIN": str(aw)}, "AWEB_E2E_SERVER_WHEEL must name the exact resolved server wheel"),
            )
            for supplied, expected in cases:
                with self.subTest(expected=expected):
                    env = base.copy()
                    env.pop("AW_BIN", None)
                    env.pop("AWEB_E2E_SERVER_WHEEL", None)
                    env.update(supplied)
                    result = subprocess.run(
                        ["bash", str(wrapper)], cwd=ROOT, env=env,
                        text=True, capture_output=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)

    def test_prebuilt_binary_skips_build_and_selector_is_literal(self):
        script = ROOT / "cli/scripts/e2e.sh"
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            aw = executable(tmp / "aw", "#!/bin/sh\nexit 0\n")
            executable(bin_dir / "make", "#!/bin/sh\nexit 91\n")
            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}:{env['PATH']}",
                "AW_BIN": str(aw),
                "AW_E2E_TEST_RUN": "^TestOne$",
                # These old test seams must not redirect a release journey.
                "CLI_E2E_STACK_SCRIPT": str(tmp / "fake-stack"),
            })
            result = subprocess.run(
                source_command(
                    script,
                    "select_aw_binary >/dev/null; configure_go_args; "
                    "printf '%s\\n' \"$AW_BIN\" \"$STACK\" \"${GO_ARGS[@]}\"",
                ),
                cwd=ROOT, env=env, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0], str(aw.resolve()))
            self.assertEqual(lines[1], str(ROOT / "scripts/e2e-library-stack.sh"))
            self.assertEqual(lines[-2:], ["-run", "^TestOne$"])

    def test_wheel_cell_prepares_fixed_journey_around_exact_wheel(self):
        wrapper = ROOT / "scripts/e2e/run_cli_server_skew_cell.sh"
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wheel = tmp / "aweb-1.26.35-py3-none-any.whl"
            wheel.write_bytes(b"exact-wheel")
            aw = executable(tmp / "aw", "#!/bin/sh\nexit 0\n")
            env = os.environ.copy()
            env.update({
                "AW_BIN": str(aw),
                "AWEB_E2E_SERVER_WHEEL": str(wheel),
                "AW_SKEW_DIRECTION": "a-to-b",
                "CLI_SERVER_SKEW_E2E_SCRIPT": str(tmp / "fake-e2e"),
            })
            result = subprocess.run(
                source_command(
                    wrapper,
                    "validate_inputs; prepare_context; "
                    "printf '%s\\n' \"$context\" \"$E2E_SCRIPT\" "
                    "\"$AW_E2E_TEST_RUN\" \"$LIBRARY_E2E_AWEB_PUBLIC_ORIGIN\" "
                    "\"$LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL\"",
                ),
                cwd=ROOT, env=env, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            lines = result.stdout.splitlines()
            context = Path(lines[0])
            try:
                self.assertEqual(lines[1], str(ROOT / "cli/scripts/e2e.sh"))
                self.assertEqual(
                    lines[2],
                    "^TestRealStackWorkspacePresenceAndLocksUseDistinctIdentifiers$",
                )
                self.assertRegex(lines[3], r"^http://127\.0\.0\.1:[0-9]+$")
                self.assertRegex(lines[4], r"^http://127\.0\.0\.1:[0-9]+$")
                self.assertIn(
                    "AWEB_E2E_SERVER_WHEEL_CONTEXT",
                    (context / "compose.yml").read_text(),
                )
                self.assertTrue((context / "Dockerfile").is_file())
                copied = next(context.glob("*.whl"))
                self.assertEqual(
                    hashlib.sha256(copied.read_bytes()).hexdigest(),
                    hashlib.sha256(b"exact-wheel").hexdigest(),
                )
            finally:
                shutil.rmtree(context, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Shell-boundary tests for the parameterized real-stack CLI journey."""

from __future__ import annotations

import json
import os
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

    def test_prebuilt_binary_skips_build_and_test_selector_reaches_go(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            log = tmp / "log"
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            aw = executable(tmp / "aw", "#!/bin/sh\nexit 0\n")
            stack = executable(
                tmp / "stack",
                "#!/bin/sh\nprintf 'stack:%s AW_BIN=%s\\n' \"$1\" \"$AW_BIN\" >> \"$TEST_LOG\"\n",
            )
            executable(
                bin_dir / "make",
                "#!/bin/sh\nprintf 'unexpected make:%s\\n' \"$*\" >> \"$TEST_LOG\"\nexit 91\n",
            )
            executable(
                bin_dir / "go",
                "#!/bin/sh\nprintf 'go:%s AW_BIN=%s DIRECTION=%s\\n' \"$*\" \"$AW_BIN\" \"$AW_SKEW_DIRECTION\" >> \"$TEST_LOG\"\n",
            )
            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}:{env['PATH']}",
                "TEST_LOG": str(log),
                "AW_BIN": str(aw),
                "CLI_E2E_STACK_SCRIPT": str(stack),
                "AW_E2E_TEST_RUN": "^TestOne$",
                "AW_SKEW_DIRECTION": "b-to-a",
            })
            result = subprocess.run(
                ["bash", str(ROOT / "cli/scripts/e2e.sh")],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            lines = log.read_text().splitlines()
            self.assertFalse(any("unexpected make" in line for line in lines), lines)
            resolved_aw = aw.resolve()
            self.assertIn(f"stack:up AW_BIN={resolved_aw}", lines)
            self.assertIn(f"stack:seed AW_BIN={resolved_aw}", lines)
            go = next(line for line in lines if line.startswith("go:"))
            self.assertIn("-run ^TestOne$", go)
            self.assertIn("DIRECTION=b-to-a", go)
            self.assertIn("stack:down", "\n".join(lines))

    def test_wheel_cell_wrapper_builds_overlay_around_exact_wheel(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wheel = tmp / "aweb-1.26.35-py3-none-any.whl"
            wheel.write_bytes(b"exact-wheel")
            aw = executable(tmp / "aw", "#!/bin/sh\nexit 0\n")
            observed = tmp / "observed.json"
            fake_e2e = executable(
                tmp / "fake-e2e",
                """#!/usr/bin/env python3
import hashlib, json, os
from pathlib import Path
overlay = Path(os.environ['LIBRARY_E2E_COMPOSE_OVERLAY'])
context = Path(os.environ['AWEB_E2E_SERVER_WHEEL_CONTEXT'])
Path(os.environ['OBSERVED']).write_text(json.dumps({
  'direction': os.environ['AW_SKEW_DIRECTION'],
  'aw_bin': os.environ['AW_BIN'],
  'selector': os.environ['AW_E2E_TEST_RUN'],
  'aweb_public_origin': os.environ['LIBRARY_E2E_AWEB_PUBLIC_ORIGIN'],
  'awid_public_origin': os.environ['LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL'],
  'overlay': overlay.read_text(),
  'wheel_sha256': hashlib.sha256(next(context.glob('*.whl')).read_bytes()).hexdigest(),
  'dockerfile_exists': (context / 'Dockerfile').is_file(),
}))
""",
            )
            env = os.environ.copy()
            env.update({
                "AW_BIN": str(aw),
                "AWEB_E2E_SERVER_WHEEL": str(wheel),
                "AW_SKEW_DIRECTION": "a-to-b",
                "CLI_SERVER_SKEW_E2E_SCRIPT": str(fake_e2e),
                "OBSERVED": str(observed),
            })
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/e2e/run_cli_server_skew_cell.sh")],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            data = json.loads(observed.read_text())
            self.assertEqual(data["direction"], "a-to-b")
            self.assertEqual(data["aw_bin"], str(aw))
            self.assertEqual(
                data["selector"],
                "^TestRealStackWorkspacePresenceAndLocksUseDistinctIdentifiers$",
            )
            self.assertIn("AWEB_E2E_SERVER_WHEEL_CONTEXT", data["overlay"])
            self.assertRegex(data["aweb_public_origin"], r"^http://127\.0\.0\.1:[0-9]+$")
            self.assertRegex(data["awid_public_origin"], r"^http://127\.0\.0\.1:[0-9]+$")
            self.assertTrue(data["dockerfile_exists"])
            import hashlib
            self.assertEqual(data["wheel_sha256"], hashlib.sha256(b"exact-wheel").hexdigest())


if __name__ == "__main__":
    unittest.main()

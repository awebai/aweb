#!/usr/bin/env python3
"""Shell-boundary tests for the parameterized real-stack CLI journey."""

from __future__ import annotations

import hashlib
import json
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

    def test_green_journey_propagates_stack_teardown_failure(self):
        script = ROOT / "cli/scripts/e2e.sh"
        with tempfile.TemporaryDirectory() as raw:
            fake_stack = executable(
                Path(raw) / "stack", "#!/bin/sh\n[ \"$1\" = down ] && exit 23\nexit 0\n"
            )
            result = subprocess.run(
                [
                    "bash", "-c",
                    f"source {shlex.quote(str(script))}; "
                    f"STACK={shlex.quote(str(fake_stack))}; unset KEEP_UP; true; teardown",
                ],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 23, result.stdout + result.stderr)

    def test_stack_down_refuses_exact_project_residue(self):
        stack = ROOT / "scripts/e2e-library-stack.sh"
        with tempfile.TemporaryDirectory() as raw:
            bin_dir = Path(raw) / "bin"
            bin_dir.mkdir()
            executable(
                bin_dir / "docker",
                """#!/bin/sh
case " $* " in
  *" compose "*" down "*) exit 0 ;;
  *" ps -aq --filter label=com.docker.compose.project="*) echo residue-container ;;
  *" network ls -q --filter label=com.docker.compose.project="*) exit 0 ;;
  *" volume ls -q --filter label=com.docker.compose.project="*) exit 0 ;;
  *) echo "unexpected docker call: $*" >&2; exit 90 ;;
esac
""",
            )
            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}:{env['PATH']}",
                "LIBRARY_E2E_PROJECT": "exact-test-project",
            })
            result = subprocess.run(
                ["bash", str(stack), "down"], cwd=ROOT, env=env,
                text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exact-test-project left container/network/volume residue", result.stderr)

    def test_skew_context_cleanup_failure_is_not_green(self):
        wrapper = ROOT / "scripts/e2e/run_cli_server_skew_cell.sh"
        with tempfile.TemporaryDirectory() as raw:
            context = Path(raw) / "context"
            context.mkdir()
            result = subprocess.run(
                [
                    "bash", "-c",
                    f"source {shlex.quote(str(wrapper))}; "
                    f"context={shlex.quote(str(context))}; "
                    "rm() { return 19; }; cleanup_context 0",
                ],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("temporary context remains after cleanup", result.stderr)

    def test_stack_server_proof_binds_runtime_version_wheel_and_container(self):
        stack = ROOT / "scripts/e2e-library-stack.sh"
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            proof = tmp / "proof.json"
            docker = executable(
                bin_dir / "docker",
                """#!/bin/sh
case " $* " in
  *" ps -q aweb "*) printf '%064d\\n' 0 | tr '0' 'a' ;;
  *" inspect --format "*) printf 'sha256:%064d\\n' 0 | tr '0' 'b' ;;
  *"installed_distributions_sha256"*)
    if [ "$FAKE_SERVER_VERSION" != "$AWEB_SKEW_EXPECTED_SERVER_VERSION" ]; then
      echo "runtime server mismatch: $FAKE_SERVER_VERSION" >&2
      exit 2
    fi
    printf '%s\\n' "$FAKE_RUNTIME_JSON"
    ;;
  *) echo "unexpected docker call: $*" >&2; exit 90 ;;
esac
""",
            )
            del docker
            wheel_sha = hashlib.sha256(b"wheel").hexdigest()
            inventory = {"aweb": "1.26.35", "mcp": "1.26.0"}
            inventory_sha = hashlib.sha256(json.dumps(
                inventory, sort_keys=True, separators=(",", ":")
            ).encode()).hexdigest()
            cell_sha = "d" * 64
            project = f"aweb-skew-{cell_sha[:20]}-{'e' * 16}"
            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}:{env['PATH']}",
                "AWEB_SKEW_RUNTIME_PROOF_PATH": str(proof),
                "AWEB_SKEW_EXPECTED_SERVER_VERSION": "1.26.35",
                "AWEB_SKEW_EXPECTED_SERVER_WHEEL_SHA256": wheel_sha,
                "AWEB_SKEW_EXPECTED_MCP_VERSION": "1.26.0",
                "AW_SKEW_CELL_IDENTITY_SHA256": cell_sha,
                "LIBRARY_E2E_PROJECT": project,
                "FAKE_SERVER_VERSION": "1.26.35",
                "FAKE_RUNTIME_JSON": json.dumps({
                    "installed_distributions": inventory,
                    "installed_distributions_sha256": inventory_sha,
                    "mcp_version": "1.26.0",
                    "server_version": "1.26.35",
                    "wheel_sha256": wheel_sha,
                }, sort_keys=True, separators=(",", ":")),
            })
            result = subprocess.run(
                ["bash", str(stack), "server-proof"], cwd=ROOT, env=env,
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(proof.read_text()), {
                "cell_identity_sha256": cell_sha,
                "container_id": "a" * 64,
                "image_id": "sha256:" + "b" * 64,
                "installed_distributions": inventory,
                "installed_distributions_sha256": inventory_sha,
                "mcp_version": "1.26.0",
                "project": project,
                "server_version": "1.26.35",
                "wheel_sha256": wheel_sha,
            })

            proof.unlink()
            env["FAKE_SERVER_VERSION"] = "1.26.31"
            result = subprocess.run(
                ["bash", str(stack), "server-proof"], cwd=ROOT, env=env,
                text=True, capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("runtime server mismatch: 1.26.31", result.stderr)
            self.assertFalse(proof.exists())

    def test_wheel_cell_prepares_fixed_journey_around_exact_wheel(self):
        wrapper = ROOT / "scripts/e2e/run_cli_server_skew_cell.sh"
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            wheel = tmp / "aweb-1.26.35-py3-none-any.whl"
            wheel.write_bytes(b"exact-wheel")
            aw = executable(tmp / "aw", "#!/bin/sh\nexit 0\n")
            env = os.environ.copy()
            identity = json.dumps(
                {"direction": "a-to-b", "journey": "make cli-e2e"},
                sort_keys=True, separators=(",", ":"),
            )
            identity_sha = hashlib.sha256(identity.encode()).hexdigest()
            env.update({
                "AW_BIN": str(aw),
                "AWEB_E2E_SERVER_WHEEL": str(wheel),
                "AW_SKEW_DIRECTION": "a-to-b",
                "AW_SKEW_CELL_IDENTITY_JSON": identity,
                "AW_SKEW_CELL_IDENTITY_SHA256": identity_sha,
                "AWEB_SKEW_RUNTIME_PROOF_PATH": str(tmp / "proof.json"),
                "AWEB_SKEW_EXPECTED_SERVER_VERSION": "1.26.35",
                "AWEB_SKEW_EXPECTED_SERVER_WHEEL_SHA256": hashlib.sha256(b"exact-wheel").hexdigest(),
                "AWEB_SKEW_EXPECTED_MCP_VERSION": "1.26.0",
                "KEEP_UP": "1",
                "LIBRARY_E2E_PROJECT": "ambient-wrong-project",
                "LIBRARY_E2E_AWEB_PORT": "1",
                "LIBRARY_E2E_AWEB_PUBLIC_ORIGIN": "https://wrong.example",
                "LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN": "https://wrong-library.example",
                "CLI_SERVER_SKEW_E2E_SCRIPT": str(tmp / "fake-e2e"),
            })
            result = subprocess.run(
                source_command(
                    wrapper,
                    "validate_inputs; prepare_context; "
                    "printf '%s\\n' \"$context\" \"$E2E_SCRIPT\" "
                    "\"$AW_E2E_TEST_RUN\" \"$LIBRARY_E2E_AWEB_PUBLIC_ORIGIN\" "
                    "\"$LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL\" "
                    "\"$LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN\" "
                    "\"$LIBRARY_E2E_PROJECT\" \"${KEEP_UP-unset}\"",
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
                self.assertRegex(lines[5], r"^http://127\.0\.0\.1:[0-9]+$")
                self.assertRegex(
                    lines[6],
                    rf"^aweb-skew-{identity_sha[:20]}-[0-9a-f]{{16}}$",
                )
                self.assertEqual(lines[7], "unset")
                compose = (context / "compose.yml").read_text()
                self.assertIn("AWEB_E2E_SERVER_WHEEL_CONTEXT", compose)
                self.assertIn(
                    "MCP_VERSION: ${AWEB_SKEW_EXPECTED_MCP_VERSION:?}", compose
                )
                dockerfile = (context / "Dockerfile").read_text()
                self.assertIn('"mcp==$MCP_VERSION"', dockerfile)
                copied = next(context.glob("*.whl"))
                self.assertEqual(
                    hashlib.sha256(copied.read_bytes()).hexdigest(),
                    hashlib.sha256(b"exact-wheel").hexdigest(),
                )
            finally:
                shutil.rmtree(context, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

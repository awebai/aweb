"""A green direct channel lane cannot hide a missing or failed OATS wake seam."""

from pathlib import Path
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "e2e"))
from user_paths_kernel_result import add_kernel_wake_result  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class ReleasedKernelBootstrapTest(unittest.TestCase):
    def test_passive_kernel_preflight_and_command_diagnostics(self):
        result = subprocess.run(
            [
                "node",
                "--test",
                str(ROOT / "scripts/e2e/user_paths_kernel_setup.test.mjs"),
            ],
            capture_output=True,
            text=True,
            # Includes real tmux start/stop/retire, not just launch planning.
            timeout=60,
        )
        # A failure names the failing Node test and its error.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_no_launch_spawn_uses_private_deployment_without_git_identity(self):
        staged = Path("/opt/user-paths/released-oats")
        package = staged if staged.is_dir() else ROOT / "candidate-gate/released-oats"
        kernel = package / "node_modules/@awebai/oats/bin/oats.mjs"
        self.assertTrue(
            kernel.is_file(), "Run make prepare-released-kernel-test first."
        )
        node = shutil.which("node")
        self.assertIsNotNone(node)
        with tempfile.TemporaryDirectory(
            prefix="released-kernel-bootstrap-"
        ) as temporary:
            root = Path(temporary).resolve()
            self.assertFalse((root / "deploy/agents").exists())
            helper = (ROOT / "scripts/e2e/user_paths_kernel_setup.mjs").as_uri()
            subprocess.run(
                [
                    node,
                    "--input-type=module",
                    "-e",
                    f"import {{prepareKernelProbeDirectories}} from {json.dumps(helper)};"
                    "prepareKernelProbeDirectories({root:process.argv[1]});",
                    str(root),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            home, deployment, source = (
                root / name for name in ("home", "deploy", "source")
            )
            (root / "bin/node").symlink_to(node)
            env = {
                "HOME": str(home),
                "PATH": str(root / "bin") + os.pathsep + "/usr/bin:/bin",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "user.useConfigOnly",
                "GIT_CONFIG_VALUE_0": "true",
                "OATS_REMOTE_CACHE": str(root / "cache"),
            }
            self.assertIsNone(shutil.which("claude", path=env["PATH"]))
            # The real kernel's deployment discovery must not find a parent checkout.
            parent_repo = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=deployment,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(parent_repo.returncode, 0)
            for field in ("user.name", "user.email"):
                result = subprocess.run(
                    ["git", "config", "--get", field],
                    cwd=deployment,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
            ref = source.as_uri()
            (source / "oats-workspace.yaml").write_text(
                f"schemaVersion: 2\nname: wake-probe\nmembers: [{ref}]\nlocalTeams: true\n"
            )
            (source / "oats-membership.yaml").write_text(
                f"schemaVersion: 2\nworkspace: {ref}\n"
            )
            soul = source / "souls/probe"
            soul.mkdir(parents=True)
            (soul / "soul.yaml").write_text(
                "schemaVersion: 2\nname: probe\ndescription: passive bootstrap control\n"
                "work: directory\nlaunch: { harness: claude }\n"
            )
            (soul / "AGENTS.md").write_text("Disposable kernel bootstrap control.\n")
            for args in (
                ["init", "-q"],
                ["add", "."],
                ["commit", "-qm", "wake-probe workspace"],
            ):
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(source),
                        "-c",
                        "user.name=Wake probe",
                        "-c",
                        "user.email=probe@example.invalid",
                        *args,
                    ],
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            (deployment / "oats-local.yaml").write_text(
                f"schemaVersion: 2\nworkspace: {ref}\n"
            )
            # This exercises deployment bootstrap, with no provider or service stand-in.
            command = [
                node,
                str(kernel),
                "spawn",
                "probe",
                "--name",
                "r20-wake-probe",
                "--backend",
                "tmux",
                "--no-launch",
                "--json",
            ]
            result = subprocess.run(
                command,
                cwd=deployment,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["error"]["code"], "E_HARNESS_UNAVAILABLE"
            )
            self.assertFalse(
                (deployment / "agents/probe/instances/r20-wake-probe").exists()
            )
            # A no-launch spawn still validates its future executable. Select a
            # real installed program explicitly, as the passive wake probe does.
            (deployment / "oats-local.yaml").write_text(
                f"schemaVersion: 2\nworkspace: {ref}\n"
                "launch-configs:\n  passive:\n    harness: claude\n"
                f"    executable: {json.dumps(str(Path(node).resolve()))}\n"
                "souls:\n  launch:\n    '*': passive\n"
            )
            result = subprocess.run(
                command,
                cwd=deployment,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            spawned = json.loads(result.stdout)
            self.assertTrue(spawned["ok"])
            self.assertFalse(spawned["result"]["launched"])
            self.assertEqual(
                Path(spawned["result"]["home"]),
                deployment / "agents/probe/instances/r20-wake-probe",
            )
            self.assertEqual(
                stat.S_IMODE((deployment / "agents").stat().st_mode), 0o700
            )

    def test_kernel_command_diagnostics_keep_codes_without_private_output(self):
        helper = (ROOT / "scripts/e2e/user_paths_kernel_setup.mjs").as_uri()
        result = subprocess.run(
            [
                "node",
                "--input-type=module",
                "-e",
                f"import {{kernelCommandErrorCode}} from {json.dumps(helper)};"
                "let input='';for await(const part of process.stdin)input+=part;"
                "console.log(JSON.stringify(JSON.parse(input).map(kernelCommandErrorCode)));",
            ],
            input=json.dumps(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "E_NO_DEPLOYMENT",
                                "message": "private result",
                            }
                        }
                    ),
                    json.dumps({"error": {"code": "private result"}}),
                    "unstructured private result",
                    "null",
                    "[]",
                ]
            ),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        self.assertEqual(
            json.loads(result.stdout), ["E_NO_DEPLOYMENT", None, None, None, None]
        )
        self.assertNotIn("private result", result.stdout)


class ReleasedKernelAdmissionTest(unittest.TestCase):
    def test_green_direct_channel_lane_cannot_hide_missing_or_failed_kernel(self):
        for receipt in (
            None,
            [],
            {},
            {"result": "FAILED", "error": "kernel wake failed"},
        ):
            with self.subTest(receipt=receipt):
                qualified = add_kernel_wake_result(
                    qualification={"status": "PASSED"}, kernel_receipt=receipt
                )
                self.assertEqual(qualified["status"], "FAILED")
                self.assertIn("error", qualified["released_kernel_wake"])
                if receipt is None or not isinstance(receipt, dict) or not receipt:
                    self.assertIn(
                        "Re-run the user-paths stage",
                        qualified["released_kernel_wake"]["error"],
                    )
                    self.assertIn(
                        "released-kernel-wake.json",
                        qualified["released_kernel_wake"]["error"],
                    )

    def test_kernel_pass_preserves_other_lane_failure(self):
        receipt = {"result": "PASSED"}
        self.assertEqual(
            add_kernel_wake_result(
                qualification={"status": "FAILED"}, kernel_receipt=receipt
            )["status"],
            "FAILED",
        )
        self.assertEqual(
            add_kernel_wake_result(
                qualification={"status": "PASSED"}, kernel_receipt=receipt
            )["status"],
            "PASSED",
        )


if __name__ == "__main__":
    unittest.main()

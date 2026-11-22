"""Source-build stamps and released CLI bootstrap must preserve lane identity."""

import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/e2e"))
from user_paths import identity_parent_arguments  # noqa: E402

LEGACY_HELP = """Create a global identity.
Usage:
  aw id create [flags]
Flags:
      --domain string     Namespace domain
      --name string       Global name
      --registry string   Registry
"""


class BootstrapControls(unittest.TestCase):
    def test_legacy_creation_keeps_its_own_supported_command(self):
        self.assertEqual(identity_parent_arguments(LEGACY_HELP), ())

    def test_parent_capable_client_keeps_explicit_root_parent(self):
        self.assertEqual(
            identity_parent_arguments(
                LEGACY_HELP + "      --root-parent   Issue under root\n"
            ),
            ("--root-parent",),
        )

    def test_prose_does_not_advertise_a_flag(self):
        self.assertEqual(
            identity_parent_arguments(
                "See --root-parent in newer releases.\n" + LEGACY_HELP
            ),
            (),
        )

    def test_unrecognized_help_refuses_with_recovery(self):
        with self.assertRaisesRegex(
            RuntimeError, "Inspect the selected CLI's id create --help and rerun"
        ):
            identity_parent_arguments("aw dev\n")

    def test_actual_make_build_stamps_the_checkout_commit(self):
        # Real Git, Make, Go compiler and linker; the small executable isolates
        # the source-build recipe from unrelated CLI dependencies and services.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Makefile").write_bytes((ROOT / "cli/go/Makefile").read_bytes())
            (root / "go.mod").write_text("module fixture.invalid/stamp\n\ngo 1.23\n")
            source = root / "cmd/aw"
            source.mkdir(parents=True)
            (source / "main.go").write_text(
                'package main\nimport "fmt"\nvar commit = "none"\n'
                'func main() { fmt.Println("aw dev\\n  commit: " + commit) }\n'
            )
            env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
            for command in (
                ["git", "init", "-q"],
                ["git", "add", "."],
                [
                    "git",
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                ["make", "build"],
            ):
                result = subprocess.run(
                    command,
                    cwd=root,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=90,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            version = subprocess.check_output([str(root / "aw"), "version"], text=True)
            self.assertIn("commit: " + commit, version)
            shutil.rmtree(root / ".git")
            refused = subprocess.run(
                ["make", "build"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(
                "Build from a Git checkout with a committed HEAD.", refused.stderr
            )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"
PIN_FILE = REPO_ROOT / "oas" / "upstream-test-pin.json"
PREPARE_SCRIPT = REPO_ROOT / "scripts" / "prepare-pinned-oas.mjs"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-all-check.yml"


class OASPinnedCheckoutContractTests(unittest.TestCase):
    def test_default_is_repo_owned_pin_with_explicit_override(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("OAS_TEST_ROOT ?= $(OAS_PINNED_ROOT)", makefile)
        self.assertNotIn("git rev-parse --git-common-dir)/../../oas", makefile)
        self.assertRegex(
            makefile,
            r"(?m)^check-oas-launch-environment-contract:\s+prepare-oas-test-root$",
        )
        self.assertRegex(
            makefile,
            r"(?m)^test-oas-proof-helpers:\s+prepare-oas-test-root$",
        )
        self.assertIn("OAS_TEST_ROOT=/path/to/local/oas", makefile)

    def test_pin_is_an_immutable_public_commit(self) -> None:
        pin = json.loads(PIN_FILE.read_text(encoding="utf-8"))
        self.assertEqual(pin["repository"], "https://github.com/OAS-Framework/oas.git")
        self.assertRegex(pin["commit"], r"\A[0-9a-f]{40}\Z")
        self.assertNotEqual(pin["commit"], "0" * 40)

    def test_materializer_restores_its_cache_to_the_exact_clean_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "upstream"
            target = root / "cache"
            pin_file = root / "pin.json"
            subprocess.run(["git", "init", "-q", str(upstream)], check=True)
            subprocess.run(
                ["git", "-C", str(upstream), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(upstream), "config", "user.name", "Test"],
                check=True,
            )
            tracked = upstream / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(upstream), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(upstream), "commit", "-qm", "pin"], check=True)
            commit = subprocess.check_output(
                ["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True
            ).strip()
            pin_file.write_text(
                json.dumps({"repository": str(upstream), "commit": commit}) + "\n",
                encoding="utf-8",
            )

            command = [
                "node",
                str(PREPARE_SCRIPT),
                "--pin-file",
                str(pin_file),
                "--target",
                str(target),
            ]
            subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True, text=True)
            (target / "tracked.txt").write_text("uncommitted\n", encoding="utf-8")
            (target / "untracked.txt").write_text("uncommitted\n", encoding="utf-8")

            subprocess.run(command, cwd=REPO_ROOT, check=True, capture_output=True, text=True)
            self.assertEqual((target / "tracked.txt").read_text(encoding="utf-8"), "reviewed\n")
            self.assertFalse((target / "untracked.txt").exists())
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(target), "rev-parse", "HEAD"], text=True
                ).strip(),
                commit,
            )
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(target), "status", "--porcelain"], text=True
                ),
                "",
            )

    def test_explicit_local_override_is_not_materialized_or_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            override = Path(temporary) / "local-oas"
            override.mkdir()
            sentinel = override / "uncommitted-work"
            sentinel.write_text("keep me\n", encoding="utf-8")
            result = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "prepare-oas-test-root",
                    f"OAS_TEST_ROOT={override}",
                ],
                cwd=REPO_ROOT,
                env={**os.environ, "PATH": os.environ.get("PATH", "")},
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("explicit OAS_TEST_ROOT override", result.stdout)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep me\n")

    def test_ci_runs_the_complete_release_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^\s*pull_request:\s*$")
        self.assertRegex(workflow, r"(?m)^\s*push:\s*$")
        self.assertIn("make release-all-check", workflow)
        self.assertIn("fetch-depth: 0", workflow)


if __name__ == "__main__":
    unittest.main()

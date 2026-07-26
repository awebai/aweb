from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from oas_principal_proof import assert_unchanged, scan_instance, write_snapshot


REPO_ROOT = Path(__file__).resolve().parents[2]


class PrincipalProofHarnessTests(unittest.TestCase):
    def test_default_suite_runs_proof_helper_tests(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        match = re.search(r"^test\s*:(.*)$", makefile, re.MULTILINE)
        self.assertIsNotNone(match, "Makefile has no default test target")
        self.assertIn("test-oas-proof-helpers", match.group(1).split())

    def test_customer_journey_wires_external_acquisition_and_distinct_operations(self) -> None:
        harness = (REPO_ROOT / "scripts/e2e-oas-attached-principal-retire.sh").read_text(encoding="utf-8")
        for required in (
            'install "$CAPABILITY_SOURCE" --dir "$FIXTURE_REPO"',
            'doctor "$FIXTURE_REPO" --soul proof-worker',
            'fail "$refused_mode refusal mutated an owning authority"',
            'independent developers did not exercise duplicate local instance names',
            'duplicate local names collapsed into one provisioning operation',
            'attacker-after-victim-retire',
            'third failed cleanup did not enter terminal visible quarantine',
            '--retry-quarantine "$QUARANTINE_OPERATION"',
        ):
            self.assertIn(required, harness)

    def test_harness_preflight_checks_repository_paths_without_tooling(self) -> None:
        result = subprocess.run(
            ["/bin/bash", "scripts/e2e-oas-attached-principal-retire.sh", "--preflight"],
            cwd=REPO_ROOT,
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class PrincipalProofFilesystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.principal = self.root / "principal"
        self.credentials = self.principal / "credentials"
        self.state = self.principal / "state"
        self.credentials.mkdir(parents=True)
        self.state.mkdir()
        self.key = self.credentials / "signing.key"
        self.key.write_bytes(b"throwaway-secret-key-material\n")
        (self.state / "state.json").write_text('{"durable":true}\n', encoding="utf-8")
        self.snapshot = self.root / "snapshot.json"
        write_snapshot(str(self.principal), str(self.snapshot))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def instance(self, name: str) -> Path:
        path = self.root / name
        path.mkdir()
        (path / "ordinary.txt").write_text("instance-only\n", encoding="utf-8")
        return path

    def test_snapshot_requires_bytes_paths_and_inodes_to_remain_unchanged(self) -> None:
        assert_unchanged(str(self.principal), str(self.snapshot))
        self.key.write_bytes(b"changed\n")
        with self.assertRaisesRegex(AssertionError, "principal store changed"):
            assert_unchanged(str(self.principal), str(self.snapshot))

    def test_snapshot_rejects_a_principal_store_symlink(self) -> None:
        os.symlink(self.key, self.state / "linked-key")
        with self.assertRaisesRegex(ValueError, "principal store contains a symbolic link"):
            write_snapshot(str(self.principal), str(self.root / "unsafe-snapshot.json"))

    def test_scan_accepts_an_unrelated_instance(self) -> None:
        scan_instance(str(self.snapshot), str(self.instance("clean-instance")))

    def test_scan_rejects_dot_aw_at_any_depth(self) -> None:
        instance = self.instance("dot-aw-instance")
        (instance / "nested" / ".aw").mkdir(parents=True)
        with self.assertRaisesRegex(AssertionError, "forbidden .aw"):
            scan_instance(str(self.snapshot), str(instance))

    def test_scan_rejects_renamed_content_copy(self) -> None:
        instance = self.instance("copy-instance")
        (instance / "innocent.bin").write_bytes(self.key.read_bytes())
        with self.assertRaisesRegex(AssertionError, "principal file content"):
            scan_instance(str(self.snapshot), str(instance))

    def test_scan_rejects_hardlink(self) -> None:
        instance = self.instance("hardlink-instance")
        os.link(self.key, instance / "ordinary-cache")
        with self.assertRaisesRegex(AssertionError, "principal hardlink"):
            scan_instance(str(self.snapshot), str(instance))

    def test_scan_rejects_renamed_symlink_to_exact_principal_root(self) -> None:
        instance = self.instance("symlink-instance")
        os.symlink(self.principal, instance / "ordinary-directory", target_is_directory=True)
        with self.assertRaisesRegex(AssertionError, "symlink resolves into principal store"):
            scan_instance(str(self.snapshot), str(instance))


if __name__ == "__main__":
    unittest.main()

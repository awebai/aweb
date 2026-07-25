from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from oas_principal_proof import assert_unchanged, scan_instance, write_snapshot


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

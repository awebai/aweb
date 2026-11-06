"""Linux runtime prerequisites. Run in the documented disposable proof container."""

import os
import tempfile
import unittest
from pathlib import Path

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.oci_platform import require_memory_directory


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class MemoryStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/memory")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_private_tmpfs_is_accepted(self):
        self.assertEqual(require_memory_directory(self.root), self.root)

    def test_disk_backed_private_directory_is_refused(self):
        with tempfile.TemporaryDirectory(dir="/disk") as disk:
            with self.assertRaisesRegex(Refused, "oci_state_invalid"):
                require_memory_directory(Path(disk))

    def test_public_or_shared_directories_are_refused(self):
        for mode in (0o750, 0o770, 0o755, 0o777):
            self.root.chmod(mode)
            with self.assertRaisesRegex(Refused, "oci_state_invalid"):
                require_memory_directory(self.root)
        self.root.chmod(0o700)
        self.assertEqual(require_memory_directory(self.root), self.root)

    def test_symlink_regular_file_and_missing_path_are_refused(self):
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        file = self.root / "file"
        file.write_bytes(b"not-a-directory")
        for path in (link, file, self.root / "absent"):
            with self.assertRaisesRegex(Refused, "oci_state_invalid"):
                require_memory_directory(path)

    def test_noncanonical_and_relative_paths_are_refused(self):
        for path in (Path("relative"), self.root / "..", Path("/bad\0path")):
            with self.assertRaisesRegex(Refused, "oci_state_invalid"):
                require_memory_directory(path)

    def test_root_owned_storage_is_not_runner_private(self):
        # The test process is a non-root dedicated UID; root's private tmpfs
        # mount is not a runner-owned runtime-state root.
        self.assertNotEqual(os.geteuid(), 0)
        with self.assertRaisesRegex(Refused, "oci_state_invalid"):
            require_memory_directory(Path("/dev"))


if __name__ == "__main__":
    unittest.main()

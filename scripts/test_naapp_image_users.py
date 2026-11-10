#!/usr/bin/env python3
"""Source contract for naapp images; runtime identity is proved by package_lab."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NaappImageUsers(unittest.TestCase):
    def test_every_naapp_image_declares_numeric_nonroot_uid_and_gid(self):
        dockerfiles = sorted(
            path
            for path in (ROOT / "naapp").rglob("*Dockerfile*")
            if path.is_file() and not path.name.endswith(".dockerignore")
        )
        self.assertGreaterEqual(len(dockerfiles), 4)
        for path in dockerfiles:
            with self.subTest(image=str(path.relative_to(ROOT))):
                users = re.findall(r"^USER\s+(\S+)\s*$", path.read_text(), re.MULTILINE)
                self.assertTrue(users, "image must explicitly declare its runtime USER")
                self.assertRegex(
                    users[-1], r"^[1-9][0-9]*:[1-9][0-9]*$",
                    "runAsNonRoot needs a numeric non-root image UID; pin its GID too",
                )


if __name__ == "__main__":
    unittest.main()

"""Filesystem controls for the joined journey's preparation helpers."""

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from adcl6_first_path import save


class SaveTests(unittest.TestCase):
    def test_new_json_is_private_even_with_permissive_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "inputs.json"
            previous_umask = os.umask(0)
            try:
                save(path, {"stage": "prepared"})
            finally:
                os.umask(previous_umask)
            self.assertEqual(json.loads(path.read_text()), {"stage": "prepared"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_replacing_public_json_publishes_a_private_complete_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compose.json"
            path.write_text('{"old": true}')
            path.chmod(0o644)
            save(path, {"services": {"holder": {"user": "1003:1003"}}})
            self.assertEqual(
                json.loads(path.read_text()),
                {"services": {"holder": {"user": "1003:1003"}}},
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(path.with_suffix(".json.tmp").exists())


if __name__ == "__main__":
    unittest.main()

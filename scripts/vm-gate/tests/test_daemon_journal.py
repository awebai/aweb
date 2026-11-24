"""Journal evidence retains the full run across snapshots and interrupted reads."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vm_gate.daemon_journal import drain


class DaemonJournalTests(unittest.TestCase):
    def test_cursor_and_bytes_advance_together_and_final_read_is_archived_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            early = b"early daemon event\n" * 20000
            tail = b"last Docker start failure\n"
            attempts = []

            def journal(command, *, stdout, **kwargs):
                self.assertIn("--boot", command)
                self.assertIn("_PID=1", command)
                for unit in ("docker", "containerd", "dbus", "apt-daily-upgrade"):
                    index = command.index(f"_SYSTEMD_UNIT={unit}.service")
                    self.assertEqual(command[index - 1], "+")
                self.assertNotIn("-n", command)
                cursor = Path(
                    next(
                        arg.split("=", 1)[1]
                        for arg in command
                        if arg.startswith("--cursor-file=")
                    )
                )
                attempts.append(cursor.read_text() if cursor.exists() else "")
                if len(attempts) == 1:
                    stdout.write(early)
                    cursor.write_text("first")
                elif len(attempts) == 2:
                    stdout.write(b"partial output")
                    raise subprocess.CalledProcessError(1, command)
                else:
                    stdout.write(tail)
                    cursor.write_text("last")

            with patch("vm_gate.daemon_journal.subprocess.run", journal):
                self.assertFalse(drain(root))
                with self.assertRaises(subprocess.CalledProcessError):
                    drain(root)
                self.assertTrue(drain(root, finish=True))
                self.assertTrue(drain(root))
                self.assertTrue(drain(root, finish=True))
            self.assertEqual(attempts, ["", "first", "first"])
            self.assertEqual((root / "daemon.log").read_bytes(), early + tail)

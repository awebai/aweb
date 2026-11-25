#!/usr/bin/env python3
"""The cross-registry CLI fixture creates its account with the caller's ids."""
import runpy
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FixtureUserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.etc = Path(self.temp.name)
        (self.etc / 'passwd').write_text('root:x:0:0:root:/root:/bin/sh\n')
        (self.etc / 'group').write_text('root:x:0:\nstaff:x:20:\n')
        self.install = runpy.run_path(str(ROOT / 'scripts/federation-cli-user.py'))['install_user']

    def test_linux_and_mac_ids_resolve_with_requested_primary_group(self):
        for uid, gid in (('1000', '1000'), ('501', '20'), ('12345', '23456')):
            with self.subTest(uid=uid, gid=gid):
                self.install(uid, gid, self.etc)
                rows = [line.split(':') for line in (self.etc / 'passwd').read_text().splitlines()]
                user, = [row for row in rows if row[2] == uid]
                self.assertEqual(user[3], gid)
                self.assertEqual(user[5], '/work/home')
                groups = [line.split(':') for line in (self.etc / 'group').read_text().splitlines()]
                group, = [row for row in groups if row[2] == gid]
                if gid == '20':
                    self.assertEqual(group[0], 'staff')
        before = [(self.etc / name).read_bytes() for name in ('passwd', 'group')]
        self.install('501', '20', self.etc)
        self.install('0', '0', self.etc)
        self.assertEqual(before, [(self.etc / name).read_bytes() for name in ('passwd', 'group')])

    def test_invalid_or_conflicting_ids_refuse_without_changing_accounts(self):
        before = [(self.etc / name).read_bytes() for name in ('passwd', 'group')]
        for uid, gid in (('-1', '20'), ('501:0', '20'), ('501', 'x'), ('0', '20')):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(ValueError):
                self.install(uid, gid, self.etc)
            self.assertEqual(before, [(self.etc / name).read_bytes() for name in ('passwd', 'group')])


if __name__ == '__main__':
    unittest.main()

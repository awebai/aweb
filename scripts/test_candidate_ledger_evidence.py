#!/usr/bin/env python3
"""Container-free controls for the real ledger fixture's failure reporting."""
import contextlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_candidate_gate_ledger as ledger


class EvidenceTests(unittest.TestCase):
    def test_fixture_initdb_mount_is_readable_after_private_git_clone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'
            source.mkdir()
            shutil.copytree(ledger.ROOT / 'scripts/e2e/initdb', source / 'scripts/e2e/initdb')
            ledger.init_fixture_repo(source)
            for args in (['git', 'add', '.'], ['git', '-c', 'user.name=fixture',
                         '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'initdb']):
                subprocess.run(args, cwd=source, check=True, capture_output=True)
            checkout = root / 'checkout'
            subprocess.run(['git', 'clone', '--local', '--no-hardlinks', str(source), str(checkout)],
                           umask=0o077, check=True, capture_output=True)
            sql = '10-create-library-db.sql'
            self.assertEqual(stat.S_IMODE((checkout / 'scripts/e2e/initdb').stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((checkout / 'scripts/e2e/initdb' / sql).stat().st_mode), 0o600)
            (checkout / 'Makefile').write_text(ledger.CLI_E2E_RECIPE)
            docker = root / 'docker'
            docker.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> docker-args\n')
            docker.chmod(0o755)
            bind = root / 'docker-bind'
            bind.mkdir(mode=0o700)
            result = subprocess.run(['make', 'cli-e2e'], cwd=checkout, umask=0o077,
                                    env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                                             AWEB_DOCKER_BIND_ROOT=str(bind), LIBRARY_E2E_PROJECT='owned'),
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            mount = bind / 'ledger-initdb' if (bind / 'ledger-initdb.yml').exists() else checkout / 'scripts/e2e/initdb'
            self.assertEqual(stat.S_IMODE(mount.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((mount / sql).stat().st_mode), 0o644)
            self.assertEqual((mount / sql).read_bytes(), (source / 'scripts/e2e/initdb' / sql).read_bytes())
            self.assertIn(str(mount) + ':/docker-entrypoint-initdb.d:ro',
                          (bind / 'ledger-initdb.yml').read_text())
            self.assertIn('-f\n' + str(bind / 'ledger-initdb.yml') + '\nup\n',
                          (checkout / 'docker-args').read_text())
            self.assertEqual(stat.S_IMODE((checkout / 'scripts/e2e/initdb').stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(bind.stat().st_mode), 0o700)

    def test_unexpected_result_prints_and_retains_child_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            for code, expected in ((42, True), (0, False)):
                result = subprocess.run([sys.executable, '-c',
                                         f'import sys; print("child stdout"); print("child stderr", file=sys.stderr); sys.exit({code})'],
                                        text=True, capture_output=True)
                output = io.StringIO()
                with contextlib.redirect_stderr(output), self.assertRaises(AssertionError):
                    ledger.retain_result(Path(tmp), 'missing-only', result, expected)
                self.assertIn('child stdout', output.getvalue())
                self.assertIn('child stderr', output.getvalue())
                self.assertIn(str(code), output.getvalue())
                self.assertEqual((Path(tmp) / 'missing-only.log').read_text(), result.stdout + result.stderr)
                with contextlib.redirect_stderr(io.StringIO()) as quiet:
                    ledger.retain_result(Path(tmp), 'expected', result, not expected)
                self.assertEqual(quiet.getvalue(), '')

    def test_compose_failure_reports_before_cleanup_and_preserves_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'Makefile').write_text(ledger.CLI_E2E_RECIPE)
            (root / 'scripts/e2e/initdb').mkdir(parents=True)
            (root / 'scripts/e2e/initdb/proof.sql').write_text('SELECT 1;\n')
            docker = root / 'docker'
            docker.write_text('#!' + sys.executable + '\n' + '''import os, sys
from pathlib import Path
args = sys.argv[1:]
with Path('calls').open('a') as output:
    output.write(' '.join(args) + '\\n')
if 'up' in args:
    sys.exit(int(os.environ['PROBE_STATUS']))
elif 'logs' in args:
    print('postgres startup diagnostic')
elif 'ps' in args:
    print('owned-postgres')
elif args[0] == 'inspect':
    sys.exit(9)  # A failed diagnostic must not mask the original exit.
elif 'down' in args:
    sys.exit(int(os.environ['CLEANUP_STATUS']))
''')
            docker.chmod(0o755)
            for probe, cleanup in ((42, 0), (42, 13), (0, 0), (0, 13)):
                with self.subTest(probe=probe, cleanup=cleanup):
                    (root / 'calls').write_text('')
                    env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                               LIBRARY_E2E_PROJECT='owned', PROBE_STATUS=str(probe), CLEANUP_STATUS=str(cleanup),
                               AWEB_DOCKER_BIND_ROOT=str(root / 'docker-bind'))
                    result = subprocess.run(['make', 'cli-e2e'], cwd=root, env=env, text=True, capture_output=True)
                    calls = (root / 'calls').read_text()
                    self.assertIn('down -v --remove-orphans', calls)
                    if probe:
                        self.assertIn('postgres startup diagnostic', result.stdout)
                        self.assertLess(calls.index('logs --no-color postgres'), calls.index('down -v'))
                        self.assertIn('inspect owned-postgres', calls)
                    else:
                        self.assertNotIn('logs --no-color postgres', calls)
                    status = probe or cleanup
                    if status:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(f'Error {status}', result.stderr)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()

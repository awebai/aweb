#!/usr/bin/env python3
"""acwq: real rc2 importer, unchanged AWID version and released dependency floor.

No service doubles: build the historical packages and run the production package
checker in a fresh uv environment. Git history is the committed fixture; changing
these revisions changes the reproduced incident and requires review.
"""
from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

from fixture_repo import init_fixture_repo, run_fixture

ROOT = Path(__file__).resolve().parents[1]
RC2 = '409da7bc6'
PUBLISHED_AWID = 'awid-service-v0.5.36'
spec = importlib.util.spec_from_file_location('package_check', ROOT / 'scripts/check-naapp-lib-package.py')
PACKAGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PACKAGE)


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root)


def archive(root, revision, *paths):
    with tarfile.open(fileobj=io.BytesIO(git(ROOT, 'archive', revision, *paths))) as source:
        source.extractall(root, filter='data')


class PublishedVersionRegression(unittest.TestCase):
    def test_rc2_changed_awid_cannot_reuse_published_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive(root, PUBLISHED_AWID, 'awid')
            init_fixture_repo(root)
            git(root, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
                'add', '.')
            git(root, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
                'commit', '-qm', 'published awid 0.5.36')
            git(root, 'tag', PUBLISHED_AWID)
            # First accept the published tree. Then overlay the real rc2 source,
            # including identity_observation.py, still carrying version 0.5.36.
            command = [sys.executable, str(ROOT / 'scripts/release_versions.py'),
                       '--check-unpublished', '--root', str(root)]
            clean = run_fixture(command, text=True, capture_output=True)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            archive(root, RC2, 'awid')
            self.assertTrue((root / 'awid/src/awid/identity_observation.py').is_file())
            changed = run_fixture(command, text=True, capture_output=True)
            self.assertNotEqual(changed.returncode, 0,
                                'changed awid-service 0.5.36 passed the release version gate')
            self.assertIn('awid-service', changed.stderr)
            self.assertIn('0.5.36', changed.stderr)
            # A new version is the supported neighboring path.
            manifest = root / 'awid/pyproject.toml'
            manifest.write_text(manifest.read_text().replace('version = "0.5.36"', 'version = "0.5.37rc1"'))
            bumped = run_fixture(command, text=True, capture_output=True)
            self.assertEqual(bumped.returncode, 0, bumped.stderr)

    def test_rc2_server_import_is_checked_at_declared_awid_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive(root, RC2, 'server', 'awid', 'naapp-lib')
            server = root / 'server'
            awid = root / 'awid'
            # Assert the incident's actual metadata before building anything.
            self.assertIn('"awid-service>=0.5.34"', (server / 'pyproject.toml').read_text())
            self.assertIn('version = "0.5.36"', (awid / 'pyproject.toml').read_text())
            wheel = PACKAGE._build(server, root / 'dist/server')
            PACKAGE._build(awid, root / 'dist/awid')
            PACKAGE._build(root / 'naapp-lib', root / 'dist/naapp')
            # Probe the actual released importer, without importing unrelated
            # application entrypoints or requiring a database to reproduce it.
            probe = root / 'probe/src/aweb'
            probe.mkdir(parents=True)
            (probe / 'identity_binding.py').write_bytes((server / 'src/aweb/identity_binding.py').read_bytes())
            with self.assertRaisesRegex(PACKAGE.PackageRefusal, r'awid.identity_observation'):
                PACKAGE._check_install(root / 'probe', wheel, PACKAGE._metadata(wheel),
                                       [root / 'dist/awid', root / 'dist/naapp'])


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Run the real sync generators against committed inputs without changing the checkout."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from fixture_repo import init_fixture_repo

ROOT = Path(__file__).resolve().parents[1]


class GeneratedCopiesTest(unittest.TestCase):
    def test_checks_stage_runs_the_drift_gate(self):
        suite = (ROOT / 'scripts/candidate-suite.sh').read_text()
        checks = suite.split('checks() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('run check-generated-copies', checks)

    def test_generators_preserve_current_committed_copies(self):
        self.check_generators(mutate=False)

    def test_source_doc_without_mirror_fails(self):
        self.check_generators(mutate=True)

    def check_generators(self, *, mutate):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = subprocess.check_output([
                'git', 'ls-files', '-z', '--', 'Makefile', 'scripts/sync-skill-copies.sh',
                'scripts/skill-packaging.mjs', 'skills', 'packages/codex-plugin',
                'oats/.agents/capabilities/owned/aweb-tasks', 'docs', 'awid/site/static',
            ], cwd=ROOT).decode().split('\0')
            for name in filter(None, paths):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            init_fixture_repo(root)
            if mutate:
                # Commit the source change without regenerating its mirror: a clean
                # but stale checkout, exactly the main defect that blocked C1.
                with (root / 'docs/trust-model.md').open('a') as handle:
                    handle.write('\nSource-only drift control.\n')
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
                            'commit', '-qm', 'fixture'], cwd=root, check=True)
            result = subprocess.run(['make', 'check-generated-copies'], cwd=root,
                                    capture_output=True, text=True)
            if mutate:
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('awid/site/static/trust-model.md', result.stdout)
                self.assertIn('Source-only drift control.', result.stdout)
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                dirty = subprocess.check_output(['git', 'status', '--porcelain=v1', '-uall'],
                                                cwd=root, text=True)
                self.assertEqual(dirty, '', dirty)


if __name__ == '__main__':
    unittest.main()

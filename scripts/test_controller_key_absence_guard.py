"""Offline controls for mutation-wrapper evidence retention, not journey proof."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / 'scripts/test-e2e-controller-key-absence-guard.sh'
SEED = 'SEED: simulated post-fetch controller-key leak at the production-resolved path'
EXPECTED = 'FAIL: erin remote home has no controller team key (unexpected synthetic-path)'


class EvidenceRetentionTests(unittest.TestCase):
    def run_guard(self, output, status=1):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        scripts = root / 'scripts'
        scripts.mkdir()
        shutil.copyfile(WRAPPER, scripts / WRAPPER.name)
        journey = scripts / 'e2e-oss-user-journey.sh'
        journey.write_text('#!/usr/bin/env bash\ncat <<\'FIXTURE\'\n' + output + '\nFIXTURE\nexit ' + str(status) + '\n')
        journey.chmod(0o700)
        artifacts = root / 'artifacts'
        artifacts.mkdir(mode=0o700)
        env = {**os.environ, 'CANDIDATE_LOG_DIR': str(artifacts)}
        result = subprocess.run(['bash', str(scripts / WRAPPER.name)], env=env,
                                capture_output=True, text=True)
        return result, artifacts

    def test_only_intended_failure_passes_and_removes_output(self):
        result, artifacts = self.run_guard('\n'.join([SEED, EXPECTED, '=== Done ===', 'FAILED: 1 failures, 455 passed']))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(artifacts.iterdir()), [])

    def test_extra_failure_retains_complete_private_output(self):
        lines = [SEED, EXPECTED, 'FAIL: early unrelated assertion (private-fixture-value)']
        lines += ['private padding'] * 100
        lines += ['=== Done ===', 'FAILED: 2 failures, 454 passed']
        output = '\n'.join(lines)
        result, artifacts = self.run_guard(output)
        self.assertEqual(result.returncode, 1)
        files = list(artifacts.glob('*/journey.log'))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_text(), output + '\n')
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(files[0].parent.stat().st_mode), 0o700)
        self.assertNotIn('private-fixture-value', result.stdout + result.stderr)
        self.assertNotIn('private padding', result.stdout + result.stderr)
        self.assertIn('retained privately', result.stderr)

    def test_incomplete_or_wrong_signal_is_not_accepted(self):
        cases = [
            ([SEED, EXPECTED, 'FAILED: 1 failures, 455 passed'], 1),
            ([SEED, EXPECTED, '=== Done ===', 'FAILED: 1 failures, 455 passed'], 0),
            ([EXPECTED, '=== Done ===', 'FAILED: 1 failures, 455 passed'], 1),
            ([SEED, SEED, EXPECTED, '=== Done ===', 'FAILED: 1 failures, 455 passed'], 1),
            ([SEED, 'FAIL: other', '=== Done ===', 'FAILED: 1 failures, 455 passed'], 1),
        ]
        for lines, status in cases:
            with self.subTest(lines=lines, status=status):
                result, artifacts = self.run_guard('\n'.join(lines), status)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(len(list(artifacts.glob('*/journey.log'))), 1)


if __name__ == '__main__':
    unittest.main()

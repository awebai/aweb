"""The early user-path stage must stop the train on a failed real journey."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('user_paths_result', ROOT / 'scripts/e2e/user_paths_result.py')
result_model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(result_model)


class UserPathsAdmission(unittest.TestCase):
    def test_missing_prepared_runtime_fails_without_allocating_or_fetching(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bind = root / 'bind'
            bind.mkdir()
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(('USER_PATHS_', 'CANDIDATE_GATE_IMAGE'))}
            env.update(USER_PATHS_EVIDENCE=str(root / 'evidence'), AWEB_DOCKER_BIND_ROOT=str(bind))
            result = subprocess.run(['python3', str(ROOT / 'scripts/e2e/user_paths_stack.py')],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('infrastructure prerequisite failed; no pull or retry attempted', result.stderr)
            self.assertEqual(list(bind.iterdir()), [])
            self.assertTrue((root / 'evidence/infrastructure.json').is_file())

    def test_missing_lane_failure_cleanup_budget_and_required_humans_cannot_qualify(self):
        inventory = result_model.qualification({}, 10, [])['required_agent_cases']
        lanes = {lane: {'outcomes': [dict(case=case, status='PASSED') for case in inventory if case.startswith(lane + '/')]}
                 for lane in ['head', 'released']}
        full = result_model.qualification(lanes, 100, [])
        self.assertEqual(full['status'], 'INCOMPLETE')
        self.assertEqual(len(full['required_humans']), 12)
        self.assertEqual(len(full['required_agent_cases']), 66)
        self.assertEqual(result_model.qualification({'head': lanes['head']}, 100, [])['status'], 'FAILED')
        self.assertEqual(result_model.qualification(lanes, 600, [])['status'], 'FAILED')
        self.assertEqual(result_model.qualification(lanes, 100, ['owned resource remains'])['status'], 'FAILED')
        lanes['released']['outcomes'][0]['status'] = 'FAILED'
        self.assertEqual(result_model.qualification(lanes, 100, [])['status'], 'FAILED')

    def test_failure_is_a_failed_second_stage_and_stops_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make = root / 'make'
            make.write_text('#!/bin/bash\nprintf "%s\\n" "$1" >> "$CALLS"\n[[ "$1" != e2e-user-paths ]] || exit 86\n')
            make.chmod(0o755)
            result = subprocess.run(['bash', str(ROOT / 'scripts/candidate-suite.sh'), 'checks user-paths unit'],
                                    env=dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                                             CALLS=str(root / 'calls'), CANDIDATE_LOG_DIR=str(root)),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
            self.assertNotIn('_candidate-unit-suites', (root / 'calls').read_text())
            summary = (root / 'summary.tsv').read_text()
            self.assertIn('checks\tPASSED', summary)
            self.assertIn('user-paths\tFAILED', summary)


if __name__ == '__main__':
    unittest.main()

"""Report-only budgets must expose overruns without changing the test verdict."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from gate_budgets import record_stage


class Budgets(unittest.TestCase):
    def test_breach_and_exact_boundary_keep_verdict_and_coverage(self):
        for status in (0, 17):
            for elapsed in (360, 361):
                with self.subTest(status=status, elapsed=elapsed), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    console = io.StringIO()
                    with contextlib.redirect_stdout(console):
                        record_stage(root, 'checks', status, elapsed, 'coverage text')
                    row = (root / 'summary.tsv').read_text().rstrip('\n').split('\t')
                    self.assertEqual(row, ['checks', 'FAILED' if status else 'PASSED', 'checks.log',
                                           f'{elapsed}s', '360s', 'coverage text'])
                    self.assertEqual('BUDGET EXCEEDED' in console.getvalue(), elapsed > 360)
                    verdict = root / 'wrapper-verdict.log'
                    self.assertEqual(verdict.exists(), elapsed > 360)
                    if verdict.exists():
                        self.assertIn('checks 361s > 360s (report-only)', verdict.read_text())

    def test_unbudgeted_user_paths_preserves_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record_stage(root, 'user-paths', 0, 50, 'incomplete: human paths not covered')
            self.assertIn('\t50s\t-\tincomplete: human paths not covered\n',
                          (root / 'summary.tsv').read_text())


if __name__ == '__main__':
    unittest.main()

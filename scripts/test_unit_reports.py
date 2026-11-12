"""Container-free controls with real pytest, Go, Vitest and Node test processes."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
REPORTER = ROOT / 'scripts/unit_report.py'


class ReportCommands(unittest.TestCase):
    def test_signal_failure_is_not_converted_to_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kind in ('pytest', 'vitest', 'go', 'tap'):
                with self.subTest(kind=kind):
                    result = subprocess.run([sys.executable, str(REPORTER), kind, kind, '--',
                                             sys.executable, '-c', 'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'],
                                            env=dict(os.environ, AWEB_UNIT_REPORT_DIR=tmp), capture_output=True)
                    self.assertEqual(result.returncode, -signal.SIGTERM)

    def test_report_options_preserve_arguments_and_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe = root / 'probe.py'
            probe.write_text('import json, sys; print(json.dumps(sys.argv[1:])); sys.exit(17)')
            for kind in ('pytest', 'vitest', 'go', 'tap'):
                with self.subTest(kind=kind):
                    env = dict(os.environ, AWEB_UNIT_REPORT_DIR=str(root / 'reports'))
                    command = [sys.executable, str(REPORTER), kind, kind, '--', sys.executable, str(probe), 'original argument']
                    result = subprocess.run(command, env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 17, result.stderr)
                    actual = json.loads(result.stdout)
                    self.assertEqual(actual[0], 'original argument')
                    expected = {
                        'pytest': ['--junitxml=' + str(root / 'reports/pytest.xml'), '-o', 'junit_duration_report=total'],
                        'vitest': ['--', '--reporter=default', '--reporter=junit', '--outputFile.junit=' + str(root / 'reports/vitest.xml')],
                        'go': ['-json'], 'tap': [],
                    }
                    self.assertEqual(actual[1:], expected[kind])
                    env.pop('AWEB_UNIT_REPORT_DIR')
                    plain = subprocess.run(command, env=env, text=True, capture_output=True)
                    self.assertEqual(plain.returncode, 17)
                    self.assertEqual(json.loads(plain.stdout), ['original argument'])


@unittest.skipUnless('--frameworks' in sys.argv, 'pass --frameworks after installing locked test tools')
class Reports(unittest.TestCase):
    def run_report(self, root, kind, name, command, enabled=True):
        env = dict(os.environ)
        env.pop('AWEB_UNIT_REPORT_DIR', None)
        if enabled:
            env['AWEB_UNIT_REPORT_DIR'] = str(root / 'reports with spaces')
        return subprocess.run([sys.executable, str(REPORTER), kind, name, '--', *command],
                              cwd=root, env=env, text=True, capture_output=True)

    def test_pytest_total_duration_selection_and_failure(self):
        python = ROOT / 'naapp/secrets/.venv/bin/python'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'test_probe.py').write_text('''import pytest, time
@pytest.fixture
def slow_setup():
    time.sleep(.03)
    yield
    time.sleep(.03)
def test_pass(slow_setup): pass
def test_fail(): assert False, 'planted failure'
def test_unselected(): assert False
''')
            command = [str(python), '-m', 'pytest', '-q', 'test_probe.py', '-k', 'not unselected']
            plain = self.run_report(root, 'pytest', 'plain', command, enabled=False)
            result = self.run_report(root, 'pytest', 'first', command)
            self.assertEqual(result.returncode, plain.returncode, result.stdout + result.stderr)
            self.assertEqual(result.returncode, 1)
            report = ET.parse(root / 'reports with spaces/first.xml')
            cases = report.findall('.//testcase')
            self.assertEqual({case.attrib['name'] for case in cases}, {'test_pass', 'test_fail'})
            passed = next(case for case in cases if case.attrib['name'] == 'test_pass')
            self.assertGreaterEqual(float(passed.attrib['time']), .06)
            self.assertEqual(len(report.findall('.//failure')), 1)
            result = self.run_report(root, 'pytest', 'second', [*command, '-k', 'test_pass'])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((root / 'reports with spaces/first.xml').exists())
            self.assertEqual(len(ET.parse(root / 'reports with spaces/second.xml').findall('.//testcase')), 1)

    def test_go_events_keep_failure_and_elapsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'go.mod').write_text('module reporterprobe\n\ngo 1.20\n')
            (root / 'probe_test.go').write_text('package reporterprobe\nimport "testing"\n'
                'func TestPass(t *testing.T) {}\nfunc TestFail(t *testing.T) { t.Fatal("planted failure") }\n')
            result = self.run_report(root, 'go', 'go', ['go', 'test', './...', '-count=1'])
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            events = [json.loads(line) for line in (root / 'reports with spaces/go.jsonl').read_text().splitlines()]
            outcomes = [e for e in events if e.get('Test') and e['Action'] in ('pass', 'fail')]
            self.assertEqual({(e['Test'], e['Action']) for e in outcomes}, {('TestPass', 'pass'), ('TestFail', 'fail')})
            self.assertTrue(all('Elapsed' in e for e in outcomes))
            passing = self.run_report(root, 'go', 'go-pass', ['go', 'test', './...', '-count=1', '-run', '^TestPass$'])
            self.assertEqual(passing.returncode, 0, passing.stdout + passing.stderr)

    def test_vitest_junit_retains_default_output_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'probe.test.js').write_text("test('passes', () => expect(1).toBe(1));\ntest('fails', () => expect(1).toBe(2));\n")
            (root / 'package.json').write_text(json.dumps({'scripts': {'test':
                f'node {ROOT}/channel/node_modules/vitest/vitest.mjs run --globals'}}))
            result = self.run_report(root, 'vitest', 'vitest', ['npm', 'test'])
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            report = ET.parse(root / 'reports with spaces/vitest.xml')
            self.assertEqual(len(report.findall('.//testcase')), 2)
            self.assertEqual(len(report.findall('.//failure')), 1)
            self.assertTrue(all('time' in c.attrib for c in report.findall('.//testcase')))
            self.assertIn('1 failed', result.stdout)
            (root / 'probe.test.js').write_text("test('passes', () => expect(1).toBe(1));\n")
            passing = self.run_report(root, 'vitest', 'vitest-pass', ['npm', 'test'])
            self.assertEqual(passing.returncode, 0, passing.stdout + passing.stderr)

    def test_tap_keeps_native_durations_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'probe.test.cjs').write_text("const test = require('node:test');\ntest('fails', () => { throw Error('planted'); });\n")
            result = self.run_report(root, 'tap', 'pi', ['node', '--test', 'probe.test.cjs'])
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            report = (root / 'reports with spaces/pi.tap').read_text()
            self.assertIn('not ok 1', report)
            self.assertIn('duration_ms:', report)
            (root / 'probe.test.cjs').write_text("require('node:test')('passes', () => {});\n")
            passing = self.run_report(root, 'tap', 'pi-pass', ['node', '--test', 'probe.test.cjs'])
            self.assertEqual(passing.returncode, 0, passing.stdout + passing.stderr)


if __name__ == '__main__':
    if '--frameworks' in sys.argv:
        sys.argv.remove('--frameworks')
    unittest.main()

"""Collected coverage and scheduling controls for the Secrets module split."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from isolated_suites import run_groups
from secrets_shards import load_shards, qualify, validate_collections
from test_naapp_suites import package_commands

ROOT = Path(__file__).resolve().parents[1]


class Partition(unittest.TestCase):
    def test_exact_union_preserves_node_order_and_parameter_separators(self):
        full = ['tests/a.py::test_x[::1]', 'tests/a.py::test_y', 'tests/b.py::test_z']
        self.assertEqual(validate_collections(full, [full[:2], full[2:]]), [2, 1])
        for shards in ([full[:1], full[2:]], [full[:2], full],
                       [full[:2], [*full[2:], 'tests/new.py::test_new']],
                       [list(reversed(full[:2])), full[2:]], [full[:2] * 2, full[2:]]):
            with self.subTest(shards=shards), self.assertRaises(ValueError):
                validate_collections(full, shards)
        with self.assertRaises(ValueError):
            validate_collections([], [[], []])

    def test_manifest_refuses_overlap_missing_files_and_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'tests').mkdir()
            for name in ('a', 'b'):
                (root / f'tests/{name}.py').touch()
            manifest = root / 'shards.json'
            valid = [['tests/a.py'], ['tests/b.py']]
            for shards in (valid, [['tests/a.py'], ['tests/a.py']],
                           [['tests/a.py'], ['tests/missing.py']],
                           [['tests/a.py'], ['../outside.py']]):
                manifest.write_text(json.dumps({'version': 1, 'shards': shards}))
                if shards == valid:
                    self.assertEqual(load_shards(root, manifest), valid)
                else:
                    with self.assertRaises(ValueError):
                        load_shards(root, manifest)

    def test_two_shard_commands_are_isolated_and_keep_five_slots(self):
        packages = ['naapp-lib', 'naapp/folio', 'naapp/library', 'naapp/secrets', 'naapp/logs']
        with tempfile.TemporaryDirectory() as tmp:
            commands = package_commands(packages, [['tests/a.py'], ['tests/b.py']], Path(tmp))
            self.assertEqual(list(commands), ['naapp-lib', 'naapp-folio', 'naapp-library',
                                             'naapp-secrets-1', 'naapp-logs', 'naapp-secrets-2'])
            for number, module in ((1, 'a'), (2, 'b')):
                command = commands[f'naapp-secrets-{number}']
                self.assertEqual(command[:4], ['make', '-C', 'naapp/secrets', 'test'])
                self.assertIn(f'SECRETS_REPORT_NAME=naapp-secrets-{number}', command)
                options = next(a for a in command if a.startswith('SECRETS_PYTEST_ARGS='))
                self.assertIn(f'tests/{module}.py', options)
                self.assertIn(f'shard-{number}/pytest', options)
                self.assertIn(f'shard-{number}/cache', options)
            # Actual child processes prove either shard's failure remains red
            # while all six command receipts survive the five-slot scheduler.
            for failed in ('naapp-secrets-1', 'naapp-secrets-2'):
                jobs = {name: [sys.executable, '-c',
                              'import sys; print(sys.argv[1]); sys.exit(17 if sys.argv[1]==sys.argv[2] else 0)',
                              name, failed] for name in commands}
                logs = Path(tmp) / failed
                self.assertEqual(run_groups(jobs, logs, len(packages), budget=900), 1)
                rows = (logs / 'summary.tsv').read_text().splitlines()
                self.assertEqual(len(rows), 6)
                self.assertEqual(sum('\tFAILED\t' in row for row in rows), 1)
                self.assertTrue(next(row for row in rows if row.startswith(failed + '\t')).split('\t')[1] == 'FAILED')


@unittest.skipUnless('--frameworks' in sys.argv, 'pass --frameworks with locked pytest installed')
class ActualCollection(unittest.TestCase):
    def test_real_make_shards_keep_separate_reports_temps_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            modules = []
            for number in (1, 2):
                module = root / f'test_shard_{number}.py'
                module.write_text('def test_case(tmp_path, pytestconfig):\n'
                                  f'    assert "shard-{number}" in str(tmp_path)\n'
                                  f'    assert "shard-{number}" in str(pytestconfig.cache._cachedir)\n'
                                  f'    assert {number} == 1, "planted second shard failure"\n')
                modules.append([str(module)])
            commands = package_commands(['naapp/secrets'], modules, root)
            env = dict(os.environ, AWEB_UNIT_REPORT_DIR=str(root / 'reports'),
                       AWEB_UNIT_REPORTER=str(ROOT / 'scripts/unit_report.py'),
                       UV_FROZEN='1', UV_OFFLINE='1')
            processes = [subprocess.Popen(command, cwd=ROOT, env=env,
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                          text=True) for command in commands.values()]
            outputs = [process.communicate()[0] for process in processes]
            for number, (process, output) in enumerate(zip(processes, outputs, strict=True), 1):
                self.assertEqual(process.returncode, 0 if number == 1 else 2, output)
                cases = ET.parse(root / f'reports/naapp-secrets-{number}.xml').findall('.//testcase')
                self.assertEqual(len(cases), 1)
                self.assertEqual(cases[0].find('failure') is not None, number == 2)

    def test_real_pytest_refuses_new_module_and_never_executes_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'tests').mkdir()
            for name in ('a', 'b'):
                (root / f'tests/test_{name}.py').write_text(
                    "def test_case():\n    raise AssertionError('collection must not execute me')\n")
            manifest = root / 'shards.json'
            manifest.write_text(json.dumps({'version': 1, 'shards': [
                ['tests/test_a.py'], ['tests/test_b.py']]}))
            (root / 'pytest.ini').write_text('[pytest]\nmarkers = e2e: separate Docker lane\n')
            (root / 'tests/test_owner_acts.py').write_text(
                'import pytest\n@pytest.mark.e2e\ndef test_separate_lane(): assert False\n')
            command = [str(ROOT / 'naapp/secrets/.venv/bin/python'), '-m', 'pytest']
            qualify(root, manifest, root / 'good', command=command)
            receipt = json.loads((root / 'good/summary.json').read_text())
            self.assertEqual(receipt['counts'], [1, 1])
            (root / 'tests/test_new.py').write_text('def test_new(): pass\n')
            with self.assertRaisesRegex(ValueError, 'union'):
                qualify(root, manifest, root / 'new-module', command=command)
            self.assertEqual(json.loads((root / 'new-module/summary.json').read_text())['status'], 'FAILED')
            # An actual collection error must fail before trusting any partial
            # receipt, even if a plugin happened to write it.
            (root / 'tests/test_new.py').write_text('invalid Python syntax !\n')
            with self.assertRaisesRegex(RuntimeError, 'collection failed'):
                qualify(root, manifest, root / 'bad-import', command=command)


if __name__ == '__main__':
    if '--frameworks' in sys.argv:
        sys.argv.remove('--frameworks')
    unittest.main()

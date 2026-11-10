"""Process-level scheduler controls; these do not substitute for Docker acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from isolated_suites import run_groups, unit_allocation
from gate_settings import groups, load_settings, validate


class Scheduling(unittest.TestCase):
    def test_overlap_separate_logs_and_failure_from_every_group(self):
        names = groups(load_settings())
        for failing in [None, *names]:
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                probe = root / 'child.py'
                probe.write_text('''import pathlib, sys, time
root, name, count, failing = sys.argv[1:]
root = pathlib.Path(root)
(root / (name + '.ready')).touch()
deadline = time.monotonic() + 5
while len(list(root.glob('*.ready'))) != int(count):
    assert time.monotonic() < deadline, 'groups did not overlap'
    time.sleep(.01)
print('only-' + name)
raise SystemExit(17 if name == failing else 0)
''')
                commands = {n: [sys.executable, str(probe), tmp, n, str(len(names)), str(failing)] for n in names}
                status = run_groups(commands, root / 'logs', len(names), budget=900)
                self.assertEqual(status == 0, failing is None)
                rows = (root / 'logs/summary.tsv').read_text().splitlines()
                self.assertEqual(len(rows), len(names))
                for name in names:
                    self.assertEqual((root / f'logs/{name}.log').read_text(), f'only-{name}\n')
                    row = next(row.split('\t') for row in rows if row.startswith(name + '\t'))
                    self.assertEqual(row[1], 'FAILED' if name == failing else 'PASSED')
                    self.assertGreaterEqual(float(row[3].removesuffix('s')), 0)
                    self.assertEqual(row[4], '900s')

    def test_allocation_restores_after_success_and_failure(self):
        for failing in (False, True):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                fixture = root / 'docker'
                fixture.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
p=pathlib.Path(os.environ['STATE_FILE'])
s=json.loads(p.read_text())
if sys.argv[1]=='inspect':
    print(json.dumps([{'HostConfig': s[sys.argv[2]]}]))
elif sys.argv[1]=='update':
    a=sys.argv[2:]; name=a[-1]
    s[name]={'NanoCpus':int(float(a[a.index('--cpus')+1])*1e9),
             'Memory':int(a[a.index('--memory')+1]),
             'MemorySwap':int(a[a.index('--memory-swap')+1]),
             'PidsLimit':int(a[a.index('--pids-limit')+1])}
    p.write_text(json.dumps(s))
else: raise SystemExit('unexpected operation')
''')
                fixture.chmod(0o755)
                original = {'runner': {'NanoCpus': 10_000_000_000, 'Memory': 32*1024**3,
                                       'MemorySwap': -1, 'PidsLimit': 2048}}
                state = root / 'state.json'
                state.write_text(json.dumps(original))
                env = dict(os.environ, STATE_FILE=str(state))
                previous = os.environ.get('STATE_FILE')
                os.environ['STATE_FILE'] = str(state)
                try:
                    try:
                        with unit_allocation({'outer': 'runner'}, load_settings()['profiles']['release']['reserve'],
                                             root / 'limits.tsv', docker=str(fixture)):
                            self.assertNotEqual(json.loads(state.read_text()), original)
                            if failing:
                                raise RuntimeError('known unit failure')
                    except RuntimeError as error:
                        self.assertEqual(str(error), 'known unit failure')
                    self.assertEqual(json.loads(state.read_text()), original)
                    self.assertIn('restored', (root / 'limits.tsv').read_text())
                finally:
                    if previous is None: os.environ.pop('STATE_FILE')
                    else: os.environ['STATE_FILE'] = previous

    def test_resource_totals_refuse_overallocation(self):
        settings = load_settings()
        validate(settings)
        settings['profiles']['release']['groups']['server']['runner']['cpus'] = 9
        with self.assertRaisesRegex(ValueError, 'allocation exceeds'):
            validate(settings)


if __name__ == '__main__':
    unittest.main()

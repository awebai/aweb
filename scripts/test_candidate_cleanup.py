#!/usr/bin/env python3
"""Native lifecycle tests: a stateful Docker fake, never a real daemon."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('pressure', ROOT / 'scripts/candidate-host-pressure.py')
pressure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pressure)

# Unknown invocations fail, so a change in the exercised Docker API is visible.
FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
path = pathlib.Path(os.environ['FAKE_STATE'])
s = json.loads(path.read_text())
s['calls'].append(args)
path.write_text(json.dumps(s))
if os.environ.get('FAKE_OFFLINE'):
    sys.exit(1)
kind = {'ps': 'container', 'images': 'image'}.get(args[0], args[0])
if args == ['info']:
    sys.exit(0)
if args[:2] == ['buildx', 'rm']:
    name = args[-1]
    if os.environ.get('FAKE_RETAIN') == 'buildx_buildkit_' + name + '0_state': sys.exit(1)
    s['builder'].pop(name, None)
    s['container'].pop('buildx_buildkit_' + name + '0', None)
    s['volume'].pop('buildx_buildkit_' + name + '0_state', None)
elif args[:2] == ['buildx', 'inspect']:
    sys.exit(0 if args[-1] in s['builder'] else 1)
elif 'inspect' in args:
    sys.exit(0 if args[-1] in s[kind] else 1)
elif args[0] in ('ps', 'images') or (len(args)>1 and args[1] == 'ls'):
    label = args[args.index('--filter') + 1].removeprefix('label=')
    print('\n'.join(k for k,v in s[kind].items() if label in v))
    sys.exit(0)
elif args[0] == 'rm' or (len(args)>1 and args[1] == 'rm'):
    kind = 'container' if args[0] == 'rm' else kind
    name = args[-1]
    if os.environ.get('FAKE_RETAIN') == name:
        sys.exit(1)
    # Model anonymous volume ownership: without -v it leaks.
    if kind == 'container' and name == 'run-postgres' and any('v' in a for a in args[1:] if a.startswith('-')):
        s['volume'].pop('anonymous-postgres', None)
    s[kind].pop(name, None)
else:
    print('UNMODELED ' + repr(args), file=sys.stderr)
    sys.exit(99)
path.write_text(json.dumps(s))
'''


class HostPressureTests(unittest.TestCase):
    def sample(self, **changes):
        return {'platform': 'Darwin', 'status': 'measured', 'vm_pids': [12],
                'kern.num_files': 10000, 'vm_lsof_rows': 20,
                'vm_numeric_fd_rows': 10, **changes}

    def test_distinct_row_units(self):
        self.assertEqual(pressure.lsof_counts('COMMAND PID USER FD TYPE\nvm 12 me cwd DIR\nvm 12 me txt REG\nvm 12 me 3u REG\nvm 12 me 40r REG\n'), (4, 2))
        with self.assertRaises(ValueError):
            pressure.lsof_counts('')

    def test_absolute_bounds_and_numeric_rows_are_only_evidence(self):
        baseline = self.sample()
        self.assertEqual(pressure.compare(baseline, self.sample(**{'kern.num_files': 15000, 'vm_lsof_rows': 5020, 'vm_numeric_fd_rows': 20000}))['status'], 'passed')
        for field, value in [('kern.num_files', 15001), ('vm_lsof_rows', 5021)]:
            self.assertEqual(pressure.compare(baseline, self.sample(**{field: value}))['status'], 'failed')

    def test_missing_or_restarted_vm_cannot_pass(self):
        self.assertEqual(pressure.compare(self.sample(), self.sample(vm_pids=[13]))['status'], 'failed')
        with self.assertRaises(ValueError):
            pressure.compare(self.sample(), self.sample(status='unavailable'))

    def test_capture_raw_snapshots_and_failure_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory) / 'host.json'
            with mock.patch.object(pressure.platform, 'system', return_value='Darwin'), mock.patch.object(pressure, 'command', side_effect=['10000\n', '12 /Docker/com.docker.virtualization\n', 'COMMAND PID USER FD TYPE\nvm 12 me 3u REG\n']):
                self.assertEqual(pressure.capture(dest)['vm_lsof_rows'], 1)
                self.assertTrue(dest.with_suffix('.vm-12.lsof.txt').exists())
            with mock.patch.object(pressure.platform, 'system', return_value='Darwin'), mock.patch.object(pressure, 'command', side_effect=['10000\n', '']):
                with self.assertRaises(RuntimeError):
                    pressure.capture(dest)
                self.assertEqual(json.loads(dest.read_text())['status'], 'unavailable')

    def test_settle_retries_preserves_samples_and_reports_the_passing_one(self):
        for levels, expected in [([16000, 16000, 10000], 'passed'), ([16000] * 4, 'failed')]:
            with self.subTest(levels=levels), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                baseline = root / 'host-before.json'
                baseline.write_text(json.dumps(self.sample()))
                pending = iter(levels)
                def capture_sample(path):
                    result = self.sample(**{'kern.num_files': next(pending)})
                    path.write_text(json.dumps(result))
                    path.with_suffix('.raw.txt').write_text('retained raw evidence')
                    return result
                with mock.patch.object(pressure, 'capture', side_effect=capture_sample), mock.patch.object(pressure.time, 'sleep') as sleep:
                    receipt = pressure.settle(baseline, root)
                self.assertEqual(receipt['status'], expected)
                self.assertEqual(receipt['passed_sample'], 3 if expected == 'passed' else None)
                self.assertEqual(len(receipt['samples']), len(levels))
                self.assertEqual(sleep.call_args_list, [mock.call(15)] * (len(levels) - 1))
                for number in range(1, len(levels) + 1):
                    self.assertTrue((root / f'host-after-{number}.raw.txt').exists())
                self.assertEqual((root / 'host-after.json').read_bytes(), (root / f'host-after-{len(levels)}.json').read_bytes())
                self.assertEqual(json.loads((root / 'host-recovery.json').read_text()), receipt)



class WrapperTests(unittest.TestCase):
    def test_allocations_are_labelled_and_nested_ownership_recorded_before_create(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            manifest = base / 'owned.tsv'
            calls = base / 'calls.jsonl'
            fake = base / 'docker'
            fake.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
a = sys.argv[1:]
m = pathlib.Path(os.environ['CANDIDATE_RESOURCE_MANIFEST'])
with pathlib.Path(os.environ['CALLS']).open('a') as f: f.write(json.dumps(a) + '\\n')
if a[:2] in [['container', 'inspect'], ['volume', 'inspect']]: sys.exit(1)
if a[:2] == ['buildx', 'create']:
    assert 'builder\\tnested-builder' in m.read_text(), 'builder recorded too late'
if a[:1] == ['compose']:
    if a[-3:] == ['config', '--format', 'json']: print(json.dumps({'name': 'dynamic-project'}))
    elif a[-2:] == ['config', '--services']: print('web')
    else: assert 'compose-project\\tdynamic-project' in m.read_text(), 'project recorded too late'
""")
            fake.chmod(0o755)
            (base / 'compose.yaml').write_text('services: {web: {image: alpine}}')
            env = {**os.environ, 'AWEB_CANDIDATE_REAL_DOCKER': str(fake),
                   'AWEB_CANDIDATE_RESOURCE_LABEL': 'run', 'CANDIDATE_RESOURCE_MANIFEST': str(manifest),
                   'CALLS': str(calls), 'BUILDX_BUILDER': 'run-builder', 'TMPDIR': str(base)}
            wrapper = ROOT / 'candidate-gate/bin/docker'
            for args in [('volume', 'create', 'data'), ('network', 'create', 'net'),
                         ('create', '--name', 'c', 'alpine'), ('run', '--rm', 'alpine'),
                         ('buildx', 'create', '--name', 'nested-builder'),
                         ('buildx', 'build', '.'), ('build', '.'), ('compose', 'up', '-d')]:
                proc = subprocess.run([str(wrapper), *args], cwd=base, env=env, capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)
            observed = [json.loads(line) for line in calls.read_text().splitlines()]
            allocating = [a for a in observed if a[0] in ('run', 'create') or a[:2] in (['volume', 'create'], ['network', 'create'], ['buildx', 'build'])]
            self.assertEqual(len(allocating), 6)
            for call in allocating:
                self.assertIn('aweb.candidate-gate=run', call)
            self.assertEqual(manifest.read_text().splitlines(), ['builder\tnested-builder', 'compose-project\tdynamic-project'])
            rejected = subprocess.run([str(wrapper), 'buildx', 'create'], env=env, capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn('explicit name', rejected.stderr)


class LifecycleTests(unittest.TestCase):
    def run_cleanup(self, ending='exit 0', retain='', offline=False, pressure_fail=False, partial=False):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / 'repo'
            (root / 'scripts').mkdir(parents=True)
            shutil.copy(ROOT / 'scripts/candidate-cleanup.sh', root / 'scripts')
            # This stub exercises cleanup propagation; real sampler math is tested above.
            (root / 'scripts/candidate-host-pressure.py').write_text('import sys\nsys.exit(' + ('1' if pressure_fail else '0') + ')\n')
            work = base / 'aweb-candidate-work.test'
            work.mkdir()
            logs = base / 'logs'
            logs.mkdir()
            (logs / 'host-before.json').write_text('{}')
            (logs / 'owned-resources.tsv').write_text('builder\trun-builder\nbuilder\tnested-builder\ncompose-project\tdynamic-project\n')
            owned = ['aweb.candidate-gate=run']
            compose = ['com.docker.compose.project=dynamic-project']
            state = {'calls': [], 'container': {'run-runner': owned, 'run-postgres': owned, 'nested': compose, 'buildx_buildkit_run-builder0': [], 'buildx_buildkit_nested-builder0': [], 'unrelated': []},
                     'network': {'run-net': owned, 'compose-net': compose, 'unrelated': []},
                     'volume': {'workspace': owned, 'compose-data': compose, 'anonymous-postgres': [], 'buildx_buildkit_run-builder0_state': [], 'buildx_buildkit_nested-builder0_state': [], 'unrelated': []},
                     'image': {'run-image': owned, 'compose-image': compose, 'unrelated': []},
                     'builder': {'run-builder': [], 'nested-builder': [], 'unrelated': []}}
            if partial:
                for kind in ('container', 'network', 'volume', 'image', 'builder'):
                    state[kind] = {k:v for k,v in state[kind].items() if k in ('unrelated', 'workspace', 'buildx_buildkit_run-builder0_state')}
            state_path = base / 'state.json'
            state_path.write_text(json.dumps(state))
            binary = base / 'bin'
            binary.mkdir()
            docker = binary / 'docker'
            docker.write_text(FAKE_DOCKER)
            docker.chmod(0o755)
            env = {**os.environ, 'PATH': f'{binary}:{os.environ["PATH"]}', 'FAKE_STATE': str(state_path),
                   'FAKE_RETAIN': retain, 'FAKE_OFFLINE': '1' if offline else ''}
            script = '''set -euo pipefail
ROOT="$1"; work="$2"; LOG_DIR="$3"
resource_label=run; runner_name=run-runner; IMAGE=run-image
buildx_config="$work/buildx"; suite_projects=(fixed-project)
source "$ROOT/scripts/candidate-cleanup.sh"
trap 'cleanup "$?"' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
''' + ending
            proc = subprocess.run(['bash', '-c', script, 'test', str(root), str(work), str(logs)], env=env, capture_output=True, text=True, timeout=30)
            final = json.loads(state_path.read_text())
            self.assertFalse(work.exists(), proc.stderr)
            self.assertFalse(any('prune' in call or 'restart' in call for call in final['calls']))
            for kind in ('container', 'network', 'volume', 'builder', 'image'):
                self.assertIn('unrelated', final[kind])
            return proc, final

    def test_success_failure_and_both_interrupts_remove_all_owned_resources(self):
        for ending, expected in [('exit 0', 0), ('exit 7', 7), ('kill -TERM $$', 143), ('kill -INT $$', 130)]:
            with self.subTest(ending=ending):
                proc, state = self.run_cleanup(ending)
                self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
                for kind in ('container', 'network', 'volume', 'builder', 'image'):
                    self.assertEqual(list(state[kind]), ['unrelated'], (kind, state[kind]))
                self.assertIn('cleanup PASSED', proc.stdout)

    def test_residual_resource_fails_a_successful_run(self):
        proc, state = self.run_cleanup(retain='workspace')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('workspace', state['volume'])
        self.assertIn('cleanup FAILED', proc.stderr)

    def test_partial_builder_bootstrap_and_seed_failure_are_cleaned(self):
        proc, state = self.run_cleanup(ending='exit 2', partial=True)
        self.assertEqual(proc.returncode, 2)
        for kind in ('container', 'network', 'volume', 'builder', 'image'):
            self.assertEqual(list(state[kind]), ['unrelated'])

    def test_retained_builder_state_fails_cleanup(self):
        proc, state = self.run_cleanup(retain='buildx_buildkit_run-builder0_state')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('buildx_buildkit_run-builder0_state', state['volume'])
        self.assertIn('cleanup FAILED', proc.stderr)

    def test_daemon_loss_is_not_absence(self):
        proc, _ = self.run_cleanup(offline=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn('cleanup FAILED', proc.stderr)

    def test_failed_host_recovery_fails_a_successful_run(self):
        proc, _ = self.run_cleanup(pressure_fail=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn('cleanup FAILED', proc.stderr)


if __name__ == '__main__':
    unittest.main()

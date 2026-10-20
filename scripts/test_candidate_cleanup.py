#!/usr/bin/env python3
"""Host measurement parsing and recovery behavior."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('pressure', ROOT / 'scripts/candidate-host-pressure.py')
pressure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pressure)

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
            with mock.patch.object(pressure.platform, 'system', return_value='Darwin'), mock.patch.object(pressure, 'command', side_effect=['10000\n', '12 1 /Docker/com.docker.hyperkit\n', 'COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nvm 12 me 3u REG 1,17 1000 99 /Users/operator/Library/Group Containers/group.com.docker/vms/Docker.raw\n']):
                self.assertEqual(pressure.capture(dest)['vm_lsof_rows'], 1)
                self.assertTrue(dest.with_suffix('.vm-12.lsof.txt').exists())
            with mock.patch.object(pressure.platform, 'system', return_value='Darwin'), mock.patch.object(pressure, 'command', side_effect=['10000\n', '']):
                with self.assertRaises(RuntimeError):
                    pressure.capture(dest)
                self.assertEqual(json.loads(dest.read_text())['status'], 'unavailable')

    def test_actual_docker_vm_is_selected_by_disk_path_not_launcher_or_parent(self):
        # Sanitized shape from the coordinator's 2026-09-30 process snapshot:
        # Apple's VM helper is reparented to launchd, not the Docker launcher.
        processes = """45655 45614 /Applications/Docker.app/Contents/MacOS/com.docker.virtualization
45661 1 /System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine
50000 1 /System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine
"""
        docker_path = '/Users/operator/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw'
        def lsof(path):
            return 'COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nvm 45661 operator cwd DIR 1,17 736 2 /\nvm 45661 operator 6u REG 1,17 1000 999 ' + path + '\n'
        for mode in ('one', 'ambiguous', 'missing'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                dest = Path(directory) / 'host.json'
                queried = []
                def command(*args):
                    if args[0] == 'sysctl': return '10000\n'
                    if args[0] == 'ps': return processes
                    self.assertEqual(args[0], 'lsof')
                    queried.append(int(args[-1]))
                    is_docker = mode == 'ambiguous' or (mode == 'one' and args[-1] == '45661')
                    return lsof(docker_path if is_docker else '/Users/operator/OtherVM/disk.img')
                with mock.patch.object(pressure.platform, 'system', return_value='Darwin'), mock.patch.object(pressure, 'command', side_effect=command):
                    if mode == 'one':
                        result = pressure.capture(dest)
                        self.assertEqual(result['vm_pids'], [45661])
                        self.assertEqual(result['vm_lsof_rows'], 2)
                        self.assertEqual(result['vm_numeric_fd_rows'], 1)
                        self.assertEqual(result['vm_identity']['matched_docker_paths'], [docker_path])
                    else:
                        with self.assertRaises(RuntimeError): pressure.capture(dest)
                        result = json.loads(dest.read_text())
                        self.assertEqual(result['status'], 'unavailable')
                    self.assertEqual([v['pid'] for v in result['vm_candidates']], [45661, 50000])
                    self.assertEqual(queried, [45661, 50000])
                    self.assertTrue(dest.with_suffix('.vm-50000.lsof.txt').exists())

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



if __name__ == '__main__':
    unittest.main()

"""Unit controls for evidence/cleanup ordering; these never contact Docker."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import docker as driver


class Evidence(unittest.TestCase):
    def run_complete_driver(self, evidence, failure=None, suite_status=0, copy_status=0, read_status=0):
        calls, configs = [], {}
        token = 'aw-egress-' + 'a' * 12
        limits = driver.allocation(driver.load_settings(), 'lane', 'server-1')

        def docker(*args):
            calls.append(args)
            if args[:2] == ('network', 'create'):
                return 'network'
            if args[0] == 'create':
                role = ('dns' if 'scripts/test-egress/dns.py' in args else
                        'postgres' if 'postgres:17' in args else
                        'redis' if 'redis:7' in args else 'runner')
                configs[role] = {'NanoCpus': round(limits[role]['cpus'] * 1e9),
                                 'Memory': limits[role]['memory_mib'] * 1024**2,
                                 'PidsLimit': 100}
                if role == 'dns' and failure != 'dns':
                    (evidence / 'dns-denied.log').touch()
                if role == 'runner':
                    self.assertIn('AWEB_UNIT_REPORT_DIR=/tmp/aweb-unit-reports', args)
                return role
            if args[0] == 'inspect':
                if '--format' in args:
                    return 'true'
                return json.dumps([{'NetworkSettings': {'Networks': {token: {'IPAddress': '172.1.1.2'}}},
                                    'HostConfig': configs[args[1]]}])
            return ''

        def run(args, **kwargs):
            calls.append(tuple(args[1:]))
            if args[1] in ('logs', 'inspect'):
                kwargs['stdout'].write('service diagnostic\n')
                return subprocess.CompletedProcess(args, read_status)
            if args[1] == 'exec':
                kwargs['stdout'].write('suite result\n')
                return subprocess.CompletedProcess(args, suite_status)
            if args[1] == 'cp':
                self.assertFalse(any(c[0] == 'rm' for c in calls))
                (evidence / 'reports').mkdir()
                (evidence / 'reports/probe.xml').write_text('<testsuite/>')
                return subprocess.CompletedProcess(args, copy_status)
            return subprocess.CompletedProcess(args, 0)

        def wait(_):
            if failure == 'postgres':
                raise RuntimeError('Postgres did not become ready')

        with patch.object(driver, 'docker', docker), patch.object(driver.subprocess, 'run', run), \
             patch.object(driver.subprocess, 'check_output', return_value='source\n'), \
             patch.object(driver, 'wait_for_postgres', wait), \
             patch.object(driver, 'require_memory_postgres', return_value={}), \
             patch.object(driver.uuid, 'uuid4') as uuid, \
             patch.object(sys, 'argv', ['driver', '--image', 'prepared', '--group', 'server-1', '--evidence', str(evidence)]):
            uuid.return_value.hex = 'a' * 32
            try:
                return driver.main(), calls
            finally:
                self.assertEqual({c[-1] for c in calls if c[0] == 'rm'}, set(configs))

    def test_readiness_failure_keeps_original_error_even_if_diagnostic_read_fails(self):
        for failing, message in [('dns', 'DNS sink did not start'), ('postgres', 'Postgres did not become ready')]:
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'evidence'
                with self.assertRaisesRegex(RuntimeError, message):
                    self.run_complete_driver(root, failure=failing, read_status=1)
                receipt = json.loads((root / 'containers' / (failing + '.capture.json')).read_text())
                self.assertEqual(receipt['logs']['exit_code'], 1)
                self.assertEqual(receipt['inspect']['exit_code'], 1)
                self.assertFalse((root / 'suite.log').exists())

    def test_suite_success_and_failure_copy_reports_before_cleanup(self):
        for status in (0, 7):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'evidence'
                result, _ = self.run_complete_driver(root, suite_status=status)
                self.assertEqual(result, status)
                self.assertTrue((root / 'reports/probe.xml').exists())
                self.assertEqual((root / 'report-copy.status').read_text(), '0\n')

    def test_report_copy_failure_cannot_pass_and_still_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'evidence'
            with self.assertRaisesRegex(RuntimeError, 'evidence=True'):
                self.run_complete_driver(root, copy_status=1)
            self.assertEqual((root / 'report-copy.status').read_text(), '1\n')

    def test_each_service_start_failure_is_retained_before_removal(self):
        for failing in ('dns', 'postgres', 'redis'):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as tmp:
                evidence = Path(tmp) / 'evidence'
                owned = []
                calls = []

                def docker(*args):
                    calls.append(args)
                    if args[:2] == ('network', 'create'):
                        return 'network'
                    if args[0] in ('run', 'create'):
                        role = ('dns' if 'scripts/test-egress/dns.py' in args else
                                'postgres' if 'postgres:17' in args else
                                'redis' if 'redis:7' in args else 'runner')
                        owned.append(role)
                        if args[0] == 'run' and role == failing:
                            raise RuntimeError('forced start failure: ' + failing)
                        return role
                    if args[0] == 'start' and args[1] == failing:
                        raise RuntimeError('forced start failure: ' + failing)
                    if args[0] == 'inspect':
                        return json.dumps([{'NetworkSettings': {'Networks': {token: {'IPAddress': '172.1.1.2'}}}}])
                    return ''

                def run(args, **kwargs):
                    calls.append(tuple(args[1:]))
                    if args[1] in ('logs', 'inspect'):
                        output = 'startup stderr\n' if args[1] == 'logs' else '[{"State":{"Error":"forced"}}]\n'
                        kwargs['stdout'].write(output)
                    if args[1] == 'rm':
                        role = args[-1]
                        self.assertTrue((evidence / 'containers' / (role + '.log')).exists())
                        self.assertTrue((evidence / 'containers' / (role + '.inspect.json')).exists())
                    return subprocess.CompletedProcess(args, 0)

                token = 'aw-egress-' + 'a' * 12
                with patch.object(driver, 'docker', docker), patch.object(driver.subprocess, 'run', run), \
                     patch.object(driver.subprocess, 'check_output', return_value='source\n'), \
                     patch.object(driver.uuid, 'uuid4') as uuid, \
                     patch.object(sys, 'argv', ['driver', '--image', 'prepared', '--group', 'server-1', '--evidence', str(evidence)]):
                    uuid.return_value.hex = 'a' * 32
                    with self.assertRaisesRegex(RuntimeError, 'forced start failure: ' + failing):
                        driver.main()
                self.assertIn('startup stderr', (evidence / 'containers' / (failing + '.log')).read_text())
                self.assertEqual(json.loads((evidence / 'containers' / (failing + '.inspect.json')).read_text())[0]['State']['Error'], 'forced')
                self.assertEqual({c[-1] for c in calls if c[0] == 'rm'}, set(owned))
                self.assertFalse(any(c[0] == 'exec' for c in calls))


if __name__ == '__main__':
    unittest.main()

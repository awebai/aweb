#!/usr/bin/env python3
"""Qualify the real Docker guard with a CI-like inherited DNS search domain.

Run with --image naming an existing Python image. No image build is needed.
The CLI adapter supplies a resolver default only when the harness leaves it unset;
all Docker commands, DNS replies and child lookups are real.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DockerDNS(unittest.TestCase):
    def qualify(self, name, startup_failure=False):
        evidence = EVIDENCE / self._testMethodName
        with tempfile.TemporaryDirectory(prefix='aw-dns-default-') as temp:
            adapter = Path(temp) / 'docker'
            adapter.write_text('''#!/usr/bin/env python3
import os
import sys
args = sys.argv[1:]
if args and args[0] in ('run', 'create') and 'scripts/test-egress/dns.py' in args:
    args[1:1] = ['--mount', 'type=bind,src=' + os.environ['TEST_DNS_SOURCE'] +
                 ',dst=/src/scripts/test-egress,readonly', '--workdir', '/src']
    if os.environ.get('TEST_DNS_START_FAILURE') == '1':
        args[args.index('python3'):] = ['python3', '-c', 'raise SystemExit("planted DNS startup failure")']
if args and args[0] in ('run', 'create') and '--dns' in args and not any(
    arg == '--dns-search' or arg.startswith('--dns-search=') for arg in args
):
    args[1:1] = ['--dns-search', 'runner.internal.cloudapp.net']
os.execv(os.environ['TEST_REAL_DOCKER'], [os.environ['TEST_REAL_DOCKER'], *args])
''')
            adapter.chmod(0o755)
            env = dict(os.environ, TEST_REAL_DOCKER=shutil.which('docker'),
                       TEST_DNS_START_FAILURE='1' if startup_failure else '0',
                       TEST_DNS_SOURCE=str(ROOT / 'scripts/test-egress'),
                       PATH=temp + os.pathsep + os.environ['PATH'])
            child = f'''import socket
from pathlib import Path
print(Path('/etc/resolv.conf').read_text(), flush=True)
try:
    socket.getaddrinfo({name!r}, 443)
except socket.gaierror:
    pass
else:
    raise AssertionError('The no-upstream DNS sink resolved the lookup')
print('Expected DNS refusal; child successful', flush=True)
'''
            result = subprocess.run(
                ['python3', str(ROOT / 'scripts/test-egress/docker.py'),
                 '--evidence', str(evidence), '--image', IMAGE,
                 '--command', 'python3', '-c', child],
                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
        print(result.stdout, flush=True)
        (evidence / 'qualification.log').write_text(result.stdout)
        if not startup_failure:
            self.assertIn('Test child exit status: 0;', result.stdout)
        return result.returncode, evidence

    def test_startup_failure_survives_container_cleanup(self):
        status, evidence = self.qualify('override.test', startup_failure=True)
        self.assertNotEqual(status, 0)
        self.assertFalse((evidence / 'suite.log').exists())
        self.assertIn('planted DNS startup failure', (evidence / 'containers/dns.log').read_text())
        state = json.loads((evidence / 'containers/dns.inspect.json').read_text())[0]['State']
        self.assertFalse(state['Running'])
        self.assertEqual(state['ExitCode'], 1)
        receipt = json.loads((evidence / 'containers/dns.capture.json').read_text())
        self.assertEqual(receipt['logs']['exit_code'], 0)
        self.assertEqual(receipt['inspect']['exit_code'], 0)
        # Inspection after return proves the logs survived actual deletion.
        absent = subprocess.run(['docker', 'inspect', receipt['container']], capture_output=True)
        self.assertNotEqual(absent.returncode, 0)

    def test_reserved_lookup_ignores_inherited_search(self):
        status, evidence = self.qualify('override.test')
        self.assertEqual(status, 0)
        self.assertEqual((evidence / 'dns-denied.log').read_text(), '')
        self.assertIn('override.test', (evidence / 'dns-denied.log.reported').read_text())

    def test_public_lookup_still_fails_guard(self):
        status, evidence = self.qualify('example.com')
        self.assertEqual(status, 1)
        self.assertIn('example.com', (evidence / 'dns-denied.log').read_text())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    IMAGE, EVIDENCE = args.image, args.evidence.resolve()
    unittest.main(argv=[__file__, *remaining])

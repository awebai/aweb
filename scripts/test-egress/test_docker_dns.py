#!/usr/bin/env python3
"""Qualify the real Docker guard with a CI-like inherited DNS search domain.

Run under the suite lock with --image naming a prepared test-egress source image.
The CLI adapter supplies a resolver default only when the harness leaves it unset;
all Docker commands, DNS replies and child lookups are real.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DockerDNS(unittest.TestCase):
    def qualify(self, name):
        evidence = EVIDENCE / self._testMethodName
        with tempfile.TemporaryDirectory(prefix='aw-dns-default-') as temp:
            adapter = Path(temp) / 'docker'
            adapter.write_text('''#!/usr/bin/env python3
import os
import sys
args = sys.argv[1:]
if args and args[0] == 'run' and '--dns' in args and not any(
    arg == '--dns-search' or arg.startswith('--dns-search=') for arg in args
):
    args[1:1] = ['--dns-search', 'runner.internal.cloudapp.net']
os.execv(os.environ['TEST_REAL_DOCKER'], [os.environ['TEST_REAL_DOCKER'], *args])
''')
            adapter.chmod(0o755)
            env = dict(os.environ, TEST_REAL_DOCKER=shutil.which('docker'),
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
        self.assertIn('Test child exit status: 0;', result.stdout)
        return result.returncode, evidence

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

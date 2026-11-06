#!/usr/bin/env python3
"""Host port allocation, plus an opt-in real Library Compose regression probe."""
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def held_library_default():
    with socket.socket() as held:
        try:
            held.bind(('127.0.0.1', 55432))
            held.listen()
        except OSError as error:
            # A preexisting dev stack is precisely the same regression trigger.
            if error.errno != errno.EADDRINUSE:
                raise
        yield


class CandidatePortsTests(unittest.TestCase):
    def allocations(self, overrides=None):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('LIBRARY_E2E_', 'AWEB_', 'AWID_', 'A2A_GW_'))}
        env.update(overrides or {})
        with tempfile.TemporaryDirectory() as temp:
            port_file, naapp_file = Path(temp) / 'ports.env', Path(temp) / 'naapp.tsv'
            subprocess.run([sys.executable, str(ROOT / 'scripts/candidate-ports.py'),
                            'gate-proof', str(port_file), str(naapp_file),
                            'naapp/folio', 'naapp/library'], env=env, check=True)
            ports = dict(line.split('=', 1) for line in port_file.read_text().splitlines())
            return ports, naapp_file.read_text().splitlines(), env

    def test_held_default_does_not_break_library_binding(self):
        with held_library_default():
            ports, _, _ = self.allocations()
            # The old gate omitted this variable, leaving Library's 55432
            # default. The Docker control below exercises the actual mapping.
            published = int(ports.get('LIBRARY_E2E_POSTGRES_PORT', '55432'))
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', published))
                listener.listen()
            self.assertNotEqual(published, 55432)

    @unittest.skipUnless(os.environ.get('AWEB_TEST_DOCKER_PORTS') == '1',
                         'set AWEB_TEST_DOCKER_PORTS=1 for the real Library Postgres probe')
    def test_real_library_postgres_with_held_default(self):
        with held_library_default():
            ports, _, env = self.allocations()
            compose = ['docker', 'compose', '-p', 'gate-port-proof-' + uuid.uuid4().hex[:12],
                       '-f', str(ROOT / 'docker-compose.e2e.yml')]
            try:
                # Original gate environment: Compose falls back to the held
                # 55432 port. Prove Docker rejects that exact binding first.
                refused = subprocess.run([*compose, 'up', '-d', '--wait', 'postgres'],
                                         env=env, text=True, capture_output=True, timeout=120)
                self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
                self.assertRegex(refused.stdout + refused.stderr,
                                 r'(?i)(port is already allocated|address already in use|ports are not available)')
                subprocess.run([*compose, 'down', '-v', '--remove-orphans'],
                               env=env, check=True, capture_output=True, timeout=60)
                env.update(ports)
                result = subprocess.run([*compose, 'up', '-d', '--wait', 'postgres'],
                                        env=env, text=True, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                probe = subprocess.run([*compose, 'exec', '-T', 'postgres', 'pg_isready', '-U', 'aweb'],
                                       env=env, text=True, capture_output=True, timeout=15)
                self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
            finally:
                subprocess.run([*compose, 'down', '-v', '--remove-orphans'],
                               env=env, check=True, capture_output=True, timeout=60)

    def test_manual_override_and_distinct_allocations(self):
        with socket.socket() as manual:
            manual.bind(('127.0.0.1', 0))
            override = str(manual.getsockname()[1])
            ports, rows, _ = self.allocations({'LIBRARY_E2E_POSTGRES_PORT': override})
            self.assertEqual(ports['LIBRARY_E2E_POSTGRES_PORT'], override)
            values = [*ports.values(), *(port for row in rows for port in row.split()[2:])]
            self.assertEqual(len(values), len(set(values)))
            self.assertEqual([row.split()[:2] for row in rows], [
                ['naapp/folio', 'gate-proof-naapp-folio'],
                ['naapp/library', 'gate-proof-naapp-library'],
            ])


if __name__ == '__main__':
    unittest.main()

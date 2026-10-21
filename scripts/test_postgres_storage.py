#!/usr/bin/env python3
"""Real PostgreSQL controls for disposable test storage; no mocked services."""
from pathlib import Path
import subprocess
import os
import json
import shutil
import tempfile
import uuid
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHECK = (ROOT / 'scripts/test-postgres-storage.sh').read_text()


class PostgresStorage(unittest.TestCase):
    def test_wrapper_preserves_child_failure_and_removes_only_owned_container(self):
        result = subprocess.run([str(ROOT / 'scripts/test-postgres.sh'), 'sh', '-c',
                                 'test "$PGHOST" = 127.0.0.1 && test "$PGPORT" = "$TEST_DB_PORT" && test "${#PGPASSWORD}" -eq 48 && exit 7'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 7, result.stderr)
        evidence = Path(result.stderr.split('PostgreSQL test evidence: ')[-1].strip())
        self.assertFalse((evidence / 'environment').exists())
        inspection = json.loads((evidence / 'postgres-inspect.json').read_text())[0]
        self.assertEqual(inspection['HostConfig']['PortBindings']['5432/tcp'][0]['HostIp'], '127.0.0.1')
        password = next(x for x in inspection['Config']['Env'] if x.startswith('POSTGRES_PASSWORD='))
        self.assertEqual(password, 'POSTGRES_PASSWORD=[REDACTED]')
        gone = subprocess.run(['docker', 'inspect', inspection['Id']], capture_output=True)
        self.assertNotEqual(gone.returncode, 0)

    def test_candidate_wrapper_keeps_pg_budget_and_stages_checker(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('AWEB_DOCKER_BIND_ROOT')) as directory:
            directory = Path(directory)
            staged = directory / 'checker.sh'
            staged.write_text(CHECK)
            bad = directory / 'bad-checker.sh'
            bad.write_text('echo wrong-checker-control >&2\nexit 1\n')
            compose = directory / 'compose.json'
            compose.write_text(json.dumps({'services': {'postgres': {
                'image': 'postgres:17',
                'environment': {'POSTGRES_PASSWORD': 'disposable-test-only'},
                'mem_limit': '2g', 'memswap_limit': '2g',
                'tmpfs': ['/var/lib/postgresql/data:rw,nosuid,nodev,size=1g'],
                'volumes': [str(bad) + ':/test-postgres-storage.sh:ro'],
                'healthcheck': {'test': ['CMD-SHELL', 'sh /test-postgres-storage.sh'],
                                'interval': '1s', 'timeout': '5s', 'retries': 30},
            }}}))
            project = 'aciq-pg-wrapper-' + uuid.uuid4().hex[:12]
            real = os.environ.get('AWEB_CANDIDATE_REAL_DOCKER') or (
                '/usr/bin/docker' if Path('/usr/bin/docker').exists() else shutil.which('docker'))
            env = {**os.environ, 'AWEB_CANDIDATE_REAL_DOCKER': real,
                   'AWEB_CANDIDATE_RESOURCE_LABEL': project,
                   'AWEB_TEST_POSTGRES_CHECKER': str(staged)}
            command = ['bash', str(ROOT / 'candidate-gate/bin/docker'),
                       'compose', '-p', project, '-f', str(compose)]
            try:
                negative = subprocess.run([*command, 'up', '-d', '--wait', '--wait-timeout', '10'],
                                          env={**env, 'AWEB_TEST_POSTGRES_CHECKER': str(bad)},
                                          capture_output=True, text=True)
                self.assertNotEqual(negative.returncode, 0)
                failed_id = subprocess.check_output([*command, 'ps', '-q', 'postgres'], env=env,
                                                   text=True).strip()
                failed = json.loads(subprocess.check_output([real, 'inspect', failed_id], text=True))[0]
                self.assertTrue(any('wrong-checker-control' in entry['Output']
                                    for entry in failed['State']['Health']['Log']))
                subprocess.run([*command, 'up', '-d', '--wait'], env=env, check=True,
                               capture_output=True, text=True)
                cid = subprocess.check_output([*command, 'ps', '-q', 'postgres'], env=env,
                                              text=True).strip()
                info = json.loads(subprocess.check_output([real, 'inspect', cid], text=True))[0]
                self.assertEqual(info['HostConfig']['Memory'], 2 * 1024**3)
                self.assertEqual(info['HostConfig']['MemorySwap'], 2 * 1024**3)
                binding = next(v for v in info['Mounts'] if v['Destination'] == '/test-postgres-storage.sh')
                self.assertEqual(Path(binding['Source']).resolve(), staged.resolve())
                self.assertFalse(binding['RW'])
                self.assertEqual(info['State']['Health']['Status'], 'healthy')
            finally:
                subprocess.run([*command, 'down', '-v', '--remove-orphans'], env=env,
                               check=True, capture_output=True)

    def test_storage_boundary(self):
        # The refusal controls protect image changes, WAL symlinks and swap.
        cases = [
            ('tmpfs', [], True),
            ('disk', [], False),
            ('different-data-directory', ['-e', 'PGDATA=/tmp/other-data'], False),
            ('disk-wal', ['-e', 'POSTGRES_INITDB_ARGS=--waldir=/var/lib/postgresql/wal'], False),
            ('swap', [], False),
        ]
        for name, extra, allowed in cases:
            with self.subTest(name=name):
                command = ['docker', 'run', '-d', '--cpus', '1', '--memory', '2g',
                           '--memory-swap', '4g' if name == 'swap' else '2g',
                           '--pids-limit', '512', '-e', 'POSTGRES_PASSWORD=disposable-test-only']
                if name != 'disk':
                    command += ['--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=1g']
                cid = subprocess.check_output(command + extra + ['postgres:17'], text=True).strip()
                try:
                    for _ in range(120):
                        ready = subprocess.run(['docker', 'exec', cid, 'pg_isready', '-h',
                                                '127.0.0.1', '-U', 'postgres'], capture_output=True)
                        if ready.returncode == 0:
                            break
                        time.sleep(.25)
                    else:
                        self.fail(subprocess.check_output(['docker', 'logs', cid], text=True))
                    result = subprocess.run(['docker', 'exec', cid, 'sh', '-c', CHECK],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, allowed,
                                     f'{name}: {result.stdout}{result.stderr}')
                finally:
                    subprocess.run(['docker', 'rm', '-f', '-v', cid], check=True,
                                   stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    unittest.main()

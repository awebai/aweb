#!/usr/bin/env python3
"""Real PostgreSQL controls for disposable test storage; no mocked services."""
from pathlib import Path
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHECK = (ROOT / 'scripts/test-postgres-storage.sh').read_text()


class PostgresStorage(unittest.TestCase):
    def test_wrapper_preserves_child_failure_and_removes_only_owned_container(self):
        result = subprocess.run([str(ROOT / 'scripts/test-postgres.sh'), 'sh', '-c',
                                 'test "$PGHOST" = 127.0.0.1 && test "$PGPORT" = "$TEST_DB_PORT" && exit 7'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 7, result.stderr)
        evidence = Path(result.stderr.split('PostgreSQL test evidence: ')[-1].strip())
        self.assertFalse((evidence / 'environment').exists())
        import json
        inspection = json.loads((evidence / 'postgres-inspect.json').read_text())[0]
        self.assertEqual(inspection['HostConfig']['PortBindings']['5432/tcp'][0]['HostIp'], '127.0.0.1')
        password = next(x for x in inspection['Config']['Env'] if x.startswith('POSTGRES_PASSWORD='))
        self.assertEqual(len(password.split('=', 1)[1]), 48)
        gone = subprocess.run(['docker', 'inspect', inspection['Id']], capture_output=True)
        self.assertNotEqual(gone.returncode, 0)

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

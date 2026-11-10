#!/usr/bin/env python3
"""Exercise the actual server worker fixture, with real private Redis processes.

The probe lives outside the product suite so it does not alter its pass set.
It also runs a shared-Redis mutation and requires that specific assertion to fail.
"""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

PROBE = '''
import os
import pytest
from redis import Redis
from redis.asyncio import Redis as AsyncRedis
from test_agent_wake import redis as wake_redis
from test_pubsub_lease_ownership import redis as lease_redis
from test_agent_wake_recovery import proxy as recovery_proxy

def test_workers_do_not_share_redis(worker_id):
    url = os.environ['REDIS_URL']
    assert url.startswith('redis://127.0.0.1:'), 'worker Redis must use loopback TCP'
    with Redis.from_url(url, decode_responses=True) as client:
        client.set('worker-isolation-owner', worker_id, nx=True)
        assert client.get('worker-isolation-owner') == worker_id, 'workers share Redis state'

@pytest.mark.asyncio
async def test_existing_fixtures_reach_worker_redis(wake_redis, lease_redis, recovery_proxy):
    async with AsyncRedis.from_url(os.environ['REDIS_URL']) as expected:
        run_id = (await expected.info('server'))['run_id']
    for client in (wake_redis, lease_redis):
        assert (await client.info('server'))['run_id'] == run_id, 'fixture bypassed worker Redis'
    async with AsyncRedis.from_url(recovery_proxy.url) as client:
        assert (await client.info('server'))['run_id'] == run_id, 'fault proxy bypassed worker Redis'
'''


class ServerWorkers(unittest.TestCase):
    def run_probe(self, root, shared=False):
        source = (ROOT / 'server/tests/conftest.py').read_text()
        if shared:
            source += '''
@pytest.fixture(scope="session", autouse=True)
def deliberately_shared_redis(worker_test_services):
    os.environ['REDIS_URL'] = os.environ['PROBE_SHARED_REDIS']
'''
        (root / 'conftest.py').write_text(source)
        (root / 'test_probe.py').write_text(PROBE)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([
            str(ROOT / 'server'), str(ROOT / 'server/tests'),
        ]))
        # Baseline URL intentionally differs from each worker's URL. Import-time
        # captures must not silently keep using the baseline service.
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        url = f'redis://127.0.0.1:{port}/0'
        env.update(REDIS_URL=url, PROBE_SHARED_REDIS=url)
        process = subprocess.Popen([
            'redis-server', '--bind', '127.0.0.1', '--port', str(port),
            '--save', '', '--appendonly', 'no',
        ], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        try:
            return subprocess.run([
                sys.executable, '-m', 'pytest', '-q', '-n', '2', '--dist=each',
                str(root),
            ], cwd=root, env=env, capture_output=True, text=True, timeout=60)
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_private_workers_and_shared_negative_control(self):
        with tempfile.TemporaryDirectory(prefix='aw-worker-probe-') as tmp:
            root = Path(tmp)
            good = self.run_probe(root)
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            self.assertIn('4 passed', good.stdout)
            bad = self.run_probe(root, shared=True)
            self.assertNotEqual(bad.returncode, 0, bad.stdout + bad.stderr)
            self.assertIn('workers share Redis state', bad.stdout)


if __name__ == '__main__':
    unittest.main()

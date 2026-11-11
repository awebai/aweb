"""Fixture admission must fail before any test can touch an implicit host service.

The child interpreter denies socket connections. Factory-only positive probes
allocate no database; the assigned native run covers actual service allocation.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _probe(tmp_path, package, fixture, *, explicit_pg=False):
    # Load the actual suite conftest as a plugin, including naapp's wrapper.
    probe = tmp_path / 'test_service_probe.py'
    probe.write_text(
        ('from tests.test_db import database_url\n' if fixture == 'database_url' else '') + 'import pytest\n@pytest.mark.asyncio\n'
        f'async def test_fixture({fixture}):\n    pass\n'
    )
    (tmp_path / 'sitecustomize.py').write_text(
        'import socket\n'
        'def denied(*args, **kwargs):\n'
        '    raise AssertionError("fixture attempted I/O before configuration admission")\n'
        'socket.socket.connect = denied\n'
        'socket.socket.connect_ex = denied\n'
        'socket.create_connection = denied\n'
        'socket.getaddrinfo = denied\n'
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith('TEST_DB_') and k != 'REDIS_URL'}
    if explicit_pg:
        env.update(TEST_DB_HOST='127.0.0.1', TEST_DB_PORT='65432')
    env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    env['PYTHONPATH'] = os.pathsep.join(str(p) for p in (
        tmp_path, ROOT/package, ROOT/'awid/src', ROOT/'server/src',
        ROOT/'naapp-lib/src', ROOT/'naapp-lib/testing/src',
    ))
    try:
        return subprocess.run(
            [sys.executable, '-m', 'pytest', '-p', 'pytest_asyncio.plugin', '-p', 'tests.conftest',
             '-o', 'asyncio_mode=auto',
             '-p', 'no:cacheprovider', '-q', '--tb=short', str(probe)],
            cwd=tmp_path, env=env, text=True, capture_output=True, timeout=45,
        )
    finally:
        probe.unlink()


@pytest.mark.parametrize('package', ['awid', 'server', 'naapp-lib'])
def test_factory_refuses_missing_explicit_postgres(tmp_path, package):
    result = _probe(tmp_path, package, 'test_db_factory')
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'Set TEST_DB_HOST and TEST_DB_PORT' in result.stdout, result.stdout + result.stderr
    assert 'attempted I/O' not in result.stdout


@pytest.mark.parametrize('package', ['awid', 'server', 'naapp-lib'])
def test_explicit_postgres_admits_factory_without_allocating(tmp_path, package):
    result = _probe(tmp_path, package, 'test_db_factory', explicit_pg=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_coordination_refuses_missing_redis_before_allocating_databases(tmp_path):
    result = _probe(tmp_path, 'naapp-lib', 'coordination', explicit_pg=True)
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'Set REDIS_URL' in result.stdout, result.stdout + result.stderr
    assert 'attempted I/O' not in result.stdout


def test_direct_database_fixture_refuses_missing_explicit_postgres(tmp_path):
    # Import the actual database_url fixture without copying its implementation.
    result = _probe(tmp_path, 'naapp-lib', 'database_url')
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'Set TEST_DB_HOST and TEST_DB_PORT' in result.stdout, result.stdout + result.stderr
    assert 'attempted I/O' not in result.stdout

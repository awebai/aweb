#!/usr/bin/env python3
"""Real AWID fixture. Prints its loopback URL, lives until stdin closes.

A second stdout line is JSON naming the fixture's storage (database URL and
schema), for test helpers that seed state the CLI cannot publish itself.
Rate limits are off unless AWID_FIXTURE_RATE_LIMITS=production, which runs the
production bucket values on the in-memory limiter, private to this fixture.
AWID_PUBLIC_ORIGINS is the fixture's own loopback origin, unless
AWID_FIXTURE_PUBLIC_ORIGINS=none leaves it unset or names other origins.

With AWID_FIXTURE_RELEASE=production it serves the AWID release production runs,
as published (pinned in production-awid/), instead of this repository's AWID;
the DNS dependency is not available there. Run uv sync --frozen in that project
beforehand.

Uses the suite's PG/Redis when configured, otherwise owns disposable containers.
No service responses are synthesized. Run uv sync --frozen in awid beforehand.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]


def fixture_app():
    """Real service with an optional exact DNS dependency for CLI journeys."""
    from awid_service.main import app
    domain = os.environ.get('AWID_FIXTURE_DNS_DOMAIN')
    if domain:
        from awid.dns_verify import DomainAuthority, DnsVerificationError
        from awid_service.deps import get_domain_verifier

        async def verify_domain(requested):
            if requested != domain:
                raise DnsVerificationError('No fixture DNS authority for ' + requested)
            return DomainAuthority(
                controller_did=os.environ['AWID_FIXTURE_DNS_CONTROLLER'],
                registry_url='https://api.awid.ai', dns_name='_awid.' + domain,
            )

        app.dependency_overrides[get_domain_verifier] = lambda: verify_domain
    return app


def main():
    # Imported here: the AWID child loads this file through runpy, without
    # this directory on its path, for fixture_app alone.
    from disposable_services import disposable_postgres_and_redis

    if os.environ.get('PGHOST'):
        serve(dict(os.environ), owns_services=False)
        return
    with disposable_postgres_and_redis() as services:
        serve({**os.environ, **services}, owns_services=True)


def serve(env, *, owns_services):
    """Serve AWID on env's PG/Redis until stdin closes. Storage this fixture
    does not own is cleaned by dropping its schema."""
    process = None
    listener = None
    schema = 'test_cli_' + uuid.uuid4().hex
    try:
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        from urllib.parse import quote
        database = (f"postgresql://{quote(env.get('PGUSER', 'postgres'), safe='')}:"
                    f"{quote(env.get('PGPASSWORD', 'postgres'), safe='')}@{env['PGHOST']}:"
                    f"{env.get('PGPORT', '5432')}/{env.get('PGDATABASE', 'postgres')}")
        env.update(AWID_DATABASE_URL=database, AWID_REDIS_URL=env.get('REDIS_URL', 'redis://127.0.0.1:6379/0'),
                   AWID_DB_SCHEMA=schema, AWID_RATE_LIMIT_DISABLED='true', APP_ENV='test')
        if os.environ.get('AWID_FIXTURE_RATE_LIMITS') == 'production':
            env.pop('AWID_RATE_LIMIT_DISABLED')
            env['AWID_RATE_LIMIT_BACKEND'] = 'memory'
        # The origin it serves on, which covering controller signatures name,
        # as any deployed registry has; a test of the missing setting opts out,
        # and a test that fronts the fixture with its own server names that
        # server's origin.
        public_origins = os.environ.get('AWID_FIXTURE_PUBLIC_ORIGINS', '')
        if public_origins == 'none':
            env.pop('AWID_PUBLIC_ORIGINS', None)
        else:
            env['AWID_PUBLIC_ORIGINS'] = public_origins or f'http://127.0.0.1:{port}'
        if os.environ.get('AWID_FIXTURE_RELEASE') == 'production':
            if env.get('AWID_FIXTURE_DNS_DOMAIN'):
                raise RuntimeError('the production AWID fixture has no DNS dependency')
            # The release's own server, settings and migrations; nothing of
            # this repository on its path.
            env.pop('PYTHONPATH', None)
            env.pop('VIRTUAL_ENV', None)
            env.pop('AWID_RATE_LIMIT_DISABLED', None)
            env['AWID_RATE_LIMIT_BACKEND'] = 'memory'
            command = ['uv', 'run', '--offline', '--frozen', '--project', str(Path(__file__).resolve().parent / 'production-awid'),
                       'python', '-m', 'uvicorn', 'awid_service.main:create_app', '--factory', '--fd', str(listener.fileno())]
            cwd = tempfile.gettempdir()
        else:
            command = ['uv', 'run', '--offline', '--frozen', '--project', str(ROOT / 'awid'),
                       'python', '-c',
                       "import runpy, sys, uvicorn; uvicorn.run(runpy.run_path(sys.argv[1])['fixture_app'](), fd=int(sys.argv[2]))",
                       str(Path(__file__).resolve()), str(listener.fileno())]
            cwd = None
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=sys.stderr, stderr=sys.stderr, pass_fds=(listener.fileno(),))
        listener.close()
        url = f'http://127.0.0.1:{port}'
        for _ in range(120):
            if process.poll() is not None:
                raise RuntimeError('real AWID exited before readiness')
            try:
                with urllib.request.urlopen(url + '/health', timeout=.5) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(.25)
        else:
            raise RuntimeError('real AWID did not become ready')
        print(url, flush=True)
        print(json.dumps({'database_url': database, 'schema': schema}), flush=True)
        sys.stdin.read()
    finally:
        if listener is not None:
            listener.close()
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if not owns_services:
                cleanup = """import asyncio, asyncpg, os
async def clean():
    conn = await asyncpg.connect(os.environ['AWID_DATABASE_URL'])
    try:
        await conn.execute('DROP SCHEMA IF EXISTS ' + os.environ['AWID_DB_SCHEMA'] + ' CASCADE')
    finally:
        await conn.close()
asyncio.run(clean())
"""
                subprocess.run(['uv', 'run', '--offline', '--frozen', '--project', str(ROOT / 'awid'), 'python', '-c', cleanup], env=env, check=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Real AWID fixture. Prints its loopback URL, lives until stdin closes.

Uses the suite's PG/Redis when configured, otherwise owns disposable containers.
No service responses are synthesized. Run uv sync --frozen in awid beforehand.
"""
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    owned = []
    process = None
    env = dict(os.environ)
    schema = 'test_cli_' + uuid.uuid4().hex
    try:
        if not env.get('PGHOST'):
            for image, port, extra in [
                ('postgres:17', 5432, ['-e', 'POSTGRES_PASSWORD=postgres']),
                ('redis:7', 6379, []),
            ]:
                container = run('docker', 'run', '-d', '--rm', '--cpus', '1', '--memory', '512m',
                                '-p', f'127.0.0.1::{port}', *extra, image)
                owned.append(container)
                mapped = run('docker', 'port', container, str(port)).rsplit(':', 1)[1]
                if port == 5432:
                    env.update(PGHOST='127.0.0.1', PGPORT=mapped, PGUSER='postgres', PGPASSWORD='postgres')
                else:
                    env['REDIS_URL'] = f'redis://127.0.0.1:{mapped}/0'
            for _ in range(60):
                if subprocess.run(['docker', 'exec', owned[0], 'pg_isready', '-U', 'postgres'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    break
                time.sleep(.25)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        from urllib.parse import quote
        database = (f"postgresql://{quote(env.get('PGUSER', 'postgres'), safe='')}:"
                    f"{quote(env.get('PGPASSWORD', 'postgres'), safe='')}@{env['PGHOST']}:"
                    f"{env.get('PGPORT', '5432')}/{env.get('PGDATABASE', 'postgres')}")
        env.update(AWID_DATABASE_URL=database, AWID_REDIS_URL=env.get('REDIS_URL', 'redis://127.0.0.1:6379/0'),
                   AWID_DB_SCHEMA=schema, AWID_RATE_LIMIT_DISABLED='true', APP_ENV='test')
        process = subprocess.Popen(['uv', 'run', '--offline', '--frozen', '--project', str(ROOT / 'awid'),
                                    'uvicorn', 'awid_service.main:app', '--host', '127.0.0.1', '--port', str(port)],
                                   env=env, stdout=sys.stderr, stderr=sys.stderr)
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
        sys.stdin.read()
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if not owned:
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
        for container in reversed(owned):
            subprocess.run(['docker', 'rm', '-f', container], stdout=sys.stderr, check=True)


if __name__ == '__main__':
    main()

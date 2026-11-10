#!/usr/bin/env python3
"""Run Go/Python/Node suites on an internal Docker network with a fail-on-query DNS sink.

Image preparation can download dependencies; the test runner has no external route.
Evidence survives cleanup. No host credentials or identity directories are mounted.
"""
import argparse
import json
import hashlib
import math
import os
import sys
from pathlib import Path
import subprocess
import shutil
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from gate_settings import allocation, load_settings, resource_args


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def postgres_args(runner, limits=None):
    limits = limits or allocation(load_settings(), "lane", "server-1")["postgres"]
    # Disposable databases must not wait on the host disk's WAL fsync. Bound
    # both RAM and WAL growth, and prohibit swapping the tmpfs back to disk.
    return ['run', '-d', '--network', 'container:' + runner,
            *resource_args(limits),
            '--tmpfs', f'/var/lib/postgresql/data:rw,noexec,nosuid,size={limits["memory_mib"] * 3 // 4}m',
            '-e', 'PGDATA=/var/lib/postgresql/data/pgdata',
            '-e', 'POSTGRES_PASSWORD=postgres', 'postgres:17',
            '-c', 'max_wal_size=128MB', '-c', 'min_wal_size=32MB']


def wait_for_postgres(container):
    # The entrypoint's temporary initialization server has no TCP listener.
    for _ in range(60):
        if subprocess.run(['docker', 'exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return
        time.sleep(.5)
    raise RuntimeError('Postgres did not become ready')


def postgres_storage(container):
    data = docker('exec', container, 'psql', '-At', '-U', 'postgres', '-d', 'postgres',
                  '-c', 'SHOW data_directory')
    result = {}
    for name, path in [('data', data), ('wal', data + '/pg_wal')]:
        resolved = docker('exec', container, 'readlink', '-f', path)
        filesystem = docker('exec', container, 'stat', '-f', '-c', '%T', resolved)
        result[name] = {'path': resolved, 'filesystem': filesystem}
    result['swap_max'] = docker('exec', container, 'cat', '/sys/fs/cgroup/memory.swap.max')
    return result


def require_memory_postgres(container):
    storage = postgres_storage(container)
    for name in ('data', 'wal'):
        if storage[name]['filesystem'] != 'tmpfs':
            raise RuntimeError(f'Postgres {name} must be on tmpfs: {storage[name]}')
    if storage['swap_max'] != '0':
        raise RuntimeError(f'Postgres swap must be disabled: memory.swap.max={storage["swap_max"]}')
    return storage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--image', help='already prepared source/dependency image')
    parser.add_argument('--build-image', help='prepare this image once and exit, retaining it')
    parser.add_argument('--profile', choices=['release', 'lane'], default=os.environ.get('AWEB_GATE_PROFILE', 'lane'))
    parser.add_argument('--group', help='shared make test-unit group')
    parser.add_argument('--command', nargs=argparse.REMAINDER, help='guard qualification command instead of make targets')
    parser.add_argument('targets', nargs='*', default=['test-server', 'test-awid', 'test-cli', 'test-channel', 'test-channel-name-live-contract', 'test-channel-core', 'test-pi-extension'])
    args = parser.parse_args()
    if args.image and args.build_image:
        parser.error('--image and --build-image are mutually exclusive')
    settings = load_settings()
    limits = allocation(settings, args.profile, args.group or 'server-1')
    gomaxprocs = max(1, math.ceil(limits['runner']['cpus']))
    args.evidence.mkdir(parents=True, exist_ok=False)
    evidence = args.evidence.resolve()
    (evidence / 'source-sha').write_text(subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True))
    (evidence / 'source-status').write_text(subprocess.check_output(['git', '-C', str(ROOT), 'status', '--short'], text=True))
    token = 'aw-egress-' + uuid.uuid4().hex[:12]
    image = args.image or args.build_image or token
    containers = []
    network = None
    try:
        if not args.image:
            # Copy only source files and a self-contained Git bundle. A worktree's
            # .git file points outside it and cannot be copied into the runner.
            with tempfile.TemporaryDirectory(prefix='aw-egress-source-') as tmp:
                bundle = Path(tmp) / 'source.bundle'
                subprocess.run(['git', '-C', str(ROOT), 'bundle', 'create', str(bundle), 'HEAD'], check=True)
                files = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).decode().split('\0')
                hashes = []
                for name in dict.fromkeys(files):
                    if name and ((ROOT / name).is_file() or (ROOT / name).is_symlink()):
                        destination = Path(tmp) / name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(ROOT / name, destination, follow_symlinks=False)
                        data = destination.readlink().as_posix().encode() if destination.is_symlink() else destination.read_bytes()
                        hashes.append(hashlib.sha256(data).hexdigest() + "  " + name)
                (evidence / 'source-files.sha256').write_text('\n'.join(hashes) + '\n')
                # A docker-container builder cannot resolve a daemon-local tools
                # image. Build the tools and suite setup in one recipe instead.
                recipe = ((ROOT / 'candidate-gate/Dockerfile').read_text()
                          + '\n' + (ROOT / 'scripts/test-egress/Dockerfile').read_text())
                dockerfile = Path(tmp) / 'isolated.Dockerfile'
                dockerfile.write_text(recipe)
                (evidence / 'Dockerfile.generated').write_text(recipe)
                subprocess.run(['docker', 'build', '-f', str(dockerfile),
                                '-t', image, tmp], check=True)
        # Pull service images before entering isolation.
        for service in ('postgres:17', 'redis:7'):
            subprocess.run(['docker', 'image', 'inspect', service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            docker('pull', service)
        if args.build_image:
            return 0
        network = docker('network', 'create', '--internal', token)
        dns = docker('run', '-d', '--network', token, '--name', token + '-dns',
                     *resource_args(limits['dns']),
                     '-v', f'{evidence}:/evidence', image, 'python3',
                     'scripts/test-egress/dns.py', '--log', '/evidence/dns-denied.log')
        containers.append(dns)
        info = json.loads(docker('inspect', dns))[0]
        dns_ip = info['NetworkSettings']['Networks'][token]['IPAddress']
        runner_started = time.monotonic()
        runner = docker('run', '-d', '--init', '--user', '1000:1000', '--network', token, '--dns', dns_ip,
                        '--dns-search', '.',  # Do not expand reserved fixtures using the host's search suffix.
                        '--add-host', '127.0.0.1.nip.io:127.0.0.1',
                        '--name', token + '-runner', *resource_args(limits['runner']),
                        '-e', f'GOMAXPROCS={gomaxprocs}',
                        '-e', 'PGHOST=127.0.0.1', '-e', 'PGUSER=postgres', '-e', 'PGPASSWORD=postgres',
                        '-e', 'REDIS_URL=redis://127.0.0.1:6379/0',
                        image, 'sleep', 'infinity')
        containers.append(runner)
        containers.append(docker(*postgres_args(runner, limits['postgres'])))
        containers.append(docker('run', '-d', '--network', 'container:' + runner,
                                 *resource_args(limits['redis']), 'redis:7'))
        wait_for_postgres(containers[-2])
        storage = require_memory_postgres(containers[-2])
        (evidence / 'postgres-storage.json').write_text(json.dumps(storage, indent=2) + '\n')
        # Preserve the candidate gate's production role-default control.
        docker('exec', containers[-2], 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
               '-c', 'ALTER ROLE postgres SET search_path = pg_catalog')
        for database in ('postgres', 'template1'):
            docker('exec', containers[-2], 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database,
                   '-c', 'CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public')
        if not (evidence / 'dns-denied.log').exists():
            raise RuntimeError('DNS sink did not start')
        if docker('inspect', '--format', '{{.State.Running}}', dns) != 'true':
            raise RuntimeError('DNS sink exited')
        # Retain inspect evidence proving that the runner has only the internal network.
        (evidence / 'network.json').write_text(docker('network', 'inspect', token))
        (evidence / 'runner.json').write_text(docker('inspect', runner))
        with (evidence / 'resource-limits.tsv').open('w') as receipt:
            for role, container in zip(('dns', 'runner', 'postgres', 'redis'), containers):
                actual = json.loads(docker('inspect', container))[0]['HostConfig']
                expected = limits[role]
                if actual['NanoCpus'] != round(expected['cpus'] * 1e9) or actual['Memory'] != expected['memory_mib'] * 1024**2:
                    raise RuntimeError(f'{role} effective allocation differs from settings')
                receipt.write(f'{args.group or "focused"}/{role}\tcpus={actual["NanoCpus"]/1e9:g}\tmemory={actual["Memory"]}\tpids={actual["PidsLimit"]}\tGOMAXPROCS={gomaxprocs}\n')
        command = args.command or ['make', 'TEST_EGRESS_RUNNER=', *([f'test-unit-{args.group}'] if args.group else args.targets)]
        with (evidence / 'suite.log').open('w') as log:
            result = subprocess.run(['docker', 'exec', runner, *command], stdout=log, stderr=subprocess.STDOUT)
        duration = time.monotonic() - runner_started
        # Keep child-created per-package logs before removing its filesystem.
        if args.group == 'naapp':
            subprocess.run(['docker', 'cp', runner + ':/tmp/naapp-unit-logs', str(evidence / 'packages')], check=True)
        print(f'Test child exit status: {result.returncode}; evidence: {evidence}', flush=True)
        if result.returncode:
            print('\n'.join((evidence / 'suite.log').read_text().splitlines()[-100:]), flush=True)
        if docker('inspect', '--format', '{{.State.Running}}', dns) != 'true':
            raise RuntimeError('DNS sink exited during tests')
        report = evidence / 'dns-denied.log.reported'
        if report.exists():
            print('TEST DNS REFUSED (reserved/allowlisted, no upstream):\n' + report.read_text())
        denied = (evidence / 'dns-denied.log').read_text()
        if denied:
            print('TEST DNS EGRESS DENIED:\n' + denied)
        status = result.returncode or (1 if denied else 0)
        (evidence / 'summary.tsv').write_text(f'{args.group or "focused"}\t{"FAILED" if status else "PASSED"}\tsuite.log\t{duration:.3f}s\t{settings["budgets"]["unit"]}s\n')
        return status
    finally:
        cleanup_failed = False
        for container in reversed(containers):
            cleanup_failed |= subprocess.run(['docker', 'rm', '-f', '-v', container], stdout=subprocess.DEVNULL).returncode != 0
        if network:
            cleanup_failed |= subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL).returncode != 0
        if not args.image and not args.build_image:
            subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, check=False)
        if cleanup_failed:
            raise RuntimeError('isolated suite cleanup failed; all owned containers were attempted')


if __name__ == '__main__':
    raise SystemExit(main())

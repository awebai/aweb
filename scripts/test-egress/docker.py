#!/usr/bin/env python3
"""Run Go/Python/Node suites on an internal Docker network with a fail-on-query DNS sink.

Image preparation can download dependencies; the test runner has no external route.
Evidence survives cleanup. No host credentials or identity directories are mounted.
"""
import argparse
import json
import hashlib
from pathlib import Path
import subprocess
import shutil
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--image', help='already prepared source/dependency image')
    parser.add_argument('--command', nargs=argparse.REMAINDER, help='guard qualification command instead of make targets')
    parser.add_argument('targets', nargs='*', default=['test-server', 'test-awid', 'test-cli', 'test-channel', 'test-channel-name-live-contract', 'test-channel-core', 'test-pi-extension'])
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=False)
    evidence = args.evidence.resolve()
    (evidence / 'source-sha').write_text(subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True))
    (evidence / 'source-status').write_text(subprocess.check_output(['git', '-C', str(ROOT), 'status', '--short'], text=True))
    token = 'aw-egress-' + uuid.uuid4().hex[:12]
    image = args.image or token
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
        network = docker('network', 'create', '--internal', token)
        dns = docker('run', '-d', '--network', token, '--name', token + '-dns',
                     '--cpus', '.5', '--memory', '128m', '--pids-limit', '128',
                     '-v', f'{evidence}:/evidence', image, 'python3',
                     'scripts/test-egress/dns.py', '--log', '/evidence/dns-denied.log')
        containers.append(dns)
        info = json.loads(docker('inspect', dns))[0]
        dns_ip = info['NetworkSettings']['Networks'][token]['IPAddress']
        runner = docker('run', '-d', '--init', '--user', '1000:1000', '--network', token, '--dns', dns_ip,
                        '--add-host', '127.0.0.1.nip.io:127.0.0.1',
                        '--name', token + '-runner', '--cpus', '2', '--memory', '8g', '--pids-limit', '2048',
                        '-e', 'PGHOST=127.0.0.1', '-e', 'PGUSER=postgres', '-e', 'PGPASSWORD=postgres',
                        '-e', 'REDIS_URL=redis://127.0.0.1:6379/0',
                        image, 'sleep', 'infinity')
        containers.append(runner)
        for name, command in [('postgres:17', ['-e', 'POSTGRES_PASSWORD=postgres']), ('redis:7', [])]:
            containers.append(docker('run', '-d', '--network', 'container:' + runner,
                                     '--cpus', '1', '--memory', '1g', '--pids-limit', '512', *command, name))
        for _ in range(60):
            if subprocess.run(['docker', 'exec', containers[-2], 'pg_isready', '-U', 'postgres'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(.5)
        else:
            raise RuntimeError('Postgres did not become ready')
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
        with (evidence / 'suite.log').open('w') as log:
            result = subprocess.run(['docker', 'exec', runner, *(args.command or ['make', 'TEST_EGRESS_RUNNER=', *args.targets])], stdout=log, stderr=subprocess.STDOUT)
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
            return 1
        return result.returncode
    finally:
        for container in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', '-v', container], stdout=subprocess.DEVNULL, check=True)
        if network:
            subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, check=True)
        if not args.image:
            subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, check=False)


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run Go/Python/Node suites on an internal Docker network with a fail-on-query DNS sink.

Image preparation can download dependencies; the test runner has no external route.
Evidence survives cleanup. No host credentials or identity directories are mounted.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Event, Thread
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
_worker_spec = importlib.util.spec_from_file_location(
    "server_worker_services", ROOT / "server/tests/worker_services.py")
_worker_module = importlib.util.module_from_spec(_worker_spec)
_worker_spec.loader.exec_module(_worker_module)
service_plan = _worker_module.service_plan

_image_spec = importlib.util.spec_from_file_location(
    "package_image", Path(__file__).with_name("package_image.py"))
_image_module = importlib.util.module_from_spec(_image_spec)
_image_spec.loader.exec_module(_image_module)
prepare_image = _image_module.prepare_image


def runner_args(token, dns_ip, image, profile='portable', server_workers=0):
    # Portable direct callers retain their limits; the CCX33 unit stage selects 7.
    cpus, memory = {'portable': ('2', '8g'), 'ccx33': ('7', '16g')}[profile]
    worker_env = ['-e', f'AWEB_SERVER_TEST_WORKERS={server_workers}'] if server_workers else []
    return ['run', '-d', '--init', '--user', '1000:1000', '--network', token,
            '--dns', dns_ip, '--dns-search', '.',
            '--add-host', '127.0.0.1.nip.io:127.0.0.1',
            '--add-host', 'signer.example.com:127.0.0.1',
            '--name', token + '-runner', '--cpus', cpus, '--memory', memory,
            '--pids-limit', '2048',
            '-e', 'PGHOST=127.0.0.1', '-e', 'PGUSER=postgres',
            '-e', 'PGPASSWORD=postgres', '-e', 'REDIS_URL=redis://127.0.0.1:6379/0',
            *worker_env, image, 'sleep', 'infinity']


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def postgres_args(runner, port=5432, parallel=False):
    # Disposable databases must not wait on the host disk's WAL fsync. Bound
    # both RAM and WAL growth, and prohibit swapping the tmpfs back to disk.
    # Worker 0 also serves the later serial unit suites: keep its original cap.
    memory = '1280m' if parallel and port != 5432 else '2g'
    port_args = ['-c', f'port={port}'] if parallel else []
    return ['run', '-d', '--network', 'container:' + runner,
            '--cpus', '1', '--memory', memory, '--memory-swap', memory, '--pids-limit', '512',
            '--tmpfs', '/var/lib/postgresql/data:rw,noexec,nosuid,size=1g',
            '-e', 'PGDATA=/var/lib/postgresql/data/pgdata',
            '-e', 'POSTGRES_PASSWORD=postgres', 'postgres:17',
            '-c', 'max_wal_size=128MB', '-c', 'min_wal_size=32MB',
            '-c', 'log_lock_waits=on', '-c', 'log_min_duration_statement=1000',
            '-c', 'log_parameter_max_length=0', '-c', 'log_parameter_max_length_on_error=0',
            *port_args]


def redis_args(runner, port=6379, parallel=False):
    primary = port == 6379
    limits = (['--cpus', '1' if primary else '.25', '--memory', '1g' if primary else '128m',
               '--memory-swap', '1g' if primary else '128m', '--pids-limit', '512' if primary else '128']
              if parallel else ['--cpus', '1', '--memory', '1g', '--pids-limit', '512'])
    command = ['redis-server', '--port', str(port)] if parallel else []
    return ['run', '-d', '--network', 'container:' + runner, *limits, 'redis:7', *command]


def wait_for_redis(container, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = subprocess.run(['docker', 'exec', container, 'redis-cli', '-p', str(port), 'ping'],
                                capture_output=True, text=True,
                                timeout=min(2, max(.001, deadline - time.monotonic())))
        if result.returncode == 0 and result.stdout.strip() == 'PONG':
            return
        time.sleep(min(.1, max(0, deadline - time.monotonic())))
    raise RuntimeError('worker Redis did not become ready')


def wait_for_postgres(container, port=5432):
    # The entrypoint's temporary initialization server has no TCP listener.
    for _ in range(60):
        if subprocess.run(['docker', 'exec', container, 'pg_isready', '-h', '127.0.0.1', '-p', str(port), '-U', 'postgres'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return
        time.sleep(.5)
    raise RuntimeError('Postgres did not become ready')


def postgres_storage(container, port=5432):
    data = docker('exec', container, 'psql', '-p', str(port), '-At', '-U', 'postgres', '-d', 'postgres',
                  '-c', 'SHOW data_directory')
    result = {}
    for name, path in [('data', data), ('wal', data + '/pg_wal')]:
        resolved = docker('exec', container, 'readlink', '-f', path)
        filesystem = docker('exec', container, 'stat', '-f', '-c', '%T', resolved)
        result[name] = {'path': resolved, 'filesystem': filesystem}
    result['swap_max'] = docker('exec', container, 'cat', '/sys/fs/cgroup/memory.swap.max')
    return result


def require_memory_postgres(container, port=5432):
    storage = postgres_storage(container, port)
    for name in ('data', 'wal'):
        if storage[name]['filesystem'] != 'tmpfs':
            raise RuntimeError(f'Postgres {name} must be on tmpfs: {storage[name]}')
    if storage['swap_max'] != '0':
        raise RuntimeError(f'Postgres swap must be disabled: memory.swap.max={storage["swap_max"]}')
    return storage


def record_host_load(path, done):
    try:
        with path.open('w', buffering=1) as log:
            while True:
                print(json.dumps({'time': time.time(), 'loadavg': os.getloadavg()}), file=log)
                if done.wait(5):
                    return
    except OSError as error:
        print(f'TEST HOST LOAD CAPTURE FAILED: {error}', file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--image', help='already prepared source/dependency image')
    parser.add_argument('--profile', choices=('portable', 'ccx33'), default='portable',
                        help='bounded runner resources; CCX33 unit resource profile')
    parser.add_argument('--server-workers', type=int, choices=(0, 7), default=0,
                        help='seven-worker server services; requires ccx33 profile')
    parser.add_argument('--collect-summary', action='store_true',
                        help='collect the isolated candidate suite target summary')
    parser.add_argument('--command', nargs=argparse.REMAINDER, help='guard qualification command instead of make targets')
    parser.add_argument('targets', nargs='*', default=['test-server', 'test-awid', 'test-cli', 'test-channel', 'test-channel-name-live-contract', 'test-channel-core', 'test-pi-extension'])
    args = parser.parse_args()
    if args.server_workers and args.profile != 'ccx33':
        parser.error('seven server workers require --profile ccx33')
    if sys.platform == 'darwin':
        sys.path.insert(0, str(ROOT / 'scripts'))
        from local_suite_slots import Scope, SuiteLabel, suite_slot

        with suite_slot(scope=Scope.WHOLE, label=SuiteLabel.PORTABLE, root=ROOT):
            return run_suite(args)
    return run_suite(args)


def run_suite(args):
    args.evidence.mkdir(parents=True, exist_ok=False)
    evidence = args.evidence.resolve()
    (evidence / 'source-sha').write_text(subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True))
    (evidence / 'source-status').write_text(subprocess.check_output(['git', '-C', str(ROOT), 'status', '--short'], text=True))
    token = 'aw-egress-' + uuid.uuid4().hex[:12]
    image = args.image or token
    containers = []
    postgres_log_readers = []
    network = None
    sampling_done = Event()
    sampler = Thread(target=record_host_load, args=(evidence / 'host-load.jsonl', sampling_done), daemon=True)
    try:
        sampler.start()
    except RuntimeError as error:
        print(f'TEST HOST LOAD CAPTURE FAILED: {error}', file=sys.stderr, flush=True)
        sampler = None
    try:
        if not args.image:
            prepare_image(ROOT, evidence, image)
        # Pull service images before entering isolation.
        for service in ('postgres:17', 'redis:7'):
            subprocess.run(['docker', 'image', 'inspect', service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            docker('pull', service)
        network = docker('network', 'create', '--internal', token)
        dns = docker('run', '-d', '--network', token, '--name', token + '-dns',
                     '--cpus', '.5', '--memory', '128m', '--pids-limit', '128',
                     '-v', f'{evidence}:/evidence', image, 'python3',
                     'scripts/test-egress/egress_dns.py', '--log', '/evidence/dns-denied.log')
        containers.append(dns)
        info = json.loads(docker('inspect', dns))[0]
        dns_ip = info['NetworkSettings']['Networks'][token]['IPAddress']
        runner = docker(*runner_args(token, dns_ip, image, args.profile, args.server_workers))
        containers.append(runner)
        services = []
        for plan in service_plan(args.server_workers):
            port = plan['postgres_port']
            pg = docker(*postgres_args(runner, port, bool(args.server_workers)))
            containers.append(pg)
            # Stream from the start so a timeout can still leave diagnostic evidence.
            try:
                with (evidence / f'postgres-{port}.log').open('w') as log:
                    postgres_log_readers.append(subprocess.Popen(
                        ['docker', 'logs', '--follow', '--timestamps', pg],
                        stdout=log, stderr=subprocess.STDOUT,
                    ))
            except OSError as error:
                print(f'TEST POSTGRES LOG CAPTURE FAILED (port {port}): {error}', file=sys.stderr, flush=True)
            redis = docker(*redis_args(runner, plan['redis_port'], bool(args.server_workers)))
            containers.append(redis)
            wait_for_postgres(pg, port)
            storage = require_memory_postgres(pg, port)
            if args.server_workers:
                wait_for_redis(redis, plan['redis_port'])
            # Preserve the production role-default and memory-only storage controls.
            docker('exec', pg, 'psql', '-p', str(port), '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
                   '-c', 'ALTER ROLE postgres SET search_path = pg_catalog')
            for database in ('postgres', 'template1'):
                docker('exec', pg, 'psql', '-p', str(port), '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database,
                       '-c', 'CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public')
            row = {**plan, 'postgres': pg, 'redis': redis, 'storage': storage}
            if args.server_workers:
                row['readbacks'] = {}
                for role, container in [('postgres', pg), ('redis', redis)]:
                    observed = json.loads(docker('inspect', container))[0]
                    limits = observed['HostConfig']
                    if limits['NetworkMode'] != 'container:' + runner or limits.get('PortBindings'):
                        raise RuntimeError('worker service escaped its unpublished runner namespace')
                    row['readbacks'][role] = {
                        'command': observed['Config']['Cmd'],
                        'limits': {name: limits[name] for name in
                                   ('NanoCpus', 'Memory', 'MemorySwap', 'PidsLimit', 'NetworkMode')},
                    }
            services.append(row)
        (evidence / 'postgres-storage.json').write_text(json.dumps(services[0]['storage'], indent=2) + '\n')
        if args.server_workers:
            (evidence / 'worker-services.json').write_text(json.dumps(services, indent=2) + '\n')
        if not (evidence / 'dns-denied.log').exists():
            raise RuntimeError('DNS sink did not start')
        if docker('inspect', '--format', '{{.State.Running}}', dns) != 'true':
            raise RuntimeError('DNS sink exited')
        # Retain inspect evidence proving that the runner has only the internal network.
        (evidence / 'network.json').write_text(docker('network', 'inspect', token))
        (evidence / 'runner.json').write_text(docker('inspect', runner))
        command_env = ['-e', 'AWEB_NAAPP_TEST_DIAGNOSTICS=1']
        if args.collect_summary:
            command_env += ['-e', 'CANDIDATE_LOG_DIR=/tmp']
        if args.collect_summary and args.server_workers:
            shard_services = [
                {key: plan[key] for key in ('postgres_port', 'redis_port')}
                for plan in services[:2]
            ]
            command_env += ['-e', 'AWEB_SECRETS_SHARD_SERVICES=' + json.dumps(shard_services)]
        with (evidence / 'suite.log').open('w') as log:
            result = subprocess.run(['docker', 'exec', *command_env, runner, *(args.command or ['make', 'TEST_EGRESS_RUNNER=', *args.targets])], stdout=log, stderr=subprocess.STDOUT)
        print(f'Test child exit status: {result.returncode}; evidence: {evidence}', flush=True)
        if result.returncode:
            print('\n'.join((evidence / 'suite.log').read_text().splitlines()[-100:]), flush=True)
        if docker('inspect', '--format', '{{.State.Running}}', dns) != 'true':
            raise RuntimeError('DNS sink exited during tests')
        report = evidence / 'dns-denied.log.reported'
        if report.exists():
            print('TEST DNS REFUSED (reserved/allowlisted, no upstream):\n' + report.read_text())
        denied = (evidence / 'dns-denied.log').read_text()
        status = result.returncode
        if denied:
            print('TEST DNS EGRESS DENIED:\n' + denied, flush=True)
            status = status or 1
        if args.collect_summary:
            try:
                docker('cp', f'{runner}:/tmp/summary.tsv', str(evidence / 'summary.tsv'))
            except (OSError, subprocess.CalledProcessError) as error:
                print(f'TEST SUMMARY COPY FAILED: {error}', flush=True)
                status = status or 1
        return status
    finally:
        try:
            for container in reversed(containers):
                subprocess.run(['docker', 'rm', '-f', '-v', container], stdout=subprocess.DEVNULL, check=True)
            if network:
                subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, check=True)
            if not args.image:
                subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, check=False)
        finally:
            sampling_done.set()
            if sampler is not None:
                sampler.join(timeout=1)
            for reader in postgres_log_readers:
                try:
                    reader.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    reader.kill()
                    reader.wait()


if __name__ == '__main__':
    raise SystemExit(main())

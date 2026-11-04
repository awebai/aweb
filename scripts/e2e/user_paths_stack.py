#!/usr/bin/env python3
"""Own one disposable real user-path stack; retain phase timings and artifacts."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from user_paths_result import qualification

REPO = Path(__file__).resolve().parents[2]
BASELINE_WHEEL = os.environ.get('USER_PATHS_BASELINE_WHEEL')
CANDIDATE_BIN = os.environ.get('USER_PATHS_CANDIDATE_BIN')
if os.environ.get('CANDIDATE_SOURCE_SHA') and (BASELINE_WHEEL or CANDIDATE_BIN):
    raise RuntimeError('author diagnostic modes cannot replace the standing candidate stage')
CLIENT_USER = f'{os.getuid()}:{os.getgid()}'
PROJECT = 'aweb-user-paths-' + uuid.uuid4().hex[:12]
EVIDENCE = Path(os.environ.get('USER_PATHS_EVIDENCE', Path(tempfile.gettempdir()) / (PROJECT + '-evidence'))).resolve()
EVIDENCE.mkdir(parents=True, exist_ok=True)
WORK = Path(tempfile.mkdtemp(prefix=PROJECT + '-', dir=os.environ.get('AWEB_DOCKER_BIND_ROOT', tempfile.gettempdir())))
COMPOSE = WORK / 'compose.json'
RESOLVE_SECONDS = float(os.environ.get('USER_PATHS_RESOLVE_SECONDS', '0'))
TIMINGS = {'resolve-released': RESOLVE_SECONDS}
START = time.monotonic() - RESOLVE_SECONDS
RUNTIME_REF = os.environ.get('USER_PATHS_RUNTIME_IMAGE') or os.environ.get('CANDIDATE_GATE_IMAGE')
LOCAL_IMAGES = {}
HEAD_BINARY = '/opt/user-paths/aw'
SERVER_PYTHON = '/opt/candidate-browser/server/.venv/bin/python'
BASELINE_READY = False


@contextmanager
def phase(name):
    started = time.monotonic()
    try:
        yield
    finally:
        TIMINGS[name] = round(time.monotonic() - started, 3)
        (EVIDENCE / 'timings.json').write_text(json.dumps(TIMINGS, indent=2) + '\n')
        print(f'user-paths phase {name}: {TIMINGS[name]:.3f}s', flush=True)


def run(*args, capture=False, timeout=None):
    remaining = max(1, 600 - (time.monotonic() - START))
    return subprocess.run(args, check=True, text=True, capture_output=capture,
                          timeout=timeout or remaining, cwd=REPO)


def compose(*args, **kwargs):
    return run('docker', 'compose', '-p', PROJECT, '-f', str(COMPOSE), *args, **kwargs)


def configuration(dns=None):
    token = 'disposable-user-path-service-token-32-bytes'
    awid = dict(AWID_DATABASE_URL='postgresql://aweb:disposable@postgres:5432/aweb',
                AWID_REDIS_URL='redis://redis:6379/0', AWID_DB_SCHEMA='awid', AWID_HOST='0.0.0.0',
                AWID_PORT='8010', AWID_RATE_LIMIT_DISABLED='true', AWID_SERVICE_TOKEN=token,
                AWID_ALLOW_INSECURE_DELIVERY_ORIGIN='1', AWID_PUBLIC_ORIGINS='http://awid:8010', APP_ENV='development')
    common = dict(AWEB_REDIS_URL='redis://redis:6379/1', AWID_REGISTRY_URL='http://awid:8010',
                  AWID_SERVICE_TOKEN=token, AWEB_HOST='0.0.0.0', AWEB_PORT='8000',
                  AWEB_FEDERATION_TEST='1', APP_ENV='development')
    services = {
        'dns': dict(image=LOCAL_IMAGES['runtime'], entrypoint=['/opt/user-paths/coredns'], command=['-conf', '/zones/Corefile'], volumes=[f'{WORK}/dns:/zones:ro']),
        'postgres': dict(image=LOCAL_IMAGES['postgres'], environment=dict(POSTGRES_USER='aweb', POSTGRES_PASSWORD='disposable', POSTGRES_DB='aweb'),
                         volumes=[f'{WORK}/init.sql:/docker-entrypoint-initdb.d/init.sql:ro'], tmpfs=['/var/lib/postgresql/data'],
                         healthcheck=dict(test=['CMD-SHELL', 'pg_isready -U aweb -d aweb'], interval='1s', timeout='2s', retries=30)),
        'redis': dict(image=LOCAL_IMAGES['redis']),
        'awid': dict(image=LOCAL_IMAGES['runtime'], entrypoint=['/opt/candidate-browser/server/.venv/bin/awid', '--host', '0.0.0.0', '--port', '8010'], environment=awid),
        'server': dict(image=LOCAL_IMAGES['runtime'], entrypoint=['/opt/candidate-browser/server/.venv/bin/aweb', 'serve', '--host', '0.0.0.0', '--port', '8000'], environment=dict(common, AWEB_DATABASE_URL='postgresql://aweb:disposable@postgres:5432/aweb', AWEB_PUBLIC_ORIGIN='http://server:8000')),
        'peer': dict(image=LOCAL_IMAGES['runtime'], entrypoint=['/opt/candidate-browser/server/.venv/bin/aweb', 'serve', '--host', '0.0.0.0', '--port', '8000'], environment=dict(common, AWEB_DATABASE_URL='postgresql://aweb:disposable@postgres:5432/peer', AWEB_PUBLIC_ORIGIN='http://peer:8000')),
        'cli': dict(image=LOCAL_IMAGES['runtime'],
                    user=CLIENT_USER, entrypoint=['sleep', 'infinity'], environment={'APP_ENV': 'development'}, volumes=[f'{WORK}:/work']),
    }
    if BASELINE_READY:
        services['server']['environment']['PYTHONPATH'] = '/work/baseline-package'
        services['server']['volumes'] = [f'{WORK}:/work']
    for service in services.values():
        service.update(cpus=1, mem_limit='1g', pids_limit=256)
    for name in ('awid', 'server', 'peer', 'cli'):
        if dns:
            services[name]['dns'] = [dns]
    return dict(services=services, networks={'default': {'internal': True}})


def wait_ready():
    # Health probes run inside the client, against actual services; no ports exported.
    compose('exec', '-T', 'cli', 'python3', '-c', '''
import time,urllib.request
for origin in ['http://awid:8010','http://server:8000','http://peer:8000']:
 end=time.monotonic()+75
 while True:
  try:
   with urllib.request.urlopen(origin+'/health',timeout=1) as r:
    if r.status==200:break
  except OSError:pass
  assert time.monotonic()<end,origin
  time.sleep(.1)
''')


def main():
    global BASELINE_READY
    # Every invocation exposes the human gap, even if infrastructure fails
    # before provisioning. Runnable agent cases alone control admission.
    initial = qualification({}, time.monotonic() - START, [])
    (EVIDENCE / 'qualification.json').write_text(json.dumps(initial, indent=2) + '\n')
    (EVIDENCE / 'coverage-summary.txt').write_text(initial['coverage_summary'] + '\n')
    for row in initial['required_humans']:
        print(row['case'] + ': ' + row['status'], flush=True)
    print(initial['coverage_summary'], flush=True)
    # A gate timeout/interrupt must reach the same owned cleanup as a failed case.
    def interrupted(signum, _frame):
        raise InterruptedError(f'user-paths interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        with phase('local-images'):
            if not RUNTIME_REF:
                raise RuntimeError('infrastructure: USER_PATHS_RUNTIME_IMAGE/CANDIDATE_GATE_IMAGE is missing; prepare the candidate image before running user-paths')
            for role, reference in [('runtime', RUNTIME_REF), ('postgres', 'postgres:17'), ('redis', 'redis:7')]:
                inspected = run('docker', 'image', 'inspect', reference, capture=True)
                record = json.loads(inspected.stdout)[0]
                LOCAL_IMAGES[role] = record['Id']
                if role == 'runtime':
                    labels = record['Config'].get('Labels') or {}
                    tree = run('git', 'rev-parse', 'HEAD^{tree}', capture=True).stdout.strip()
                    if labels.get('aweb.user-paths-ready') != '1' or labels.get('aweb.user-paths-source-tree') != tree:
                        raise RuntimeError('infrastructure: local runtime lacks prepared user-paths inputs for this source tree; rebuild the candidate image')
            (EVIDENCE / 'local-images.json').write_text(json.dumps(LOCAL_IMAGES, indent=2))
    except Exception as error:
        shutil.rmtree(WORK)
        (EVIDENCE / 'infrastructure.json').write_text(json.dumps(dict(status='FAILED', error=str(error)), indent=2))
        raise RuntimeError('user-paths infrastructure prerequisite failed; no pull or retry attempted: ' + str(error)) from error
    (WORK / 'dns').mkdir()
    (WORK / 'dns/Corefile').write_text('test:53 {\n file /zones/test.zone { reload 1s }\n}\n.:53 {\n forward . 127.0.0.11\n}\n')
    (WORK / 'dns/test.zone').write_text('$ORIGIN test.\n$TTL 1\n@ IN SOA ns.test. hostmaster.test. (1 1 1 1 1)\n@ IN NS ns.test.\nns IN A 127.0.0.1\n')
    (WORK / 'init.sql').write_text('CREATE EXTENSION pgcrypto WITH SCHEMA public;\nCREATE DATABASE peer;\n\\connect peer\nCREATE EXTENSION pgcrypto WITH SCHEMA public;\n')
    for source in ('scripts/fetch_released_aw.py', 'scripts/e2e/user_paths.py', 'scripts/e2e/user_paths_receive.mjs', 'scripts/e2e/user_paths_result.py'):
        shutil.copy2(REPO / source, WORK / Path(source).name)
        (EVIDENCE / 'harness').mkdir(exist_ok=True)
        shutil.copy2(REPO / source, EVIDENCE / 'harness' / Path(source).name)
    (EVIDENCE / 'source-sha.txt').write_text(run('git', 'rev-parse', 'HEAD', capture=True).stdout)
    (EVIDENCE / 'source-status.txt').write_text(run('git', 'status', '--porcelain', capture=True).stdout)
    if CANDIDATE_BIN:
        import hashlib
        binary = Path(CANDIDATE_BIN)
        shutil.copy2(binary, WORK / 'candidate-aw')
        (WORK / 'candidate-aw').chmod(0o700)
        (EVIDENCE / 'candidate-binary.json').write_text(json.dumps(dict(
            source_sha=os.environ['USER_PATHS_CANDIDATE_SHA'],
            sha256=hashlib.sha256(binary.read_bytes()).hexdigest()), indent=2))
    COMPOSE.write_text(json.dumps(configuration()))
    status = 1
    try:
        if BASELINE_WHEEL:
            # Offline historical comparison of a previously hash-checked wheel.
            import hashlib
            wheel = Path(BASELINE_WHEEL)
            shutil.copy2(wheel, WORK / wheel.name)
            (EVIDENCE / 'baseline-artifact.json').write_text(json.dumps(dict(
                filename=wheel.name, sha256=hashlib.sha256(wheel.read_bytes()).hexdigest()), indent=2))
            run('docker', 'run', '--rm', '--pull=never', '--name', PROJECT + '-fetch', '--network', 'none',
                '--user', CLIENT_USER, '--entrypoint', 'python3', '-v', f'{WORK}:/work', LOCAL_IMAGES['runtime'],
                '-m', 'pip', 'install', '--no-index', '--no-deps', '--target=/work/baseline-package', '/work/' + wheel.name)
            BASELINE_READY = True
        with phase('fetch-released'):
            metadata_args = []
            if os.environ.get('USER_PATHS_LATEST_METADATA'):
                shutil.copy2(os.environ['USER_PATHS_LATEST_METADATA'], WORK / 'latest.json')
                import hashlib
                snapshot = (WORK / 'latest.json').read_bytes()
                digest = hashlib.sha256(snapshot).hexdigest()
                expected = os.environ.get('USER_PATHS_LATEST_SHA256')
                if os.environ.get('CANDIDATE_SOURCE_SHA') and not expected:
                    raise RuntimeError('candidate released aw input has no ledger digest')
                if expected and digest != expected:
                    raise RuntimeError('released aw input differs from the ledger digest')
                (EVIDENCE / 'released-metadata.json').write_bytes(snapshot)
                (EVIDENCE / 'released-metadata.sha256').write_text(digest + '\n')
                metadata_args = ['--metadata-input', '/work/latest.json']
            run('docker', 'run', '--rm', '--pull=never', '--name', PROJECT + '-fetch', '--network', 'bridge',
                '--user', CLIENT_USER, '--cpus', '1', '--memory', '512m', '--pids-limit', '64',
                '--entrypoint', 'python3', '-v', f'{WORK}:/work', LOCAL_IMAGES['runtime'], '/work/fetch_released_aw.py', '/work/artifacts/released', *metadata_args)
            provenance = json.loads((WORK / 'artifacts/released/provenance.json').read_text())
            shutil.copy2(WORK / 'artifacts/released/provenance.json', EVIDENCE / 'released-provenance.json')
            if os.environ.get('USER_PATHS_COMPARISON_METADATA'):
                shutil.copy2(os.environ['USER_PATHS_COMPARISON_METADATA'], WORK / 'comparison.json')
                run('docker', 'run', '--rm', '--pull=never', '--name', PROJECT + '-fetch', '--network', 'bridge',
                    '--user', CLIENT_USER, '--cpus', '1', '--memory', '512m', '--pids-limit', '64',
                    '--entrypoint', 'python3', '-v', f'{WORK}:/work', LOCAL_IMAGES['runtime'], '/work/fetch_released_aw.py',
                    '/work/comparison', '--metadata-input', '/work/comparison.json')
                shutil.copy2(WORK / 'comparison/provenance.json', EVIDENCE / 'comparison-provenance.json')
        with phase('setup'):
            compose('up', '--pull', 'never', '-d', 'dns', 'postgres', 'redis')
            dns = run('docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',
                      compose('ps', '-q', 'dns', capture=True).stdout.strip(), capture=True).stdout.strip()
            COMPOSE.write_text(json.dumps(configuration(dns)))
            compose('up', '--pull', 'never', '-d', '--wait', 'postgres')
            compose('up', '--pull', 'never', '-d', 'awid', 'server', 'peer', 'cli')
            wait_ready()
            (EVIDENCE / 'head-version.txt').write_text(compose('exec', '-T', 'cli', HEAD_BINARY, 'version', capture=True).stdout)
            if BASELINE_READY:
                actual = compose('exec', '-T', 'server', SERVER_PYTHON, '-c',
                    'import aweb,importlib.metadata; print(aweb.__file__); print(importlib.metadata.version("aweb")); assert aweb.__file__.startswith("/work/baseline-package/")', capture=True).stdout
                (EVIDENCE / 'baseline-runtime.txt').write_text(actual)
            if CANDIDATE_BIN:
                version = compose('exec', '-T', 'cli', '/work/candidate-aw', 'version', capture=True).stdout
                assert os.environ['USER_PATHS_CANDIDATE_SHA'] in version, version
                (EVIDENCE / 'candidate-version.txt').write_text(version)
        lane_failures = []
        selected_lanes = [('head', HEAD_BINARY)] if BASELINE_READY else [('head', HEAD_BINARY), ('released', provenance['binary'])]
        if CANDIDATE_BIN:
            selected_lanes = [('forward', '/work/candidate-aw'), ('reverse', '/work/candidate-aw')]
        for lane, binary in selected_lanes:
            with phase(lane):
                comparison_args = ['-e', 'USER_PATHS_COMPARISON_BIN=/work/comparison/aw'] if (WORK / 'comparison/aw').exists() else []
                try:
                    baseline_args = ['--baseline-chat-only'] if BASELINE_READY else []
                    if CANDIDATE_BIN:
                        baseline_args = ['--local-chat-direction', lane]
                    compose('exec', '-T', '-e', f'AW_BIN={binary}', *comparison_args, 'cli', 'python3', '/work/user_paths.py', '--lane', lane, *baseline_args)
                except subprocess.CalledProcessError:
                    lane_failures.append(lane)
        status = 1 if lane_failures else 0
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup_errors = []
        def cleanup_action(description, action):
            try:
                action()
            except Exception as error:
                cleanup_errors.append(description + ': ' + str(error))
        with phase('cleanup'):
            # A timed-out docker client does not stop its container automatically.
            cleanup_action('artifact container', lambda: subprocess.run(['docker', 'rm', '-f', PROJECT + '-fetch'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15))
            # Retain actual source, artifact identity, named case output and timings.
            for lane in ['head', 'released', 'forward', 'reverse']:
                if (WORK / lane).exists():
                    cleanup_action(lane + ' evidence', lambda: shutil.copytree(WORK / lane, EVIDENCE / lane, dirs_exist_ok=True,
                                    ignore=shutil.ignore_patterns('home', 'g1', 'g2', 't1', 't2', 'remote', 'nonresident')))
            cleanup_action('logs', lambda: (EVIDENCE / 'services.log').write_text(compose('logs', '--no-color', capture=True, timeout=15).stdout))
            cleanup_action('compose down', lambda: compose('down', '-v', '--remove-orphans', timeout=45))
            for resource, command in [('container', ['ps', '-aq']), ('network', ['network', 'ls', '-q']), ('volume', ['volume', 'ls', '-q'])]:
                def check_absent():
                    remaining = run('docker', *command, '--filter', 'label=com.docker.compose.project=' + PROJECT, capture=True, timeout=10).stdout.strip()
                    if remaining:
                        raise RuntimeError(f'owned {resource} remains: {remaining}')
                cleanup_action(resource + ' absence', check_absent)
            cleanup_action('scratch homes', lambda: shutil.rmtree(WORK))
        TIMINGS['total'] = round(time.monotonic() - START, 3)
        (EVIDENCE / 'timings.json').write_text(json.dumps(TIMINGS, indent=2) + '\n')
        # Human coverage remains visibly incomplete. Only the runnable matrix
        # and exact reviewed released-client budget control stage admission.
        lanes = {lane: json.loads((EVIDENCE / lane / 'results.json').read_text())
                 for lane in ['head', 'released'] if (EVIDENCE / lane / 'results.json').exists()}
        result = qualification(lanes, TIMINGS['total'], cleanup_errors)
        (EVIDENCE / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
        print('user-paths ' + result['status'] + '; ' + result['coverage_summary'], flush=True)
        if cleanup_errors:
            raise RuntimeError('; '.join(cleanup_errors))
    assert status == 0 and TIMINGS['total'] < 600, TIMINGS
    if CANDIDATE_BIN:
        return  # Named component proof only; the standing matrix is not qualified.
    assert result['status'] == 'PASSED', result


if __name__ == '__main__':
    main()

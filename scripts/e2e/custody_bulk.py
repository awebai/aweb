#!/usr/bin/env python3
"""Run the real 300-message custody regression using local candidate images.

Requires local aweb/AWID service images, Python, CoreDNS, Postgres and Redis,
and an exact Linux aw binary for the client's CPU.
No builds, pulls, registry fetch, published ports or production identity are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-image', default='server-aweb:latest')
    parser.add_argument('--awid-image', default='server-awid:latest')
    parser.add_argument('--client-image', default='python:3.12-slim')
    parser.add_argument('--dns-image', default='coredns/coredns:1.12.0')
    parser.add_argument('--aw-bin', type=Path, required=True)
    parser.add_argument('--provision-aw-bin', type=Path,
                        help='Optional current CLI for provisioning when measuring an older release')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--cases', default='', help='Comma-separated diagnostic selection; default runs every case')
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    project = 'aweb-custody-bulk-' + uuid.uuid4().hex[:12]
    work = Path(tempfile.mkdtemp(prefix=project + '-'))
    config_path = work / 'compose.json'
    started = time.monotonic()

    def run(*command, **options):
        return subprocess.run(command, check=True, text=True, timeout=options.pop('timeout', 120), **options)

    def compose(*command, **options):
        return run('docker', 'compose', '-p', project, '-f', str(config_path), *command, **options)

    try:
        images = {}
        for name, ref in [('server', args.server_image), ('awid', args.awid_image), ('client', args.client_image),
                          ('dns', args.dns_image), ('postgres', 'postgres:17'), ('redis', 'redis:7')]:
            images[name] = json.loads(run('docker', 'image', 'inspect', ref, capture_output=True).stdout)[0]['Id']
        (evidence / 'inputs.json').write_text(json.dumps(dict(
            source=run('git', '-C', str(REPO), 'rev-parse', 'HEAD', capture_output=True).stdout.strip(),
            binary_sha256=hashlib.sha256(args.aw_bin.read_bytes()).hexdigest(),
            harness_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in (REPO / 'scripts/e2e').glob('custody_bulk*.py')},
            images=images, client_uid=os.getuid(), client_gid=os.getgid()), indent=2))
        for filename in ('custody_bulk_client.py', 'custody_bulk_relay.py'):
            shutil.copy2(REPO / 'scripts/e2e' / filename, work / filename)
        shutil.copy2(args.aw_bin.resolve(), work / 'aw')
        shutil.copy2((args.provision_aw_bin or args.aw_bin).resolve(), work / 'provision-aw')
        (work / 'aw').chmod(0o755)
        (work / 'provision-aw').chmod(0o755)
        (work / 'dns').mkdir()
        (work / 'dns/Corefile').write_text('test:53 {\n file /zones/test.zone { reload 1s }\n}\n.:53 {\n forward . 127.0.0.11\n}\n')
        (work / 'dns/test.zone').write_text('$ORIGIN test.\n$TTL 1\n@ IN SOA ns.test. hostmaster.test. (1 1 1 1 1)\n@ IN NS ns.test.\nns IN A 127.0.0.1\n')
        (work / 'init.sql').write_text('CREATE EXTENSION pgcrypto WITH SCHEMA public;\n')
        (work / 'control.json').write_text('{"case":"startup"}')
        user = f'{os.getuid()}:{os.getgid()}'
        source = [f'{REPO}:/source:ro']
        service_environment = dict(APP_ENV='development', PYTHONPATH='/source/server/src:/source/awid/src:/source/naapp-lib/src',
                                   AWID_REGISTRY_URL='http://awid:8010', AWID_SERVICE_TOKEN='disposable-custody-bulk-service-token')

        def configuration(dns=None):
            services = {
                'postgres': dict(image=images['postgres'], environment=dict(POSTGRES_USER='aweb', POSTGRES_PASSWORD='disposable', POSTGRES_DB='aweb'),
                                 tmpfs=['/var/lib/postgresql/data'], volumes=[f'{work}/init.sql:/docker-entrypoint-initdb.d/init.sql:ro'],
                                 healthcheck=dict(test=['CMD-SHELL', 'pg_isready -U aweb -d aweb'], interval='1s', timeout='2s', retries=30)),
                'redis': dict(image=images['redis']),
                'dns': dict(image=images['dns'], command=['-conf', '/zones/Corefile'], volumes=[f'{work}/dns:/zones:ro']),
                'awid': dict(image=images['awid'], entrypoint=['awid', '--host', '0.0.0.0', '--port', '8010'],
                             volumes=source, environment=dict(service_environment, AWID_DATABASE_URL='postgresql://aweb:disposable@postgres:5432/aweb',
                             AWID_REDIS_URL='redis://redis:6379/0', AWID_DB_SCHEMA='awid', AWID_PUBLIC_ORIGINS='http://awid:8010',
                             AWID_ALLOW_INSECURE_DELIVERY_ORIGIN='1', AWID_RATE_LIMIT_DISABLED='true')),
                'server': dict(image=images['server'], entrypoint=['aweb', 'serve', '--host', '0.0.0.0', '--port', '8000'],
                               volumes=source, environment=dict(service_environment, AWEB_DATABASE_URL='postgresql://aweb:disposable@postgres:5432/aweb',
                               AWEB_REDIS_URL='redis://redis:6379/1', AWEB_FEDERATION_TEST='1', AWEB_PUBLIC_ORIGIN='http://front:8000')),
                'front': dict(image=images['client'], entrypoint=['python3', '/work/custody_bulk_relay.py'], user=user, volumes=[f'{work}:/work']),
                'cli': dict(image=images['client'], entrypoint=['sleep', 'infinity'], user=user, volumes=[f'{work}:/work', 'identities:/identities']),
            }
            for name, service in services.items():
                service.update(cpus=1, mem_limit='1g', pids_limit=128)
                if dns and name in ('server', 'awid', 'cli'):
                    service['dns'] = [dns]
            return dict(services=services, networks={'default': {'internal': True}}, volumes={'identities': {}})

        config_path.write_text(json.dumps(configuration()))
        compose('up', '--pull', 'never', '-d', 'dns', 'postgres', 'redis')
        dns_container = compose('ps', '-q', 'dns', capture_output=True).stdout.strip()
        dns = run('docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', dns_container, capture_output=True).stdout.strip()
        config_path.write_text(json.dumps(configuration(dns)))
        compose('up', '--pull', 'never', '-d', '--wait', 'postgres')
        compose('up', '--pull', 'never', '-d', 'awid', 'server', 'front', 'cli')
        compose('run', '--rm', '--no-deps', '--pull', 'never', '--user', '0:0', '--entrypoint', 'chown', 'cli', user, '/identities')
        compose('exec', '-T', 'cli', 'python3', '-c', '''
import time,urllib.request
for url in ['http://awid:8010/health','http://front:8000/health']:
 end=time.monotonic()+60
 while True:
  try:
   assert urllib.request.urlopen(url,timeout=1).status==200;break
  except OSError:
   assert time.monotonic()<end,url;time.sleep(.1)
''')
        (evidence / 'version.txt').write_text(compose('exec', '-T', 'cli', '/work/aw', 'version', capture_output=True).stdout)
        compose('exec', '-T', '-e', 'CUSTODY_BULK_CASES=' + args.cases, 'cli', 'python3', '/work/custody_bulk_client.py', timeout=300)
    finally:
        cleanup_errors = []

        def cleanup(label, action):
            try:
                action()
            except Exception as error:
                cleanup_errors.append(label + ': ' + str(error))

        if config_path.exists():
            for path in work.glob('*.json*'):
                if path.name not in ('compose.json', 'control.json'):
                    shutil.copy2(path, evidence / path.name)
            cleanup('logs', lambda: (evidence / 'services.log').write_text(compose('logs', '--no-color', capture_output=True).stdout))
            cleanup('compose down', lambda: compose('down', '-v', '--remove-orphans', timeout=60))
            for command in [('ps', '-aq'), ('network', 'ls', '-q'), ('volume', 'ls', '-q')]:
                def absent(command=command):
                    remaining = run('docker', *command, '--filter', 'label=com.docker.compose.project=' + project, capture_output=True).stdout.strip()
                    assert not remaining, remaining
                cleanup(str(command), absent)
        cleanup('scratch', lambda: shutil.rmtree(work))
        (evidence / 'cleanup.json').write_text(json.dumps(dict(project=project, errors=cleanup_errors,
                                                             resources_absent=not cleanup_errors, seconds=time.monotonic()-started)))
        if cleanup_errors:
            raise RuntimeError('owned cleanup failed: ' + '; '.join(cleanup_errors))


if __name__ == '__main__':
    main()

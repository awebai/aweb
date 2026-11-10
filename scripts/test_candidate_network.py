#!/usr/bin/env python3
"""Candidate service routes, with an opt-in real Compose collision control."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('candidate_network', ROOT / 'scripts/candidate-network.py')
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


def bash(source, **env):
    return subprocess.run(['bash', '-eu', '-c', source], cwd=ROOT,
                          env={**os.environ, **env}, text=True, capture_output=True)


class EndpointTests(unittest.TestCase):
    def test_every_shell_journey_selects_scoped_container_endpoints(self):
        # Evaluate the actual endpoint assignments, not duplicate mappings.
        paths = ['scripts/e2e-oss-user-journey.sh', 'scripts/e2e-a2a-gateway-docker.sh',
                 'scripts/e2e-oss-federation.sh', 'scripts/e2e-library-stack.sh',
                 'scripts/e2e-cross-registry-messaging.sh', 'cli/scripts/e2e.sh']
        for path in paths:
            source = (ROOT / path).read_text()
            assignments = [line for line in source.splitlines()
                           if '_URL="$(journey_url ' in line]
            self.assertTrue(assignments, path)
            for assignment in assignments:
                variable = assignment.split('=', 1)[0]
                result = bash('source scripts/journey-network.sh\n'
                              'PROJECT=proof; DOCKER_PUBLISHED_HOST=aweb-docker.test; '
                              'PUBLISHED_HOST=aweb-docker.test; '
                              'AWID_PORT=49151; AWEB_PORT=49152; LIBRARY_PORT=49153; '
                              'ALPHA_PORT=49154; BETA_PORT=49155; GATEWAY_PORT=49156; '
                              'AWID_A_PORT=49157; AWID_B_PORT=49158; '
                              'AWEB_A_PORT=49159; AWEB_B_PORT=49160\n'
                              + assignment + f'\nprintf "%s" "${variable}"',
                              CANDIDATE_RUNNER_NAME='probe')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertRegex(result.stdout, r'^http://proof-[a-z-]+\.test:(8000|8010|8080|8765)$')
        # Host invocation is a supported neighboring path, not a gate route.
        result = bash('source scripts/journey-network.sh; journey_url proof awid 8010 http://127.0.0.1:49151',
                      CANDIDATE_RUNNER_NAME='')
        self.assertEqual(result.stdout.strip(), 'http://127.0.0.1:49151')

    def test_channel_does_not_reserve_ports_and_selects_both_service_names(self):
        source = (ROOT / 'channel/test/integration.test.ts').read_text()
        allocation = source[source.index('  const directNetwork ='):source.index('  const projectSeed =')]
        endpoints = source[source.index('  const publishedHost ='):source.index('  await writeFile(envFilePath,')]
        program = ('const projectName="proof"; '
                   'function dockerPublishedHost(){return "aweb-docker.test";} '
                   'function reserveLoopbackPorts(){throw Error("unexpected host allocation");}\n'
                   + allocation + endpoints + '\nconsole.log(JSON.stringify([awebURL,awidURL]));')
        result = subprocess.run(['node', '--input-type=module', '-e', program],
                                env={**os.environ, 'CANDIDATE_RUNNER_NAME': 'probe'},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         ['http://proof-aweb.test:8000', 'http://proof-awid.test:8010'])

    def test_naapp_database_and_registry_endpoints_are_direct(self):
        for package in ('folio', 'library'):
            path = ROOT / 'naapp' / package / 'tests/test_e2e_smoke.py'
            tree = ast.parse(path.read_text())
            definitions = [node for node in tree.body
                           if isinstance(node, (ast.ClassDef, ast.FunctionDef))
                           and node.name in ('E2EStack', 'e2e_stack')]
            namespace = {}
            exec('from __future__ import annotations\nfrom dataclasses import dataclass\n'
                 + '\n'.join(ast.unparse(node) for node in definitions), namespace)
            stack = namespace['e2e_stack']({'NAAPP_E2E_PROJECT': 'proof',
                                           'NAAPP_E2E_CONTAINER_NETWORK': '1',
                                           'NAAPP_E2E_HOST': 'aweb-docker.test'})
            self.assertEqual(stack.awid_url, 'http://proof-awid.test:8010')
            self.assertIn('proof-postgres.test:5432', stack.postgres_url)

    def test_gate_does_not_allocate_or_use_host_ports(self):
        source = (ROOT / 'scripts/candidate-docker-gate.sh').read_text()
        for forbidden in ('candidate-ports.py', 'ports.env', 'host-gateway',
                          'AWEB_DOCKER_PUBLISHED_HOST='):
            self.assertNotIn(forbidden, source)
        journey = (ROOT / 'scripts/e2e-oss-user-journey.sh').read_text()
        functions = journey[journey.index('allocate_service_ports() {'):journey.index('compose() {')]
        result = bash(functions + '\n'
                      'docker() { echo "unexpected host allocation" >&2; return 99; }; '
                      'AWEB_PORT=; AWID_PORT=; PORT_ALLOCATOR=; '
                      'allocate_service_ports; release_service_ports; '
                      'printf "%s %s" "$AWEB_PORT" "$AWID_PORT"',
                      CANDIDATE_RUNNER_NAME='probe')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '8000 8010')

    def test_transport_failure_names_service_address_path_and_real_error(self):
        with socket.socket() as held:
            held.bind(('127.0.0.1', 0))  # reserved but deliberately not listening
            address = f'http://127.0.0.1:{held.getsockname()[1]}'
            result = bash('source scripts/journey-network.sh; '
                          f'journey_wait_health awid {address} 1', CANDIDATE_RUNNER_NAME='probe')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'service=awid address={address}/health path=compose-network', result.stderr)
        self.assertIn('curl:', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_network_override_preserves_other_aliases_and_removes_every_publish(self):
        config = {'name': 'proof', 'services': {
            'awid': {'ports': [{'target': 8010, 'published': '12345'}],
                     'networks': {'default': {'aliases': ['registry-a.test']}}},
            'postgres': {'networks': {'data': None}}}}
        rendered = network.override(config)
        self.assertEqual(rendered.count('ports: !reset []'), 2)
        self.assertIn('proof-awid.test', rendered)
        self.assertIn('proof-postgres.test', rendered)
        self.assertIn('"data":', rendered)
        # An overlay appends aliases. It must not reset federation TLS names.
        self.assertNotIn('aliases: !', rendered)
        self.assertEqual(config['services']['awid']['networks']['default']['aliases'], ['registry-a.test'])
        with self.assertRaisesRegex(ValueError, 'Compose network'):
            network.override({'name': 'proof', 'services': {'awid': {'network_mode': 'host'}}})


class ComposeConfigTests(unittest.TestCase):
    def test_compose_failure_preserves_diagnostic_and_cleans_overlays(self):
        # Actual Compose CLI refusal, before any daemon call. Exercise both the
        # network and resource-only wrapper paths, including a quoted temp path.
        real = os.environ.get('AWEB_CANDIDATE_REAL_DOCKER') or shutil.which('docker')
        self.assertIsNotNone(real)
        with tempfile.TemporaryDirectory(prefix="compose error's ") as tmp:
            root = Path(tmp)
            compose_file = root / 'compose.json'
            compose_file.write_text(json.dumps({'services': {'awid': {'image': 'busybox'}}}))
            args = ['compose', '-p', 'proof', '-f', str(compose_file),
                    'config', '--format', 'invalid-format']
            direct = subprocess.run([real, *args], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(direct.returncode, 0, direct.stdout)
            for runner in ('', 'proof-runner'):
                with self.subTest(runner=runner):
                    env = {**os.environ, 'AWEB_CANDIDATE_REAL_DOCKER': real,
                           'AWEB_CANDIDATE_RESOURCE_LABEL': 'proof',
                           'CANDIDATE_RUNNER_NAME': runner, 'CANDIDATE_RESOURCE_MANIFEST': '',
                           'TMPDIR': tmp}
                    wrapped = subprocess.run(['bash', str(ROOT / 'candidate-gate/bin/docker'), *args],
                                             env=env, capture_output=True, text=True, timeout=30)
                    self.assertEqual(wrapped.returncode, direct.returncode, wrapped.stderr)
                    self.assertEqual(wrapped.stderr, direct.stderr)
                    self.assertEqual(list(root.glob('aweb-candidate-compose-*')), [])

    def test_existing_shared_namespace_fixtures_survive_the_network_overlay(self):
        # Real Compose config merges only: no daemon, builds or containers.
        docker = os.environ.get('AWEB_CANDIDATE_REAL_DOCKER') or shutil.which('docker')
        self.assertIsNotNone(docker, 'Docker Compose CLI is required for fixture validation')
        env = {**os.environ, 'FOLIO_WAKES_ORIGIN': 'https://folio-wakes.test:8765',
               'FOLIO_WAKES_APP_KEY_FILES': '{}', 'GRANT_APP_E2E_PROJECT': 'proof'}
        fixtures = [(['scripts/e2e/folio-wakes.compose.yml'], {'folio', 'client'}),
                    (['docker-compose.e2e.yml', 'scripts/e2e/grant-app-acceptance.compose.yml'], {'client'})]
        for files, expected_shared in fixtures:
            with self.subTest(files=files), tempfile.TemporaryDirectory() as tmp:
                args = [docker, 'compose', '-p', 'proof', '--project-directory', str(ROOT)]
                for file in files:
                    args += ['-f', str(ROOT / file)]

                def config(extra=()):
                    result = subprocess.run([*args, *extra, 'config', '--format', 'json'],
                                            env=env, text=True, capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    return json.loads(result.stdout)

                original = config()
                shared = {name for name, service in original['services'].items()
                          if service.get('network_mode') == 'service:aweb'}
                self.assertEqual(shared, expected_shared)
                overlay = Path(tmp) / 'network.yml'
                overlay.write_text(network.override(original))
                merged = config(['-f', str(overlay)])
                for name, service in merged['services'].items():
                    self.assertFalse(service.get('ports'), name)
                    if name in shared:
                        self.assertEqual(service['network_mode'], 'service:aweb')
                        self.assertNotIn('networks', service)
                    else:
                        self.assertIn(f'proof-{name}.test', service['networks']['default']['aliases'])
                # Preserve the fixture's actual signed loopback audience.
                self.assertEqual(merged['services']['aweb']['environment']['AWEB_PUBLIC_ORIGIN'],
                                 original['services']['aweb']['environment']['AWEB_PUBLIC_ORIGIN'])


@unittest.skipUnless(os.environ.get('AWEB_TEST_DOCKER_NETWORK') == '1', 'requires an approved Docker slot')
class ComposeExitStatusTests(unittest.TestCase):
    def test_real_exec_status_and_failed_up_on_both_wrapper_paths(self):
        real = os.environ.get('AWEB_CANDIDATE_REAL_DOCKER') or shutil.which('docker')
        label = 'acwx-status-' + uuid.uuid4().hex[:12]
        runner = label + '-runner'
        projects = [label + suffix for suffix in ('-exec', '-up-network', '-up-host')]

        def docker(*args, check=True):
            return subprocess.run([real, *args], check=check, capture_output=True,
                                  text=True, timeout=90)

        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / 'compose.json'
            compose.write_text(json.dumps({'services': {'worker': {
                'image': 'python:3.12-slim', 'command': ['sleep', '600'],
                'labels': {'aweb.candidate-gate': label},
                'cpus': .25, 'mem_limit': '64m', 'pids_limit': 32}}}))
            env = {**os.environ, 'AWEB_CANDIDATE_REAL_DOCKER': real,
                   'AWEB_CANDIDATE_RESOURCE_LABEL': label,
                   'CANDIDATE_RESOURCE_MANIFEST': '',
                   'AWEB_CANDIDATE_SIBLING_CPUS': '.25',
                   'AWEB_CANDIDATE_SIBLING_MEMORY': '64m',
                   'AWEB_CANDIDATE_SIBLING_PIDS': '32'}

            def wrapped(project, runner_name, *args):
                with tempfile.TemporaryDirectory(dir=tmp, prefix="overlay's ") as overlays:
                    result = subprocess.run(
                        ['bash', str(ROOT / 'candidate-gate/bin/docker'), 'compose',
                         '-p', project, '-f', str(compose), *args],
                        env={**env, 'CANDIDATE_RUNNER_NAME': runner_name, 'TMPDIR': overlays},
                        capture_output=True, text=True, timeout=90)
                    leftovers = list(Path(overlays).glob('aweb-candidate-compose-*'))
                    return result, leftovers

            try:
                docker('run', '-d', '--name', runner, '--label', 'aweb.candidate-gate=' + label,
                       '--cpus', '.25', '--memory', '64m', '--pids-limit', '32',
                       'python:3.12-slim', 'sleep', '600')
                docker('compose', '-p', projects[0], '-f', str(compose), 'up', '-d')
                for runner_name in ('', runner):
                    for status in (0, 2, 17):
                        with self.subTest(operation='exec', runner=runner_name, status=status):
                            result, leftovers = wrapped(
                                projects[0], runner_name, 'exec', '-T', 'worker', 'python', '-c',
                                f'import sys; print("worker-result"); sys.exit({status})')
                            self.assertEqual(result.returncode, status, result.stderr)
                            self.assertEqual(result.stdout.strip(), 'worker-result')
                            self.assertEqual(leftovers, [])
                            self.assertNotIn('unbound variable', result.stderr)
                config = json.loads(compose.read_text())
                config['services']['worker']['command'] = ['python', '-c', 'raise SystemExit(17)']
                compose.write_text(json.dumps(config))
                for project, runner_name in zip(projects[1:], (runner, '')):
                    with self.subTest(operation='up', runner=runner_name, status=17):
                        result, leftovers = wrapped(project, runner_name, 'up',
                                                    '--abort-on-container-exit',
                                                    '--exit-code-from', 'worker')
                        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
                        self.assertEqual(leftovers, [])
                        attached = json.loads(docker('inspect', runner).stdout)[0]['NetworkSettings']['Networks']
                        self.assertNotIn(project + '_default', attached, 'failed up attached the runner')
            finally:
                cleanup_errors = []
                for project in projects:
                    result = docker('compose', '-p', project, '-f', str(compose),
                                    'down', '-v', '--remove-orphans', check=False)
                    if result.returncode:
                        cleanup_errors.append(result.stderr)
                owned = docker('ps', '-aq', '--filter', 'label=aweb.candidate-gate=' + label).stdout.split()
                if owned:
                    docker('rm', '-fv', *owned)
                self.assertEqual(docker('ps', '-aq', '--filter', 'label=aweb.candidate-gate=' + label).stdout.strip(), '')
                for project in projects:
                    self.assertEqual(docker('network', 'ls', '-q', '--filter',
                                            'label=com.docker.compose.project=' + project).stdout.strip(), '')
                self.assertEqual(cleanup_errors, [])
                print(f'status probe cleanup PASSED: label={label}; containers=0; project networks=0')


@unittest.skipUnless(os.environ.get('AWEB_TEST_DOCKER_NETWORK') == '1', 'requires an approved Docker slot')
class ComposeNetworkTests(unittest.TestCase):
    def test_real_services_start_despite_competing_host_port_and_stay_isolated(self):
        real = os.environ.get('AWEB_CANDIDATE_REAL_DOCKER') or shutil.which('docker')
        image = 'python:3.12-slim'
        label = 'acwx-network-' + uuid.uuid4().hex[:12]
        runner, competitor = label + '-runner', label + '-competitor'
        projects = [label + '-a', label + '-b']

        def docker(*args, check=True):
            return subprocess.run([real, *args], check=check, capture_output=True, text=True, timeout=90)

        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, 'AWEB_CANDIDATE_REAL_DOCKER': real,
                   'AWEB_CANDIDATE_RESOURCE_LABEL': label, 'CANDIDATE_RUNNER_NAME': runner,
                   'CANDIDATE_RESOURCE_MANIFEST': str(Path(tmp) / 'resources.tsv'),
                   'AWEB_CANDIDATE_SIBLING_CPUS': '.25',
                   'AWEB_CANDIDATE_SIBLING_MEMORY': '64m',
                   'AWEB_CANDIDATE_SIBLING_PIDS': '32'}
            compose_file = Path(tmp) / 'compose.json'
            commands = []
            try:
                docker('run', '-d', '--name', runner, '--label', 'aweb.candidate-gate=' + label,
                       '--cpus', '.25', '--memory', '64m', '--pids-limit', '32',
                       image, 'sleep', '600')
                docker('run', '-d', '--name', competitor, '--label', 'aweb.candidate-gate=' + label,
                       '--cpus', '.25', '--memory', '64m', '--pids-limit', '32',
                       '-p', '127.0.0.1::8010', image, 'sleep', '600')
                port = json.loads(docker('inspect', competitor).stdout)[0]['NetworkSettings']['Ports']['8010/tcp'][0]['HostPort']
                server = ('import http.server,os; '
                          'handler=type("Handler",(http.server.BaseHTTPRequestHandler,),'
                          '{"do_GET":lambda s:(s.send_response(200),s.end_headers(),'
                          's.wfile.write(os.environ["MARKER"].encode()))}); '
                          'http.server.HTTPServer(("0.0.0.0",8010),handler).serve_forever()')
                compose_file.write_text(json.dumps({'services': {'awid': {
                    'image': image, 'command': ['python', '-c', server],
                    'environment': {'MARKER': '${COMPOSE_PROJECT_NAME}'},
                    'ports': [f'127.0.0.1:{port}:8010'],
                    'networks': {'default': {'aliases': ['registry.test']}}}}}))
                fetch = ('import urllib.request,time,sys; '
                         'opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));\n'
                         'for attempt in range(50):\n'
                         ' try:\n'
                         '  print(opener.open(sys.argv[1],timeout=1).read().decode()); break\n'
                         ' except OSError:\n'
                         '  if attempt == 49: raise\n'
                         '  time.sleep(.1)\n')
                for project in projects:
                    cmd = ['bash', str(ROOT / 'candidate-gate/bin/docker'), 'compose',
                           '-p', project, '-f', str(compose_file)]
                    commands.append(cmd)
                    result = subprocess.run([*cmd, 'up', '-d'], env=env, capture_output=True, text=True, timeout=90)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    container = docker('ps', '-q', '--filter', 'label=com.docker.compose.project=' + project,
                                       '--filter', 'label=com.docker.compose.service=awid').stdout.strip()
                    info = json.loads(docker('inspect', container).stdout)[0]
                    self.assertFalse(info['HostConfig'].get('PortBindings'), info['HostConfig'])
                    url = f'http://{project}-awid.test:8010'
                    self.assertEqual(docker('exec', runner, 'python', '-c', fetch, url).stdout.strip(), project)
                    # Temporary Docker clients take the same direct route.
                    self.assertEqual(docker('run', '--rm', '--network', project + '_default',
                                            '--label', 'aweb.candidate-gate=' + label,
                                            '--cpus', '.25', '--memory', '64m', '--pids-limit', '32',
                                            image, 'python', '-c', fetch, url).stdout.strip(), project)
                outsider = docker('exec', projects[1] + '-awid-1', 'python', '-c',
                                  'import socket; socket.getaddrinfo(__import__("sys").argv[1],8010)',
                                  projects[0] + '-awid.test', check=False)
                self.assertNotEqual(outsider.returncode, 0, 'other journey unexpectedly resolved private service')
                self.assertIn('gaierror', outsider.stderr)
                self.assertTrue(json.loads(docker('inspect', competitor).stdout)[0]['State']['Running'])
            finally:
                cleanup_errors = []
                for cmd in reversed(commands):
                    result = subprocess.run([*cmd, 'down', '-v', '--remove-orphans'], env=env,
                                            capture_output=True, text=True, timeout=60)
                    if result.returncode:
                        cleanup_errors.append(result.stderr)
                owned = docker('ps', '-aq', '--filter', 'label=aweb.candidate-gate=' + label).stdout.split()
                if owned:
                    docker('rm', '-fv', *owned)
                for project in projects:
                    networks = docker('network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project).stdout.split()
                    if networks:
                        docker('network', 'rm', *networks)
                self.assertEqual(docker('ps', '-aq', '--filter', 'label=aweb.candidate-gate=' + label).stdout.strip(), '')
                for project in projects:
                    self.assertEqual(docker('network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project).stdout.strip(), '')
                self.assertEqual(cleanup_errors, [], 'Compose teardown failed before final labelled cleanup')
                print(f'network probe cleanup PASSED: label={label}; containers=0; project networks=0')



if __name__ == '__main__':
    unittest.main()

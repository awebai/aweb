#!/usr/bin/env python3
"""Opt-in native-Linux probes of the actual cross-registry CLI fixture.

Build scripts/federation-cli.Dockerfile at this checkout first, then set
AWEB_TEST_FEDERATION_CLI_IMAGE and AWEB_TEST_DOCKER_BIND_OWNERSHIP=1.
No registry/service stack is needed: controller preparation and human preparation
are local operations. Never print generated keys or human records.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=90, **kwargs)


def image_identity(inspect_json):
    info, = json.loads(inspect_json)
    configured_user = info['Config'].get('User') or ''
    return {'image_id': info['Id'], 'configured_user': configured_user,
            'effective_user': configured_user or '0'}


def inspect_image(real, image):
    inspected = run(real, 'image', 'inspect', image)
    assert inspected.returncode == 0, inspected.stderr
    return image_identity(inspected.stdout)


class ImageInspectTests(unittest.TestCase):
    def test_omitted_and_empty_user_mean_root_but_explicit_user_is_preserved(self):
        for config, expected in (({}, '0'), ({'User': ''}, '0'),
                                 ({'User': '1000:1000'}, '1000:1000')):
            with self.subTest(config=config):
                result = image_identity(json.dumps([{'Id': 'sha256:probe', 'Config': config}]))
                self.assertEqual(result['effective_user'], expected)
                self.assertEqual(result['image_id'], 'sha256:probe')


@contextmanager
def fixture():
    real = os.environ.get('AWEB_CANDIDATE_REAL_DOCKER') or shutil.which('docker')
    image = os.environ['AWEB_TEST_FEDERATION_CLI_IMAGE']
    assert platform.system() == 'Linux' and os.getuid() != 0, 'requires native Linux and a nonroot caller'
    print('CLI image user/id: ' + json.dumps(inspect_image(real, image)), flush=True)
    project = 'acwx-bind-' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix='aweb-candidate-work.',
                                     dir=os.environ.get('AWEB_DOCKER_BIND_ROOT')) as tmp:
        root = Path(tmp)
        bind = root / 'docker-bind'
        bind.mkdir()
        shim = root / 'shim'
        shim.mkdir()
        capture = root / 'captured.yml'
        adapter = shim / 'docker'
        # Run the real script through config generation, stopping at its first
        # Docker calls. KEEP leaves the generated fixture available for the probe.
        adapter.write_text('''#!/usr/bin/env python3
import os,shutil,sys
assert sys.argv[1] == 'compose', sys.argv
shutil.copyfile(sys.argv[sys.argv.index('-f')+1], os.environ['CAPTURE_COMPOSE'])
raise SystemExit(89)
''')
        adapter.chmod(0o755)
        env = {**os.environ, 'PATH': str(shim) + os.pathsep + os.environ['PATH'],
               'CAPTURE_COMPOSE': str(capture), 'AWEB_DOCKER_BIND_ROOT': str(bind),
               'AWEB_CROSS_REGISTRY_KEEP': '1', 'AWEB_CROSS_REGISTRY_PROJECT': 'aweb-cross-reg-' + project}
        generated = run('bash', str(ROOT / 'scripts/e2e-cross-registry-messaging.sh'), env=env)
        assert generated.returncode == 89, generated.stdout + generated.stderr
        parsed = run(real, 'compose', '-f', str(capture), 'config', '--format', 'json')
        assert parsed.returncode == 0, parsed.stderr
        cli = json.loads(parsed.stdout)['services']['cli']
        cli.pop('build', None)
        cli['image'] = image
        cli['labels'] = {'aweb.candidate-gate': project}
        cli.update(cpus=2, mem_limit='4g', pids_limit=1024)
        work = Path(next(v['source'] for v in cli['volumes'] if v['target'] == '/work'))
        config = root / 'probe.json'
        args = [real, 'compose', '-p', project, '-f', str(config)]
        try:
            yield real, image, project, root, work, cli, config, args
        finally:
            if config.exists():
                down = run(*args, 'down', '-v', '--remove-orphans')
                assert down.returncode == 0, down.stderr
            # Remove only this probe's own files as their owner, even after RED.
            # This is fallback test cleanup, never the property under test.
            if root.exists():
                cleaned = run(real, 'run', '--rm', '--user', '0:0', '--network', 'none',
                              '--label', 'aweb.candidate-gate=' + project,
                              '--cpus', '.5', '--memory', '64m', '--pids-limit', '32',
                              '-v', str(root) + ':/probe', '--entrypoint', 'sh', image,
                              '-c', 'find /probe -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +')
                assert cleaned.returncode == 0, cleaned.stderr
            for command in [('ps', '-aq'), ('network', 'ls', '-q'), ('volume', 'ls', '-q')]:
                result = run(real, *command, '--filter', 'label=com.docker.compose.project=' + project)
                assert result.returncode == 0 and not result.stdout.strip(), result.stderr + result.stdout
            print('probe cleanup PASS: ' + project, flush=True)


def write_config(config, cli):
    config.write_text(json.dumps({'services': {'cli': cli}}))


@unittest.skipUnless(os.environ.get('AWEB_TEST_DOCKER_BIND_OWNERSHIP') == '1', 'requires an approved Linux VM')
class BindOwnershipTests(unittest.TestCase):
    def probe(self, same_user):
        with fixture() as (real, image, project, root, work, cli, config, args):
            if same_user:
                cli['user'] = f'{os.getuid()}:{os.getgid()}'
            write_config(config, cli)
            prepared = run(*args, 'run', '--rm', '--no-deps', 'cli', 'id', 'namespace',
                           'prepare-controller', '--domain', 'ownership.example.com',
                           '--registry', 'http://awid.invalid', '--json')
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            paths = [work, work / 'home', work / 'home/.awid']
            observations = [{'path': str(p.relative_to(root)), 'uid': p.stat().st_uid,
                             'gid': p.stat().st_gid, 'mode': oct(p.stat().st_mode & 0o777)} for p in paths]
            # The real fixture tears Compose down before deleting host files.
            down = run(*args, 'down', '-v', '--remove-orphans')
            self.assertEqual(down.returncode, 0, down.stderr)
            # Match the fixture's rm, then the actual gate fallback cleanup.
            removed = run('rm', '-rf', str(work.parent))
            gate = run('bash', '-c', 'source scripts/candidate-cleanup.sh; cleanup_work',
                       cwd=ROOT, env={**os.environ, 'work': str(root), 'ROOT': str(ROOT)})
            print(json.dumps({'mode': 'same-user-control' if same_user else 'declared-cli-user',
                              'caller': [os.getuid(), os.getgid()], 'cli_user': cli.get('user', 'image-default'),
                              'paths': observations, 'fixture_rm': removed.returncode,
                              'gate_cleanup': gate.returncode, 'fixture_stderr': removed.stderr,
                              'gate_stderr': gate.stderr}), flush=True)
            with self.subTest(boundary='fixture'):
                self.assertEqual(removed.returncode, 0, removed.stderr)
            with self.subTest(boundary='gate'):
                self.assertEqual(gate.returncode, 0, gate.stderr)

    def test_declared_cli_user_leaves_deletable_fixture(self):
        self.probe(False)

    def test_runner_uid_control_leaves_deletable_fixture(self):
        self.probe(True)


KEYRING_PROBE = r'''
import ast,json,os,resource,runpy
from pathlib import Path
path='/usr/local/bin/cross-registry-human-journey.py'
Path.home().mkdir(parents=True,exist_ok=True)
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'home_mode':oct(Path.home().stat().st_mode & 0o777),'memlock':resource.getrlimit(resource.RLIMIT_MEMLOCK),'cap_eff':next(x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:'))}),flush=True)
scope=runpy.run_path(path)
def first_local_step():
    human,prompts=scope['command'](['id','human','init','--domain','alpha.example.com','--json'])
    assert human['status']=='prepared' and prompts==2
    print('actual journey local human preparation PASS',flush=True)
scope['main']=first_local_step
# Execute the fixture's exact unlock/start sequence and its main() call; replace
# only later registry-dependent journey steps with the first failing local step.
startup=ast.parse(Path(path).read_text()).body[-1]
assert isinstance(startup,ast.If) and '__name__' in ast.unparse(startup.test)
exec(compile(ast.Module(body=startup.body,type_ignores=[]),path,'exec'),scope)
'''


@unittest.skipUnless(os.environ.get('AWEB_TEST_DOCKER_BIND_OWNERSHIP') == '1', 'requires an approved Linux VM')
class SecretServiceStartupTests(unittest.TestCase):
    def test_actual_local_journey_step_in_isolated_sessions(self):
        # Independent fresh sessions, not retries: separate ownership and bind
        # semantics while preserving real daemon ordering, IPC_LOCK and CLI code.
        for same_user, bound_home in ((False, True), (True, True), (False, False), (True, False)):
            with self.subTest(same_user=same_user, bound_home=bound_home), fixture() as data:
                real, image, project, root, work, cli, config, args = data
                if same_user:
                    cli['user'] = f'{os.getuid()}:{os.getgid()}'
                if not bound_home:
                    cli['environment']['HOME'] = '/tmp/probe-home'
                cli['entrypoint'] = ['dbus-run-session', '--', 'python3', '-c', KEYRING_PROBE]
                write_config(config, cli)
                result = run(*args, 'run', '--rm', '--no-deps', 'cli')
                print(json.dumps({'same_user': same_user, 'bound_home': bound_home,
                                  'exit': result.returncode, 'stdout': result.stdout,
                                  'stderr': result.stderr}), flush=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

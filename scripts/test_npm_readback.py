#!/usr/bin/env python3
"""Owned HTTP registry: propagation, immutable mismatches, and the aw publisher."""
import base64
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.parse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ('aw-linux-x64', 'aw-linux-arm64', 'aw-darwin-x64', 'aw-darwin-arm64',
            'aw-windows-x64', 'aw-windows-arm64', 'aw')


def load_reader():
    spec = importlib.util.spec_from_file_location('npm_readback', ROOT / 'cli/go/npm/readback.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Registry:
    def __init__(self):
        self.packages = {}
        self.reads = set()
        self.versions = {}
        self.tags = {}
        self.published = []
        self.visible = lambda: True
        self.tags_visible = lambda name: True
        self.status = 200
        self.corrupt = None
        self.corrupt_bytes = False

    @contextmanager
    def serve(self):
        state = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, status, body):
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PUT(self):
                doc = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                name = doc['name']
                data = next(iter(doc['_attachments'].values()))['data']
                state.packages[name] = base64.b64decode(data)
                state.versions[name] = next(iter(doc['versions']))
                state.tags[name] = doc['dist-tags']
                state.published.append((name, state.versions[name], doc['dist-tags']))
                self.answer(201, b'{"ok":true}')

            def do_GET(self):
                path = urllib.parse.unquote(self.path).split('?')[0].strip('/')
                if path.startswith('tarballs/'):
                    name = path[len('tarballs/'):]
                    data = state.packages[name]
                    self.answer(200, data + b'changed' if state.corrupt_bytes else data)
                    return
                version_request = len(path.split('/')) == 3
                name = path.rsplit('/', 1)[0] if version_request else path
                state.reads.add((name, 'version' if version_request else 'tag'))
                if state.status != 200:
                    self.answer(state.status, b'{}')
                    return
                if not state.visible() or name not in state.packages:
                    self.answer(404, b'{}')
                    return
                data = state.packages[name]
                integrity = 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()
                if state.corrupt == name:
                    integrity = 'sha512-' + base64.b64encode(b'wrong').decode()
                doc = {'name': name, 'version': state.versions.get(name, '1.2.3'), 'dist': {
                    'integrity': integrity, 'tarball': state.url + '/tarballs/' + urllib.parse.quote(name, safe='')},
                    'dist-tags': state.tags.get(name, {'next': '1.2.3'}) if state.tags_visible(name) else {'next': '1.2.3-rc.2'}}
                self.answer(200, json.dumps(doc).encode())

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{server.server_port}'
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield self
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class Clock:
    value = 0
    def now(self):
        return self.value
    def sleep(self, seconds):
        self.value += seconds


class ReadbackTests(unittest.TestCase):
    def test_nineteen_minute_visibility_and_per_package_tag_lag(self):
        reader = load_reader()
        with tempfile.TemporaryDirectory() as temp, Registry().serve() as registry:
            clock = Clock()
            artifacts = []
            for package in PACKAGES:
                name = '@awebai/' + package
                path = Path(temp) / (package + '.tgz')
                path.write_bytes(package.encode())
                artifacts.append(reader.Artifact(name, path))
                registry.packages[name] = path.read_bytes()
            registry.visible = lambda: clock.now() >= 19 * 60
            registry.tags_visible = lambda name: clock.now() >= 19 * 60 + 30 * (PACKAGES.index(name.split("/")[-1]) + 1)
            reader.verify(artifacts, '1.2.3', dist_tag='next', registry=registry.url,
                          clock=clock.now, sleep=clock.sleep, backoff_seconds=30)
            self.assertEqual(clock.now(), 19 * 60 + 30 * len(PACKAGES))
            self.assertEqual(registry.reads, {(a.package, kind) for a in artifacts for kind in ('tag', 'version')})

    def test_outage_and_mismatch_never_succeed(self):
        reader = load_reader()
        for fault in ('outage', 'absent', 'integrity', 'bytes', 'stale-tag'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp, Registry().serve() as registry:
                path = Path(temp) / 'p.tgz'
                path.write_bytes(b'exact bytes')
                name = '@awebai/aw'
                registry.packages[name] = path.read_bytes()
                clock = Clock()
                if fault == 'outage': registry.status = 503
                if fault == 'absent': registry.visible = lambda: False
                if fault == 'integrity': registry.corrupt = name
                if fault == 'bytes': registry.corrupt_bytes = True
                if fault == 'stale-tag': registry.tags_visible = lambda name: False
                with self.assertRaisesRegex(reader.ReadbackRefusal, 'permanent' if fault in ('integrity', 'bytes') else 'uncertain'):
                    reader.verify([reader.Artifact(name, path)], '1.2.3', registry=registry.url,
                                  dist_tag='next', deadline_seconds=10, backoff_seconds=5,
                                  clock=clock.now, sleep=clock.sleep)
                self.assertEqual(clock.now(), 0 if fault in ('integrity', 'bytes') else 10)

    def test_bounded_entrypoint_survives_real_old_deadline(self):
        # Actual elapsed time and real HTTP: the old two-minute default fails.
        # The curl adapter only selects our owned endpoint for the old shell
        # implementation, whose registry URL was not configurable.
        with tempfile.TemporaryDirectory() as temp, Registry().serve() as registry:
            root = Path(temp)
            package = '@awebai/lag-fixture'
            staged = root / 'p.tgz'
            staged.write_bytes(b'exact staged bytes')
            registry.packages[package] = staged.read_bytes()
            started = time.monotonic()
            registry.visible = lambda: time.monotonic() - started >= 125
            curl = shutil.which('curl')
            adapter = root / 'curl'
            adapter.write_text('#!/usr/bin/env python3\nimport os,sys\n' +
                f'args=[v.replace("https://registry.npmjs.org", {registry.url!r}) for v in sys.argv[1:]]\n' +
                f'os.execv({curl!r}, [{curl!r}]+args)\n')
            adapter.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'], NPM_CONFIG_REGISTRY=registry.url)
            result = subprocess.run(['bash', str(ROOT / 'scripts/npm-exact-publish.sh'),
                'verify-published-bounded', '--tgz', str(staged), '--package', package,
                '--version', '1.2.3', '--post-action', 'publish'], env=env, capture_output=True, text=True, timeout=170)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_distribution_sync_carries_the_readback_workflow(self):
        # Exercise the real source-sync copy over an existing distribution
        # workflow, the file that used to remain independently maintained.
        workflow = (ROOT / '.github/workflows/aw-release.yml').read_text()
        copy = next(line.strip() for line in workflow.splitlines() if line.strip().startswith('cp -a cli/go/.'))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'cli/go'
            source.mkdir(parents=True)
            shutil.copytree(ROOT / 'cli/go/.github', source / '.github')
            shutil.copytree(ROOT / 'cli/go/npm', source / 'npm', ignore=shutil.ignore_patterns('__pycache__'))
            external = root / 'distribution'
            (external / '.github/workflows').mkdir(parents=True)
            target = external / '.github/workflows/release.yml'
            target.write_text('old release workflow')
            subprocess.run(['bash', '-c', copy], cwd=root,
                           env=dict(os.environ, external=str(external)), check=True)
            self.assertEqual(target.read_bytes(), (source / '.github/workflows/release.yml').read_bytes())
            self.assertIn('run: ./npm/publish.sh', target.read_text())
            self.assertIn('timeout-minutes: 60', target.read_text())
            self.assertEqual((external / 'npm/readback.py').read_bytes(), (source / 'npm/readback.py').read_bytes())

    def test_aw_publisher_reads_all_seven_and_refuses_mismatch(self):
        # Real npm packs and publishes to our disposable HTTP registry. No npm
        # credentials or external registry are used by this test.
        for mismatch in (True, False):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as temp, Registry().serve() as registry:
                root = Path(temp)
                shutil.copytree(ROOT / 'cli/go/npm', root / 'npm', ignore=shutil.ignore_patterns('__pycache__'))
                (root / 'artifacts').mkdir()
                for os_name in ('linux', 'darwin', 'windows'):
                    for arch in ('amd64', 'arm64'):
                        windows = os_name == 'windows'
                        names = ('aw.exe', 'aweb-a2a-gw.exe') if windows else ('aw', 'aweb-a2a-gw')
                        archive = root / 'artifacts' / (f'{os_name}_{arch}.' + ('zip' if windows else 'tar.gz'))
                        if windows:
                            with zipfile.ZipFile(archive, 'w') as handle:
                                for name in names: handle.writestr(name, b'disposable binary')
                        else:
                            with tarfile.open(archive, 'w:gz') as handle:
                                for name in names:
                                    info = tarfile.TarInfo(name); info.size = 17
                                    handle.addfile(info, io.BytesIO(b'disposable binary'))
                bindir = root / 'bin'; bindir.mkdir()
                if shutil.which('gsed'): (bindir / 'sed').symlink_to(shutil.which('gsed'))
                config = root / 'npmrc'
                config.write_text(f'registry={registry.url}\n//127.0.0.1:{urllib.parse.urlparse(registry.url).port}/:_authToken=disposable-fixture\n')
                env = {k: v for k, v in os.environ.items() if not k.startswith(('NPM_', 'npm_', 'NODE_AUTH'))}
                env.update(GITHUB_REF_NAME='v1.2.3', GITHUB_ACTIONS='false', NPM_CONFIG_USERCONFIG=str(config),
                           NPM_CONFIG_CACHE=str(root / 'cache'), NPM_CONFIG_UPDATE_NOTIFIER='true',
                           npm_config_update_notifier='true', CI='false',
                           NPM_CONFIG_REGISTRY=registry.url, PATH=str(bindir) + os.pathsep + env['PATH'])
                if mismatch: registry.corrupt = '@awebai/aw-windows-arm64'
                result = subprocess.run(['bash', str(root / 'npm/publish.sh'), '--staged-final'],
                                        env=env, capture_output=True, text=True, timeout=90)
                if mismatch:
                    self.assertNotEqual(result.returncode, 0, 'publisher went green without checking the registry')
                    self.assertIn('permanent integrity mismatch', result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(registry.reads, {('@awebai/' + p, kind) for p in PACKAGES for kind in ('version', 'tag')})
                self.assertEqual(set(registry.packages), {'@awebai/' + p for p in PACKAGES})


if __name__ == '__main__':
    unittest.main()

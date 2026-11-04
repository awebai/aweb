"""Artifact boundary controls; no npm writes and no install scripts."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest

spec = importlib.util.spec_from_file_location("fetch_aw", Path(__file__).with_name("fetch_released_aw.py"))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


def archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, body in entries.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(body)
            tar.addfile(entry, io.BytesIO(body))
    return out.getvalue()


class ReleasedArtifactTests(unittest.TestCase):
    def test_real_http_fetch_and_failures_never_fall_back(self):
        selected = fetch.platform_package()
        hits = []
        scenario = {'failure': ''}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                hits.append(self.path)
                failure = scenario['failure']
                if failure == 'missing' and selected in self.path:
                    self.send_error(404)
                    return
                name = selected if selected in self.path else 'aw'
                binary = b'#!/bin/sh\necho "aw 1.2.3"\necho "  commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (fixture)"\n'
                if failure == 'output':
                    binary = b'#!/bin/sh\necho "unexpected output"\n'
                if failure == 'stamp':
                    binary = b'#!/bin/sh\necho "aw 1.2.3"\necho "  commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb (fixture)"\n'
                package = {'name': '@awebai/' + name, 'version': '1.2.3'}
                if name == 'aw':
                    package['optionalDependencies'] = {'@awebai/' + selected: '1.2.3' if failure != 'pin' else '9.9.9'}
                archive_name = 'aw.exe' if 'windows' in selected else 'bin/aw'
                body = archive({'package/package.json': json.dumps(package).encode(), 'package/' + archive_name: binary})
                metadata = dict(package, gitHead='a' * 40, dist={
                    'tarball': origin + '/' + name + '.tgz',
                    'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(body).digest()).decode()})
                if failure == 'identity':
                    metadata['name'] = '@awebai/other'
                if failure == 'version' and name != 'aw':
                    metadata['version'] = '1.2.4'
                if failure == 'platform' and name != 'aw':
                    metadata['name'] = '@awebai/aw-unsupported'
                if failure == 'source' and name != 'aw':
                    metadata['gitHead'] = 'b' * 40
                if failure == 'latest-source' and name == 'aw':
                    metadata['gitHead'] = 'b' * 40
                if self.path.endswith('.tgz'):
                    if failure == 'integrity':
                        body += b'changed'
                else:
                    body = json.dumps(metadata).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        origin = f'http://127.0.0.1:{server.server_port}'
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = fetch.fetch(root / 'good', origin)
                self.assertEqual(evidence['platform'], selected)
                self.assertEqual(hits.count('/@awebai%2faw/latest'), 1)
                self.assertTrue((root / 'good/provenance.json').is_file())
                frozen = fetch.latest_metadata(origin)
                hits.clear()
                fetch.fetch(root / 'frozen', origin, metadata=frozen)
                self.assertNotIn('/@awebai%2faw/latest', hits)
                first = fetch.freeze_latest(root / 'snapshots', origin)
                original = first.read_bytes()
                scenario['failure'] = 'latest-source'
                second = fetch.freeze_latest(root / 'snapshots', origin)
                self.assertNotEqual(first, second)
                self.assertEqual(first.read_bytes(), original)
                self.assertEqual(json.loads(second.read_text())['gitHead'], 'b' * 40)
                scenario['failure'] = ''
                self.assertEqual(fetch.freeze_latest(root / 'snapshots', origin), first)
                self.assertEqual(first.read_bytes(), original)
                for failure in ['integrity', 'identity', 'pin', 'missing', 'output', 'version', 'platform', 'source', 'stamp']:
                    scenario['failure'] = failure
                    with self.subTest(failure=failure), self.assertRaises(Exception):
                        fetch.fetch(root / failure, origin)
                    self.assertFalse((root / failure / 'provenance.json').exists())
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(OSError):
            fetch.fetch(Path(directory) / 'network-failure', origin)

    def test_selects_executing_process_platform(self):
        self.assertEqual(fetch.platform_package("linux", "aarch64"), "aw-linux-arm64")
        self.assertEqual(fetch.platform_package("darwin", "arm64"), "aw-darwin-arm64")
        self.assertEqual(fetch.platform_package("win32", "AMD64"), "aw-windows-x64")
        with self.assertRaises(ValueError):
            fetch.platform_package("linux", "riscv64")

    def test_integrity_is_required_and_checked(self):
        body = b"retained exact tarball"
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode()
        fetch.verify_integrity(body, integrity)
        for bad in ("", "sha256-no", integrity[:-4] + "AAAA"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                fetch.verify_integrity(body, bad)
        with self.assertRaises(ValueError):
            fetch.verify_integrity(body + b"changed", integrity)

    def test_packed_name_version_and_platform_pin(self):
        pkg = {"name": "@awebai/aw", "version": "1.2.3", "optionalDependencies": {"@awebai/aw-linux-x64": "1.2.3"}}
        packed = archive({"package/package.json": json.dumps(pkg).encode()})
        self.assertEqual(fetch.package_json(packed, pkg['name'], '1.2.3'), pkg)
        for name, version in (("@awebai/wrong", "1.2.3"), (pkg['name'], "1.2.4")):
            with self.assertRaises(ValueError):
                fetch.package_json(packed, name, version)
        with self.assertRaises(ValueError):
            fetch.validate_platform_pin(pkg, 'aw-darwin-arm64', '1.2.3')

    def test_safe_single_file_read_refuses_traversal_links_duplicates(self):
        for name in ("../escape", "/absolute", "package/../../escape"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                fetch.tar_member(archive({name: b"bad", "package/bin/aw": b"binary"}), "package/bin/aw")
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as tar:
            link = tarfile.TarInfo('package/bin/aw')
            link.type = tarfile.SYMTYPE
            link.linkname = '/etc/passwd'
            tar.addfile(link)
        with self.assertRaises(ValueError):
            fetch.tar_member(out.getvalue(), 'package/bin/aw')
        self.assertEqual(fetch.tar_member(archive({'package/bin/aw': b'actual bytes'}), 'package/bin/aw'), b'actual bytes')


if __name__ == '__main__':
    unittest.main()

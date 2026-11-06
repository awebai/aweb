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
                if failure == 'no-head' or (failure == 'wrapper-no-head' and name == 'aw') \
                        or (failure == 'platform-no-head' and name != 'aw'):
                    del metadata['gitHead']
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

                # A release published without gitHead on every package takes its
                # source commit from the awebai/aw tag; the binary stamp still decides.
                resolved = []
                def tag(commit):
                    def resolve(version):
                        resolved.append(version)
                        return commit
                    return resolve
                scenario['failure'] = ''
                evidence = fetch.fetch(root / 'head-wins', origin, resolve_tag=tag('b' * 40))
                self.assertEqual((resolved, evidence['source']), ([], 'gitHead'), 'a present gitHead is never overridden')
                scenario['failure'] = 'no-head'
                frozen = json.loads(fetch.freeze_latest(root / 'tag-snapshots', origin, resolve_tag=tag('a' * 40)).read_text())
                self.assertEqual((frozen['source'], frozen['sourceCommit']), ('aw-tag', 'a' * 40))
                self.assertNotIn('gitHead', frozen)
                resolved.clear()
                evidence = fetch.fetch(root / 'tag-frozen', origin, metadata=frozen, resolve_tag=tag('b' * 40))
                self.assertEqual(resolved, [], 'frozen metadata carries its resolved source')
                self.assertEqual((evidence['source'], evidence['sourceCommit']), ('aw-tag', 'a' * 40))
                recorded = json.loads((root / 'tag-frozen/provenance.json').read_text())
                self.assertEqual((recorded['source'], recorded['sourceCommit']), ('aw-tag', 'a' * 40))
                evidence = fetch.fetch(root / 'tag-live', origin, resolve_tag=tag('a' * 40))
                self.assertEqual((resolved, evidence['source']), (['1.2.3'], 'aw-tag'))
                def missing(version):
                    raise ValueError('no awebai/aw tag v' + version)
                refusals = [('tag-stamp', 'no-head', tag('b' * 40)), ('tag-missing', 'no-head', missing),
                            ('mixed-wrapper', 'wrapper-no-head', tag('a' * 40)),
                            ('mixed-platform', 'platform-no-head', tag('a' * 40))]
                for case, failure, resolver in refusals:
                    scenario['failure'] = failure
                    with self.subTest(case=case), self.assertRaises(ValueError):
                        fetch.fetch(root / case, origin, resolve_tag=resolver)
                    self.assertFalse((root / case / 'provenance.json').exists())
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(OSError):
            fetch.fetch(Path(directory) / 'network-failure', origin)

    def test_aw_tag_commit_requires_exactly_one_peeled_tag(self):
        ref = 'refs/tags/v1.36.55^{}'
        commit = '59372f4330b4cd8315d9b277a93dbffa0d7accae'
        seen = []
        def listing(output):
            def ls_remote(url, requested):
                seen.append((url, requested))
                return output
            return ls_remote
        self.assertEqual(fetch.aw_tag_commit('1.36.55', ls_remote=listing(f'{commit}\t{ref}\n')), commit)
        self.assertEqual(seen, [('https://github.com/awebai/aw', ref)])
        for output in ('', f'{commit}\t{ref}\n{commit}\t{ref}\n', f'{commit[:12]}\t{ref}\n',
                       f'{commit}\trefs/tags/v1.36.55\n', f'{commit.upper()}\t{ref}\n'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                fetch.aw_tag_commit('1.36.55', ls_remote=listing(output))
        with self.assertRaises(ValueError):
            fetch.aw_tag_commit('1.36.55-rc.1', ls_remote=listing(''))

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

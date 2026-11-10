#!/usr/bin/env python3
"""Real Go/npm restamps preserve tree-based test evidence; no containers."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from fixture_repo import init_fixture_repo
from publish_release import build_aw_npm, aw_ldflags
from release_artifacts import write_manifest
from release_stamp import compare_restamp
from release_versions import VersionRefusal

ROOT = Path(__file__).resolve().parents[1]


class Restamp(unittest.TestCase):
    def test_same_tree_restamps_only_artifacts_and_refuses_changed_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / 'repo'
            root.mkdir()
            project = root / 'cli/go'
            for command in ['aw', 'aweb-a2a-gw']:
                folder = project / 'cmd' / command
                folder.mkdir(parents=True)
                (folder / 'main.go').write_text('package main\nimport "fmt"\nvar version,commit,commitRepo,date string\nfunc main(){fmt.Println(version,commit,commitRepo,date)}\n')
            (project / 'go.mod').write_text('module example.test/stamp\n\ngo 1.26.10\n')
            shutil.copytree(ROOT / 'cli/go/npm', project / 'npm',
                            ignore=shutil.ignore_patterns('node_modules', '*.tgz'))
            init_fixture_repo(root)
            def git(*args, **kwargs):
                return subprocess.check_output(['git', *args], cwd=root, text=True, **kwargs).strip()
            git('add', '.')
            git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'fixture',
                env=dict(os.environ, GIT_AUTHOR_DATE='2026-01-01T00:00:00Z', GIT_COMMITTER_DATE='2026-01-01T00:00:00Z'))
            first = git('rev-parse', 'HEAD')
            environments = dict(CLI_VERSION='9.0.0', CANDIDATE_GATE_KEY='same-tree-key',
                                GOTOOLCHAIN='go1.26.10', CGO_ENABLED='0')
            with patch.dict(os.environ, environments):
                def produce(label):
                    sha = git('rev-parse', 'HEAD')
                    out = base / label
                    out.mkdir()
                    npm = base / (label + '-npm')
                    shutil.copytree(project / 'npm', npm)
                    packages = build_aw_npm(root, '9.0.0', sha, npm)
                    for package in packages:
                        subprocess.run(['npm', 'pack', '--ignore-scripts', '--pack-destination', str(out)],
                                       cwd=npm / package, check=True, capture_output=True)
                    with zipfile.ZipFile(out / 'fixture-1.0.0-py3-none-any.whl', 'w') as archive:
                        archive.writestr(zipfile.ZipInfo('fixture-1.0.0.dist-info/METADATA', (2020, 1, 1, 0, 0, 0)), 'Name: fixture\nVersion: 1.0.0\n')
                    with patch.dict(os.environ, SOURCE_COMMIT=sha):
                        write_manifest(root, out)
                    return out
                left = produce('first')
                git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test', 'commit', '--allow-empty', '-qm', 'restamp',
                    env=dict(os.environ, GIT_AUTHOR_DATE='2026-01-02T00:00:00Z', GIT_COMMITTER_DATE='2026-01-02T00:00:00Z'))
                second = git('rev-parse', 'HEAD')
                self.assertNotEqual(first, second)
                right = produce('second')
                compare_restamp(left, right)
                print('Pinned stamp control: ' + subprocess.check_output(['go', 'version'], text=True).strip())
                sample = next(right.glob('*aw-linux-x64*.tgz'))
                with tarfile.open(sample) as archive:
                    binary = base / 'sample-aw'
                    binary.write_bytes(archive.extractfile('package/bin/aw').read())
                embedded = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
                self.assertNotIn('\tbuild\t-ldflags=', embedded)
                print('Pinned -trimpath observation: embedded build info omits ldflags; producer manifest records them')
                print(embedded)
                document = json.loads((right / 'manifest.json').read_text())
                original = json.dumps(document)
                # A real build-settings change in one executable must refuse,
                # even though the caller updates the archive's valid hash.
                changed = base / 'changed-aw'
                subprocess.run(['go', 'build', '-trimpath', '-tags=unexpected', '-ldflags', aw_ldflags('9.0.0', second),
                                '-o', str(changed), './cmd/aw'], cwd=project, check=True,
                               env=dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0'))
                row = next(row for row in document['files'] if row['package'] == '@awebai/aw-linux-x64')
                archive_path = right / row['path']
                original_archive = archive_path.read_bytes()
                with tarfile.open(fileobj=io.BytesIO(original_archive)) as source, tarfile.open(archive_path, 'w:gz') as destination:
                    for member in source.getmembers():
                        data = source.extractfile(member).read() if member.isfile() else None
                        if member.name == 'package/bin/aw':
                            data = changed.read_bytes()
                            member.size = len(data)
                        destination.addfile(member, io.BytesIO(data) if data is not None else None)
                row['sha256'] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
                (right / 'manifest.json').write_text(json.dumps(document))
                with self.assertRaisesRegex(VersionRefusal, 'CLI code/build settings'):
                    compare_restamp(left, right)
                archive_path.write_bytes(original_archive)
                (right / 'manifest.json').write_text(original)
                document = json.loads(original)
                row = next(row for row in document['files'] if row['package'] == 'fixture')
                wheel = right / row['path']
                wheel.write_bytes(wheel.read_bytes() + b'changed payload')
                row['sha256'] = hashlib.sha256(wheel.read_bytes()).hexdigest()
                (right / 'manifest.json').write_text(json.dumps(document))
                with self.assertRaisesRegex(VersionRefusal, 'non-CLI artifact'):
                    compare_restamp(left, right)


if __name__ == '__main__':
    unittest.main()

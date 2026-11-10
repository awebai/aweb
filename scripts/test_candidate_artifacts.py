#!/usr/bin/env python3
"""Artifact scheduling and retained-byte contract; no containers needed."""
import os
import json
import hashlib
from release_artifacts import verify, build_python, prepare_python, PYTHON_PACKAGES
from fixture_repo import init_fixture_repo
from install_release_wheels import install
from release_versions import VersionRefusal
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ArtifactOrdering(unittest.TestCase):
    def test_artifacts_precede_a_focused_journey(self):
        # Boundary doubles only for scheduling: no claim about product E2E.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for executable in ('make', 'docker'):
                path = root / executable
                path.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n')
                path.chmod(0o755)
            result = subprocess.run(['bash', str(ROOT / 'scripts/candidate-suite.sh'), 'user-paths'],
                env=dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                         CANDIDATE_LOG_DIR=str(root), CALLS=str(root / 'calls'), BUILDX_BUILDER='fixture'),
                text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            stages = [row.split('\t')[0] for row in (root / 'summary.tsv').read_text().splitlines()]
            self.assertEqual(stages, ['artifacts', 'user-paths'],
                             'focused journey bypassed the release artifact prerequisite')


class ManifestBytes(unittest.TestCase):
    def test_changed_or_missing_bytes_refuse_but_retained_bytes_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / 'example.whl'
            artifact.write_bytes(b'the built release bytes')
            row = dict(path=artifact.name, package='example', version='1.0.0',
                       sha256=hashlib.sha256(artifact.read_bytes()).hexdigest())
            (root / 'manifest.json').write_text(json.dumps(dict(files=[row])))
            self.assertEqual(verify(root)['files'], [row])
            artifact.write_bytes(b'rebuilt or corrupted bytes')
            with self.assertRaisesRegex(VersionRefusal, 'sha256 mismatch: example.whl'):
                verify(root)
            artifact.unlink()
            with self.assertRaisesRegex(VersionRefusal, 'sha256 mismatch: example.whl'):
                verify(root)


class BuildOnce(unittest.TestCase):
    def test_all_python_release_files_are_retained_and_reuse_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, relative in PYTHON_PACKAGES.items():
                project = root / relative
                module = name.replace('-', '_')
                (project / 'src' / module).mkdir(parents=True)
                (project / 'src' / module / '__init__.py').write_text('VALUE = 42\n')
                (project / 'pyproject.toml').write_text(
                    f'[project]\nname="{name}"\nversion="9.0.0"\n'
                    '[build-system]\nrequires=["hatchling"]\nbuild-backend="hatchling.build"\n'
                    f'[tool.hatch.build.targets.wheel]\npackages=["src/{module}"]\n')
            init_fixture_repo(root)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True, capture_output=True)
            subprocess.run(['git', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
                            'commit', '-qm', 'new release inputs'], cwd=root, check=True, capture_output=True)
            out = root / 'artifacts'
            prepare_python(root, out)
            manifest = verify(out, root=root)
            self.assertEqual(len(manifest['files']), 2 * len(PYTHON_PACKAGES))
            self.assertEqual({row['package'] for row in manifest['files']}, set(PYTHON_PACKAGES))
            mtimes = {path.name: path.stat().st_mtime_ns for path in out.iterdir()}
            prepare_python(root, out)
            self.assertEqual({path.name: path.stat().st_mtime_ns for path in out.iterdir()}, mtimes,
                             'reused candidate bytes were rebuilt')
            altered = out / manifest['files'][0]['path']
            altered.write_bytes(altered.read_bytes() + b'changed')
            with self.assertRaisesRegex(VersionRefusal, 'sha256 mismatch'):
                prepare_python(root, out)


class ManifestInstallation(unittest.TestCase):
    def test_wheel_replaces_editable_and_tampered_wheel_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / 'project'
            (project / 'src/probe_release').mkdir(parents=True)
            source = project / 'src/probe_release/__init__.py'
            source.write_text('VALUE = 42\n')
            (project / 'pyproject.toml').write_text(
                '[project]\nname="probe-release"\nversion="1.0.0"\n'
                '[build-system]\nrequires=["hatchling"]\nbuild-backend="hatchling.build"\n'
                '[tool.hatch.build.targets.wheel]\npackages=["src/probe_release"]\n')
            artifacts = root / 'artifacts'
            wheel = build_python(project, artifacts)
            row = dict(path=wheel.name, package='probe-release', version='1.0.0',
                       sha256=hashlib.sha256(wheel.read_bytes()).hexdigest())
            (artifacts / 'manifest.json').write_text(json.dumps(dict(files=[row])))
            venv = root / 'venv'
            subprocess.run(['uv', 'venv', str(venv)], check=True, capture_output=True)
            python = venv / 'bin/python'
            source.write_text('VALUE = 99\n')
            subprocess.run(['uv', 'pip', 'install', '--python', str(python), '-e', str(project)],
                           check=True, capture_output=True)
            probe = [str(python), '-I', '-c', 'import probe_release; print(probe_release.VALUE)']
            self.assertEqual(subprocess.check_output(probe, text=True).strip(), '99')
            install(artifacts, python, ['probe-release'])
            self.assertEqual(subprocess.check_output(probe, text=True).strip(), '42')
            wheel.write_bytes(wheel.read_bytes() + b'changed')
            with self.assertRaisesRegex(ValueError, 'sha256 mismatch'):
                install(artifacts, python, ['probe-release'])


if __name__ == '__main__':
    unittest.main()

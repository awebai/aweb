#!/usr/bin/env python3
"""Artifact scheduling and retained-byte contract; no containers needed."""
import os
import json
import hashlib
import shutil
import sys
from release_artifacts import verify, build_python, prepare_python, PYTHON_PACKAGES
from fixture_repo import init_fixture_repo
from install_release_wheels import install
from release_versions import VersionRefusal
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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


class ContextCleanup(unittest.TestCase):
    def test_preparation_removes_each_context_and_preserves_exit_status(self):
        for status in (0, 17):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                commands = root / 'bin'
                commands.mkdir()
                python = commands / 'python3'
                python.write_text('#!' + sys.executable + '\n' +
                    'import os,pathlib,sys,tempfile\n'
                    'if sys.argv[2] == "materialize":\n'
                    ' p=tempfile.mkdtemp(prefix="candidate-wheel-context-",dir=os.environ["CONTEXT_PARENT"])\n'
                    ' with open(os.environ["CONTEXT_RECEIPT"],"a") as f: f.write(p+"\\n")\n'
                    ' print(p)\n')
                python.chmod(0o755)
                artifacts = root / 'retained'
                artifacts.mkdir()
                (artifacts / 'keep').write_text('retained bytes')
                environment = dict(os.environ, PATH=str(commands)+os.pathsep+os.environ['PATH'],
                    CONTEXT_PARENT=str(root), CONTEXT_RECEIPT=str(root / 'contexts'),
                    CANDIDATE_ARTIFACT_DIR=str(artifacts))
                prepared = subprocess.run(['bash', '-c',
                    'set -eu; source "$1"; source "$1"; cp -R "$CANDIDATE_WHEEL_CONTEXT" "$CONTEXT_PARENT/parent-owned"; export CANDIDATE_WHEEL_CONTEXT="$CONTEXT_PARENT/parent-owned"; exit "$2"', '--',
                    str(ROOT / 'scripts/prepare-release-wheels.sh'), str(status)], env=environment,
                    capture_output=True, text=True)
                self.assertEqual(prepared.returncode, status, prepared.stderr)
                contexts = (root / 'contexts').read_text().splitlines()
                self.assertEqual(len(contexts), 2)
                self.assertFalse([path for path in contexts if Path(path).exists()],
                                 'preparation leaked temporary wheel contexts')
                self.assertEqual((artifacts / 'keep').read_text(), 'retained bytes')
                self.assertTrue((root / 'parent-owned').is_dir(), 'child deleted the parent-owned channel context')


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

    def test_cache_refuses_changed_key_and_build_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            init_fixture_repo(root)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
                            'commit', '-qm', 'source'], cwd=root, check=True)
            from release_artifacts import write_manifest
            out = root / 'artifacts'
            out.mkdir()
            # A real wheel, so production manifest metadata extraction runs.
            project = root / 'project'
            (project / 'src/cache_probe').mkdir(parents=True)
            (project / 'src/cache_probe/__init__.py').write_text('VALUE=1\n')
            (project / 'pyproject.toml').write_text(
                '[project]\nname="cache-probe"\nversion="1.0.0"\n'
                '[build-system]\nrequires=["hatchling"]\nbuild-backend="hatchling.build"\n'
                '[tool.hatch.build.targets.wheel]\npackages=["src/cache_probe"]\n')
            build_python(project, out)
            with patch.dict(os.environ, CANDIDATE_GATE_KEY='key-one', CLI_VERSION='1.0.0'):
                write_manifest(root, out)
                verify(out, root=root)
                for key, value in [('CANDIDATE_GATE_KEY', 'key-two'), ('CLI_VERSION', '1.0.1'),
                                   ('SOURCE_COMMIT', 'changed-source')]:
                    with self.subTest(key=key), patch.dict(os.environ, {key: value}):
                        with self.assertRaisesRegex(VersionRefusal, 'build inputs'):
                            verify(out, root=root)

    def test_image_build_requires_opt_in_and_matching_tree(self):
        from install_release_wheels import validate_build_context
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / '.gitignore').write_text('*\n')
            validate_build_context(directory, '0', '')
            (directory / 'manifest.json').write_text(json.dumps(dict(source_tree='a' * 40)))
            with self.assertRaisesRegex(ValueError, 'CANDIDATE_WHEEL_MODE'):
                validate_build_context(directory, '0', '')
            with self.assertRaisesRegex(ValueError, 'source tree'):
                validate_build_context(directory, '1', 'b' * 40)
            with self.assertRaisesRegex(ValueError, 'source tree'):
                validate_build_context(directory, '1', '')
            validate_build_context(directory, '1', 'a' * 40)

    def test_build_wrapper_rechecks_tree_before_invoking_docker(self):
        from release_artifacts import build_inputs
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            docker = directory / 'docker'
            docker.write_text('#!/bin/sh\nprintf "BUILD_INVOKED\\n"\n')
            docker.chmod(0o755)
            payload = directory / 'fixture.whl'
            payload.write_bytes(b'fixture')
            tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip()
            document = dict(source_tree=tree, build_inputs=build_inputs(ROOT),
                files=[dict(path=payload.name, sha256=hashlib.sha256(payload.read_bytes()).hexdigest())])
            manifest = directory / 'manifest.json'
            manifest.write_text(json.dumps(document))
            environment = dict(os.environ, CANDIDATE_ARTIFACT_DIR=str(directory),
                CANDIDATE_CHECKOUT_ROOT=str(ROOT), AWEB_CANDIDATE_RESOURCE_LABEL='',
                AWEB_CANDIDATE_REAL_DOCKER=str(docker))
            command = ['bash', str(ROOT / 'candidate-gate/bin/docker'), 'build', '.']
            good = subprocess.run(command, env=environment, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIn('BUILD_INVOKED', good.stdout)
            document['source_tree'] = 'b' * 40
            manifest.write_text(json.dumps(document))
            bad = subprocess.run(command, env=environment, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertNotIn('BUILD_INVOKED', bad.stdout)
            self.assertIn('different source tree', bad.stderr)


class BuildOnce(unittest.TestCase):
    def test_current_release_wheels_have_no_relocated_data(self):
        import zipfile
        with tempfile.TemporaryDirectory() as temporary:
            for name, relative in PYTHON_PACKAGES.items():
                with self.subTest(package=name):
                    wheel = build_python(ROOT / relative, Path(temporary) / name)
                    with zipfile.ZipFile(wheel) as archive:
                        self.assertFalse([path for path in archive.namelist()
                                          if path.split('/')[0].endswith('.data')])

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
            from release_artifacts import materialize
            (root / 'scripts').mkdir(exist_ok=True)
            for helper in ['install_release_wheels.py', 'release-wheel-entrypoint.sh']:
                shutil.copy2(ROOT / 'scripts' / helper, root / 'scripts' / helper)
            context = materialize(root, out)
            self.assertFalse(context.is_relative_to(root))
            self.assertFalse((root / '.candidate-artifacts').exists())
            self.assertTrue((context / 'manifest.json').is_file())
            shutil.rmtree(context)
            (root / 'scripts/release-wheel-entrypoint.sh').unlink()
            context_parent = root / 'failed-contexts'
            context_parent.mkdir()
            with patch('tempfile.tempdir', str(context_parent)):
                with self.assertRaises(FileNotFoundError):
                    materialize(root, out)
            self.assertEqual(list(context_parent.iterdir()), [], 'failed materialization leaked a context')
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
            from install_release_wheels import check
            check(artifacts, python, ['probe-release'])
            shutil.copy2(ROOT / 'scripts/install_release_wheels.py', artifacts / 'install.py')
            shutil.copy2(ROOT / 'scripts/release-wheel-entrypoint.sh', artifacts / 'entrypoint.sh')
            runtime = ['sh', str(ROOT / 'scripts/release-wheel-entrypoint.sh'), str(python), '-I', '-c', 'import probe_release; assert probe_release.VALUE == 42']
            runtime_env = dict(os.environ, RELEASE_WHEEL_DIR=str(artifacts), RELEASE_WHEEL_PYTHON=str(python), RELEASE_WHEEL_PACKAGES='probe-release')
            subprocess.run(runtime, env=runtime_env, check=True)
            site = Path(subprocess.check_output([str(python), '-I', '-c',
                'import sysconfig; print(sysconfig.get_path("purelib"))'], text=True).strip())
            remnant = site / '_editable_remnant.pth'
            remnant.write_text(str(project / 'src') + '\n')
            with self.assertRaises(subprocess.CalledProcessError):
                check(artifacts, python, ['probe-release'])
            self.assertNotEqual(subprocess.run(runtime, env=runtime_env, capture_output=True).returncode, 0)
            remnant.unlink()
            direct = next(site.glob('probe_release-*.dist-info/direct_url.json'))
            original = direct.read_text()
            direct.write_text(json.dumps(dict(url=project.as_uri(), dir_info=dict(editable=True))))
            with self.assertRaises(subprocess.CalledProcessError):
                check(artifacts, python, ['probe-release'])
            direct.write_text(original)
            manifest_bytes = (artifacts / 'manifest.json').read_bytes()
            (artifacts / 'manifest.json').unlink()
            self.assertNotEqual(subprocess.run(runtime, env=runtime_env, capture_output=True).returncode, 0)
            (artifacts / 'manifest.json').write_bytes(manifest_bytes)
            check(artifacts, python, ['probe-release'])
            wheel.write_bytes(wheel.read_bytes() + b'changed')
            with self.assertRaisesRegex(ValueError, 'sha256 mismatch'):
                install(artifacts, python, ['probe-release'])


if __name__ == '__main__':
    unittest.main()

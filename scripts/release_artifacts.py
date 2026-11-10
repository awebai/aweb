#!/usr/bin/env python3
"""Build and retain release packages once; consumers verify the same manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from publish_release import PYPI_LANES, NPM_LANES
from release_versions import require_unpublished_changes, VersionRefusal

ROOT = Path(__file__).resolve().parents[1]
PYTHON_PACKAGES = {name: directory for _, packages in PYPI_LANES.values() for name, directory in packages}


def build_python(project: Path, out: Path) -> Path:
    """The package check and release stage share this single build operation."""
    subprocess.run(['uv', 'build', '--sdist', '--wheel', '--out-dir', str(out), str(project)],
                   check=True, capture_output=True, text=True)
    wheels = sorted(out.glob('*.whl'))
    if len(wheels) != 1 or len(list(out.glob('*.tar.gz'))) != 1:
        raise VersionRefusal(f'expected one wheel and one sdist from {project}')
    return wheels[0]


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def manifest_path(directory: Path) -> Path:
    return directory / 'manifest.json'


def verify(directory: Path, *, root: Path | None = None) -> dict:
    manifest = json.loads(manifest_path(directory).read_text())
    if root is not None:
        tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=root, text=True).strip()
        if manifest['source_tree'] != tree:
            raise VersionRefusal('artifact manifest belongs to a different source tree')
    for row in manifest['files']:
        path = directory / row['path']
        if path.resolve().parent != directory.resolve():
            raise VersionRefusal(f'unsafe artifact path: {row["path"]}')
        if not path.is_file() or digest(path) != row['sha256']:
            raise VersionRefusal(f'artifact sha256 mismatch: {row["path"]}')
    if not manifest['files']:
        raise VersionRefusal('empty artifact manifest')
    return manifest


def wheel(directory: Path, name: str) -> Path:
    manifest = verify(directory)
    selected = [row for row in manifest['files'] if row['package'] == name and row['path'].endswith('.whl')]
    if len(selected) != 1:
        raise VersionRefusal(f'expected one manifest wheel for {name}')
    row = selected[0]
    print(f'manifest wheel: {name} {row["version"]} sha256={row["sha256"]} {directory / row["path"]}', flush=True)
    return directory / row['path']


def write_manifest(root: Path, directory: Path) -> None:
    """Use package metadata, not filename guesses, for the publish inventory."""
    import tarfile
    import zipfile
    from email import message_from_bytes
    rows = []
    for path in sorted(directory.iterdir()):
        if path.name.endswith('.whl'):
            with zipfile.ZipFile(path) as archive:
                names = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
                metadata = message_from_bytes(archive.read(names[0]))
            name, version = metadata['Name'], metadata['Version']
        elif path.name.endswith('.tar.gz'):
            with tarfile.open(path) as archive:
                members = [member for member in archive.getmembers() if member.name.count('/') == 1 and member.name.endswith('/PKG-INFO')]
                metadata = message_from_bytes(archive.extractfile(members[0]).read())
            name, version = metadata['Name'], metadata['Version']
        elif path.name.endswith('.tgz'):
            with tarfile.open(path) as archive:
                metadata = json.load(archive.extractfile('package/package.json'))
            name, version = metadata['name'], metadata['version']
        else:
            continue
        rows.append(dict(path=path.name, package=name, version=version, sha256=digest(path)))
    document = dict(schema=1,
        source_sha=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        source_tree=subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=root, text=True).strip(),
        files=rows)
    manifest_path(directory).write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
    (directory / 'SHA256SUMS').write_text(''.join(f'{row["sha256"]}  {row["path"]}\n' for row in rows))
    verify(directory, root=root)


def prepare_python(root: Path, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if manifest_path(directory).exists():
        verify(directory, root=root)
        for name in PYTHON_PACKAGES:
            wheel(directory, name)
        return
    built = {}
    for name, relative in PYTHON_PACKAGES.items():
        project = root / relative
        out = directory / name
        out.mkdir()
        built_wheel = build_python(project, out)
        built[name] = directory / built_wheel.name
        for artifact in (*out.glob('*.whl'), *out.glob('*.tar.gz')):
            artifact.rename(directory / artifact.name)
        (out / '.gitignore').unlink(missing_ok=True)
        out.rmdir()
    require_unpublished_changes(root, built)
    write_manifest(root, directory)


def prepare_npm(root: Path, directory: Path, prefix: str) -> None:
    from publish_release import build_npm_lane, build_aw_npm
    import shutil
    import tempfile
    manifest = verify(directory, root=root)
    package = '@awebai/aw' if prefix == 'aw-v' else NPM_LANES[prefix][1]
    if any(row['package'] == package for row in manifest['files']):
        return
    if prefix == 'aw-v':
        version = os.environ['CLI_VERSION']
        source_sha = manifest['source_sha']
        with tempfile.TemporaryDirectory(prefix='candidate-npm-') as temporary:
            npm_root = Path(temporary) / 'npm'
            shutil.copytree(root / 'cli/go/npm', npm_root,
                            ignore=shutil.ignore_patterns('node_modules', '*.tgz'))
            package_dirs = build_aw_npm(root, version, source_sha, npm_root)
            for package_dir in package_dirs:
                subprocess.run(['npm', 'pack', '--ignore-scripts', '--pack-destination', str(directory)],
                               cwd=npm_root / package_dir, check=True)
    else:
        relative, _, _ = build_npm_lane(root, prefix)
        subprocess.run(['npm', 'pack', '--ignore-scripts', '--pack-destination', str(directory)],
                       cwd=root / relative, check=True)
    write_manifest(root, directory)


def materialize(root: Path, directory: Path) -> None:
    """Docker contexts receive copies whose digests are checked at installation."""
    import shutil
    manifest = verify(directory, root=root)
    destination = root / '.candidate-artifacts'
    destination.mkdir(exist_ok=True)
    for path in destination.glob('*.whl'):
        path.unlink()
    shutil.copy2(manifest_path(directory), destination / 'manifest.json')
    for row in manifest['files']:
        if row['path'].endswith('.whl'):
            shutil.copy2(directory / row['path'], destination / row['path'])
    shutil.copy2(root / 'scripts/install_release_wheels.py', destination / 'install.py')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['python', 'npm', 'materialize', 'manifest', 'verify', 'wheel'])
    parser.add_argument('--directory', type=Path, default=os.environ.get('CANDIDATE_ARTIFACT_DIR'))
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--package')
    parser.add_argument('--prefix', choices=[*NPM_LANES, 'aw-v'])
    args = parser.parse_args()
    if args.directory is None:
        parser.error('CANDIDATE_ARTIFACT_DIR or --directory is required')
    try:
        if args.action == 'python':
            prepare_python(args.root, args.directory.resolve())
        elif args.action == 'npm':
            prepare_npm(args.root, args.directory.resolve(), args.prefix)
        elif args.action == 'materialize':
            materialize(args.root, args.directory.resolve())
        elif args.action == 'manifest':
            write_manifest(args.root, args.directory.resolve())
        elif args.action == 'verify':
            verify(args.directory, root=args.root)
        else:
            print(wheel(args.directory, args.package))
    except (VersionRefusal, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'release artifacts refused: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

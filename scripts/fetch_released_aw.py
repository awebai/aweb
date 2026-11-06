#!/usr/bin/env python3
"""Fetch npm latest once, retaining exact checked wrapper/platform bytes."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen
from urllib.error import HTTPError


def platform_package(system=None, machine=None):
    system, machine = system or sys.platform, (machine or platform.machine()).lower()
    operating = {'linux': 'linux', 'darwin': 'darwin', 'win32': 'windows'}.get(system)
    arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'amd64': 'x64', 'x86_64': 'x64'}.get(machine)
    if not operating or not arch:
        raise ValueError(f'unsupported executing process platform: {system}/{machine}')
    return f'aw-{operating}-{arch}'


def verify_integrity(body, integrity):
    expected = 'sha512-' + base64.b64encode(hashlib.sha512(body).digest()).decode()
    if integrity != expected:
        raise ValueError('tarball SHA512 integrity mismatch or missing integrity')


def tar_member(body, name):
    # Do not extract an archive. Validate every entry, then read one regular file.
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as tar:
        members = tar.getmembers()
        names = set()
        for entry in members:
            path = PurePosixPath(entry.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'package':
                raise ValueError('unsafe tar member path')
            if entry.name in names or not (entry.isfile() or entry.isdir()):
                raise ValueError('duplicate or non-regular tar member')
            names.add(entry.name)
        found = [entry for entry in members if entry.name == name and entry.isfile()]
        if len(found) != 1 or found[0].size > 128 * 1024 * 1024:
            raise ValueError(f'missing or oversized regular package file: {name}')
        return tar.extractfile(found[0]).read()


def package_json(body, name, version):
    value = json.loads(tar_member(body, 'package/package.json'))
    if value.get('name') != name or value.get('version') != version:
        raise ValueError('packed package name/version mismatch')
    return value


def validate_platform_pin(wrapper, package, version):
    if wrapper.get('optionalDependencies', {}).get('@awebai/' + package) != version:
        raise ValueError('wrapper does not pin executing platform to exact version')


def download(url):
    try:
        with urlopen(url, timeout=30) as response:
            body = response.read(128 * 1024 * 1024 + 1)
    except HTTPError as error:
        error.close()
        raise
    if len(body) > 128 * 1024 * 1024:
        raise ValueError('oversized registry response')
    return body


AW_DISTRIBUTION = 'https://github.com/awebai/aw'


def _ls_remote(url, ref):
    return subprocess.run(['git', 'ls-remote', url, ref], capture_output=True, text=True,
                          timeout=30, check=True).stdout


def aw_tag_commit(version, ls_remote=_ls_remote):
    """The commit of the awebai/aw release tag, for a release npm recorded no gitHead for."""
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('an aw tag source needs an exact final version')
    ref = f'refs/tags/v{version}^{{}}'
    lines = ls_remote(AW_DISTRIBUTION, ref).splitlines()
    if len(lines) != 1:
        raise ValueError(f'expected exactly one {ref} in {AW_DISTRIBUTION}, found {len(lines)}')
    commit, _, listed = lines[0].partition('\t')
    if listed != ref or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError(f'malformed {ref} listing from {AW_DISTRIBUTION}')
    return commit


def latest_metadata(registry='https://registry.npmjs.org', resolve_tag=aw_tag_commit):
    metadata = json.loads(download(registry + '/@awebai%2faw/latest'))
    if metadata.get('name') != '@awebai/aw' or not re.fullmatch(r'\d+\.\d+\.\d+', metadata.get('version', '')):
        raise ValueError('npm latest must name an exact final aw package')
    latest = {key: metadata[key] for key in ('name', 'version', 'dist')}
    # npm records gitHead only when a directory is published; a tarball
    # publish (aw 1.36.55) records none, and its source comes from the tag.
    if 'gitHead' in metadata:
        latest.update(gitHead=metadata['gitHead'], source='gitHead')
    else:
        latest.update(source='aw-tag', sourceCommit=resolve_tag(latest['version']))
    return latest


def wrapper_source(wrapper, resolve_tag):
    """The wrapper's source kind and commit; a present gitHead always decides."""
    if 'gitHead' in wrapper:
        if wrapper.get('source', 'gitHead') != 'gitHead' or 'sourceCommit' in wrapper:
            raise ValueError('a gitHead source cannot also name another source')
        if not isinstance(wrapper['gitHead'], str) or not re.fullmatch(r'[0-9a-f]{40}', wrapper['gitHead']):
            raise ValueError('missing immutable package source gitHead')
        return 'gitHead', wrapper['gitHead']
    if wrapper.get('source') not in (None, 'aw-tag'):
        raise ValueError('unknown aw package source')
    commit = wrapper.get('sourceCommit') or resolve_tag(wrapper['version'])
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('aw tag source commit is not a full commit')
    return 'aw-tag', commit


def freeze_latest(directory, registry='https://registry.npmjs.org', resolve_tag=aw_tag_commit):
    # Concurrent gate invocations can observe different latest versions. A
    # shared mutable filename would let one replace the other's ledger input.
    body = (json.dumps(latest_metadata(registry, resolve_tag), sort_keys=True) + '\n').encode()
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / ('released-aw-' + hashlib.sha256(body).hexdigest() + '.json')
    descriptor, temporary = tempfile.mkstemp(prefix='.released-aw-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(body)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination


def fetch(destination, registry='https://registry.npmjs.org', metadata=None, resolve_tag=aw_tag_commit):
    destination.mkdir(parents=True, exist_ok=False)
    selected = platform_package()
    wrapper = metadata if metadata is not None else latest_metadata(registry, resolve_tag)
    version = wrapper.get('version', '')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('npm latest must name an exact final aw version')
    source, commit = wrapper_source(wrapper, resolve_tag)
    records = []
    for name, metadata in [('aw', wrapper), (selected, None)]:
        metadata = metadata or json.loads(download(f'{registry}/@awebai%2f{name}/{version}'))
        if metadata.get('name') != '@awebai/' + name or metadata.get('version') != version:
            raise ValueError('registry package name/version mismatch')
        if source == 'aw-tag':
            if 'gitHead' in metadata:
                raise ValueError('gitHead is absent on only some packages of this release')
        elif not re.fullmatch(r'[0-9a-f]{40}', metadata.get('gitHead', '')):
            raise ValueError('missing immutable package source gitHead')
        elif metadata['gitHead'] != commit:
            raise ValueError('wrapper/platform source gitHead mismatch')
        dist = metadata['dist']
        body = download(dist['tarball'])
        verify_integrity(body, dist['integrity'])
        packed = package_json(body, '@awebai/' + name, version)
        (destination / (name + '.tgz')).write_bytes(body)
        records.append(dict(name=metadata['name'], version=version, gitHead=metadata.get('gitHead'), **dist))
        if name == 'aw':
            validate_platform_pin(packed, selected, version)
        else:
            filename = 'aw.exe' if 'windows' in selected else 'bin/aw'
            binary = destination / ('aw.exe' if 'windows' in selected else 'aw')
            binary.write_bytes(tar_member(body, 'package/' + filename))
            binary.chmod(0o700)
    result = subprocess.run([str(binary.resolve()), 'version'], capture_output=True, text=True, timeout=10,
                            env=dict(os.environ, AW_NO_UPDATE_CHECK='1'), check=True)
    if not re.search(r'^aw ' + re.escape(version) + r'\s*$', result.stdout, re.M):
        raise ValueError('downloaded aw version output mismatch')
    if not re.search(r'^\s*commit: ' + re.escape(commit) + r'(?:\s|$)', result.stdout, re.M):
        raise ValueError('downloaded aw source stamp mismatch')
    evidence = dict(version=version, platform=selected, source=source, sourceCommit=commit, binary=str(binary.resolve()),
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    version_output=result.stdout, packages=records)
    (destination / 'provenance.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path, nargs='?')
    parser.add_argument('--resolve-only', type=Path)
    parser.add_argument('--metadata-input', type=Path)
    parser.add_argument('--freeze-latest', type=Path)
    args = parser.parse_args()
    if args.freeze_latest:
        print(freeze_latest(args.freeze_latest))
    elif args.resolve_only:
        args.resolve_only.parent.mkdir(parents=True, exist_ok=True)
        args.resolve_only.write_text(json.dumps(latest_metadata(), sort_keys=True) + '\n')
    else:
        if args.destination is None:
            parser.error('destination is required')
        metadata = json.loads(args.metadata_input.read_text()) if args.metadata_input else None
        print(json.dumps(fetch(args.destination, metadata=metadata)))

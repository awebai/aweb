"""Compare same-tree artifacts without claiming machine-code equivalence."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

from release_versions import VersionRefusal


def commit_time(root: Path, sha: str) -> str:
    seconds = subprocess.check_output(['git', 'show', '-s', '--format=%ct', sha], cwd=root, text=True).strip()
    return datetime.fromtimestamp(int(seconds), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def binary_identity(payload: bytes, sha: str, timestamp: str) -> list[str]:
    # -trimpath omits ldflags from embedded build info; the manifest records
    # the producer's flags and each executable must contain the requested stamp.
    if sha.encode() not in payload:
        raise VersionRefusal('CLI executable lacks the requested main.commit stamp')
    with tempfile.TemporaryDirectory() as temporary:
        binary = Path(temporary) / 'binary'
        binary.write_bytes(payload)
        output = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
    lines = output.splitlines()
    identity = [lines[0].rsplit(': ', 1)[-1]]
    settings = {}
    for line in lines[1:]:
        fields = line.strip().split('\t')
        if fields[0] == 'build':
            key, value = fields[1].split('=', 1)
            settings[key] = value
            if key == 'vcs.revision':
                if value != sha:
                    raise VersionRefusal('CLI VCS revision does not match requested commit')
                value = '<commit>'
            elif key == 'vcs.time':
                if value != timestamp:
                    raise VersionRefusal('CLI VCS time does not match requested commit')
                value = '<time>'
            elif key == '-ldflags':
                if 'main.commit=' + sha not in value:
                    raise VersionRefusal('CLI embedded ldflags lack main.commit')
                value = value.replace('main.commit=' + sha, 'main.commit=<commit>')
            fields[1] = key + '=' + value
        elif fields[0] == 'mod' and len(fields) >= 3:
            # A main-module pseudo-version contains the commit time and short SHA.
            match = re.fullmatch(r'(v\d+\.\d+\.\d+(?:-[^\s]*)?)(\d{14})-([a-f0-9]{12})(\+incompatible)?', fields[2])
            if match:
                expected_time = timestamp.replace('-', '').replace(':', '').replace('T', '').removesuffix('Z')
                if match[2] != expected_time or match[3] != sha[:12]:
                    raise VersionRefusal('CLI main-module pseudo-version does not match requested commit')
                fields[2] = match[1] + '<time>-<commit>' + (match[4] or '')
        identity.append('\t'.join(fields))
    for key, expected in [('vcs.modified', 'false'), ('-trimpath', 'true'), ('CGO_ENABLED', '0')]:
        if settings.get(key) != expected:
            raise VersionRefusal(f'CLI build setting {key} must be {expected}')
    if not any(row.startswith('path\t') for row in identity) or not any(row.startswith('mod\t') for row in identity):
        raise VersionRefusal('CLI module build info is incomplete')
    if not {'vcs.revision', 'vcs.time', 'GOOS', 'GOARCH'} <= settings.keys():
        raise VersionRefusal('CLI build info is incomplete')
    return identity


def cli_payloads(path: Path, manifest: dict) -> dict:
    result = {}
    platform_package = next(row['package'] for row in manifest['files'] if row['path'] == path.name) != '@awebai/aw'
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            if not member.isfile():
                raise VersionRefusal(f'unexpected CLI archive member: {member.name}')
            payload = archive.extractfile(member).read()
            if member.name == 'package/package.json':
                data = json.loads(payload)
                if data.pop('gitHead', None) != manifest['source_sha']:
                    raise VersionRefusal('CLI package gitHead does not match requested commit')
                value = json.dumps(data, sort_keys=True)
            elif platform_package and member.name in {'package/bin/aw', 'package/bin/aw.exe',
                                 'package/bin/aweb-a2a-gw', 'package/bin/aweb-a2a-gw.exe'}:
                value = binary_identity(payload, manifest['source_sha'], manifest['source_time'])
            else:
                value = payload
            result[member.name] = (member.mode, value)
    return result


def compare_restamp(previous: Path, current: Path) -> None:
    from release_artifacts import verify
    left, right = verify(previous), verify(current)
    def invariant(document):
        if document['build_inputs'].get('source_commit') != document['source_sha']:
            raise VersionRefusal('manifest source commit binding disagrees')
        if any(row['package'] == '@awebai/aw' or row['package'].startswith('@awebai/aw-') for row in document['files']) and 'cli_ldflags' not in document:
            raise VersionRefusal('CLI manifest lacks producer ldflags')
        result = {key: value for key, value in document.items()
                  if key not in {'source_sha', 'source_time', 'files', 'build_inputs', 'cli_ldflags'}}
        result['build_inputs'] = {key: value for key, value in document['build_inputs'].items()
                                 if key != 'source_commit'}
        if 'cli_ldflags' in document:
            flags = document['cli_ldflags']
            stamp = 'main.commit=' + document['source_sha']
            if stamp not in flags:
                raise VersionRefusal('producer ldflags lack requested main.commit')
            result['cli_ldflags'] = flags.replace(stamp, 'main.commit=<commit>')
        return result
    if invariant(left) != invariant(right):
        raise VersionRefusal('restamp changes source tree or build inputs')
    lhs = {row['path']: row for row in left['files']}
    rhs = {row['path']: row for row in right['files']}
    if lhs.keys() != rhs.keys():
        raise VersionRefusal('restamp changes artifact file set')
    for name, row in lhs.items():
        other = rhs[name]
        is_cli = row['package'] == '@awebai/aw' or row['package'].startswith('@awebai/aw-')
        if not is_cli:
            if row != other:
                raise VersionRefusal(f'restamp changes non-CLI artifact: {name}')
        else:
            if {k: v for k, v in row.items() if k != 'sha256'} != {k: v for k, v in other.items() if k != 'sha256'}:
                raise VersionRefusal(f'restamp changes CLI package identity: {name}')
            if cli_payloads(previous / name, left) != cli_payloads(current / name, right):
                raise VersionRefusal(f'restamp changes CLI code/build settings or package files: {name}')
    print('restamp verified: identical tree, inputs and non-CLI bytes; CLI build metadata differs only in commit stamps (not a machine-code equality claim)', flush=True)

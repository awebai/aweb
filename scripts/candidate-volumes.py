#!/usr/bin/env python3
"""Remember volumes from owned containers before their ownership link disappears."""
import argparse
import json
import os
import subprocess
from pathlib import Path


def docker(binary, *args):
    return subprocess.check_output([binary, *args], text=True).strip()


def remember(binary, label, manifest, containers):
    path = Path(manifest)
    before = {line.split('\t')[1] for line in path.read_text().splitlines()
              if line.startswith('preexisting-volume\t')} if path.exists() else set()
    if not containers:
        containers = docker(binary, 'ps', '-aq', '--filter', 'label=aweb.candidate-gate=' + label).split()
    names = set()
    for container in containers:
        inspected = subprocess.run([binary, 'container', 'inspect', container],
                                   text=True, capture_output=True)
        if inspected.returncode:
            # Another cleanup may already have removed it. A daemon failure is
            # still caught by the real removal and the wrapper's final info.
            continue
        info = json.loads(inspected.stdout)[0]
        if (info.get('Config', {}).get('Labels') or {}).get('aweb.candidate-gate') != label:
            continue
        for mount in info.get('Mounts', []):
            if mount.get('Type') != 'volume' or mount['Name'] in before:
                continue
            volume = json.loads(docker(binary, 'volume', 'inspect', mount['Name']))[0]
            labels = volume.get('Labels') or {}
            if 'com.docker.volume.anonymous' in labels or labels.get('aweb.candidate-gate') == label:
                names.add(volume['Name'])
    # One append per receipt avoids partial records from concurrent suite CLIs.
    with Path(manifest).open('a') as output:
        for name in sorted(names):
            output.write('volume\t' + name + '\n')


def remove_recorded(binary, manifest):
    names = {line.split('\t')[1] for line in Path(manifest).read_text().splitlines()
             if line.startswith('volume\t') and len(line.split('\t')) == 2}
    existing = set(docker(binary, 'volume', 'ls', '-q').split())
    failed = False
    for name in sorted(names & existing):
        failed |= subprocess.run([binary, 'volume', 'rm', name], check=False).returncode != 0
    remaining = names & set(docker(binary, 'volume', 'ls', '-q').split())
    with Path(manifest).open('a') as output:
        output.write('absence-owned-volumes\t' + (','.join(sorted(remaining)) or 'none') + '\n')
    if failed or remaining:
        raise RuntimeError('owned volume cleanup failed: ' + ','.join(sorted(remaining)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['remember', 'remove'])
    parser.add_argument('--docker', default=os.environ.get('AWEB_CANDIDATE_REAL_DOCKER', 'docker'))
    parser.add_argument('--label', default=os.environ.get('AWEB_CANDIDATE_RESOURCE_LABEL', ''))
    parser.add_argument('--manifest', default=os.environ.get('CANDIDATE_RESOURCE_MANIFEST', ''))
    parser.add_argument('containers', nargs='*')
    # The shim places options between the operation and container operands.
    args = parser.parse_intermixed_args()
    if not args.label or not args.manifest:
        parser.error('run label and manifest are required')
    if args.operation == 'remember':
        remember(args.docker, args.label, args.manifest, args.containers)
    else:
        remove_recorded(args.docker, args.manifest)


if __name__ == '__main__':
    main()

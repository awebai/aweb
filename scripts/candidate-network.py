#!/usr/bin/env python3
"""Candidate-only Compose networking: no published ports, scoped service DNS."""
from __future__ import annotations

import json
import os
import subprocess
import sys


def override(config: dict) -> str:
    project = config['name']
    lines = ['services:']
    for service, spec in config['services'].items():
        mode = spec.get('network_mode', '')
        if mode and not mode.startswith('service:'):
            raise ValueError(f'{project}/{service}: candidate services require a Compose network or service namespace')
        lines += [f'  {json.dumps(service)}:', '    ports: !reset []']
        if mode:
            # Folio/grant clients share aweb's signed loopback audience. Their
            # network belongs to the referenced service; adding networks here
            # would conflict with network_mode and split that namespace.
            continue
        lines.append('    networks:')
        for network in spec.get('networks', {'default': None}):
            # Append to existing aliases, including federation's TLS/DNS names.
            lines += [f'      {json.dumps(network)}:',
                      f'        aliases: [{json.dumps(f"{project}-{service}.test")}]']
    return '\n'.join(lines) + '\n'


def attach(action: str, project: str) -> None:
    docker = os.environ.get('AWEB_CANDIDATE_REAL_DOCKER', '/usr/bin/docker')
    runner = os.environ['CANDIDATE_RUNNER_NAME']
    label = os.environ['AWEB_CANDIDATE_RESOURCE_LABEL']

    def run(*args: str) -> str:
        return subprocess.run([docker, *args], check=True, capture_output=True,
                              text=True, timeout=30).stdout

    info = json.loads(run('inspect', runner))[0]
    if info['Config']['Labels'].get('aweb.candidate-gate') != label:
        raise ValueError(f'candidate runner ownership mismatch: {runner}')
    attached = info['NetworkSettings']['Networks']
    networks = run('network', 'ls', '-q', '--filter',
                   f'label=com.docker.compose.project={project}').split()
    for network_id in networks:
        network = json.loads(run('network', 'inspect', network_id))[0]
        name = network['Name']
        if action == 'connect' and name not in attached:
            run('network', 'connect', network_id, runner)
        elif action == 'disconnect' and name in attached:
            run('network', 'disconnect', network_id, runner)


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'override':
            print(override(json.load(sys.stdin)), end='')
        else:
            attach(sys.argv[1], sys.argv[2])
    except (ValueError, subprocess.SubprocessError) as error:
        print(f'candidate journey network failure: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        raise SystemExit(1)

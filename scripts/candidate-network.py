#!/usr/bin/env python3
"""Candidate-only Compose networking: no published ports, scoped service DNS."""
from __future__ import annotations

import json
import os
import subprocess
import sys


def networks(config: dict) -> dict:
    for key, spec in config.get('networks', {}).items():
        if spec.get('external'):
            raise ValueError(f'{config["name"]}/{key}: caller-declared external network is not supported by the candidate gate')
    return {key: {**spec, 'name': spec.get('name', f'{config["name"]}_{key}')}
            for key, spec in config.get('networks', {}).items()}


def override(config: dict) -> str:
    network_specs = networks(config)
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
    if network_specs:
        # Replace creation options (internal, IPAM, driver) too: Compose rejects
        # them on an external network. prepare() applies them to the real network.
        lines.append('networks: !override')
        for key, spec in network_specs.items():
            lines += [f'  {json.dumps(key)}:', f'    name: {json.dumps(spec["name"])}',
                      '    external: true']
    return '\n'.join(lines) + '\n'


def create_args(key: str, spec: dict, project: str, label: str) -> list[str]:
    args = ['network', 'create']
    for option in ('driver',):
        if spec.get(option):
            args += ['--' + option, spec[option]]
    for option in ('internal', 'attachable'):
        if spec.get(option):
            args.append('--' + option)
    for version in ('4', '6'):
        if 'enable_ipv' + version in spec:
            args += ['--ipv' + version, str(spec['enable_ipv' + version]).lower()]
    for option, values in (('opt', spec.get('driver_opts', {})), ('label', spec.get('labels', {}))):
        for name, value in values.items():
            args += ['--' + option, f'{name}={value}']
    ipam = spec.get('ipam', {})
    if ipam.get('driver'):
        args += ['--ipam-driver', ipam['driver']]
    for name, value in ipam.get('options', {}).items():
        args += ['--ipam-opt', f'{name}={value}']
    for pool in ipam.get('config', []):
        for source, option in (('subnet', 'subnet'), ('ip_range', 'ip-range'), ('gateway', 'gateway')):
            if pool.get(source):
                args += ['--' + option, pool[source]]
        for name, value in pool.get('aux_addresses', {}).items():
            args += ['--aux-address', f'{name}={value}']
    args += ['--label', f'aweb.candidate-gate={label}',
             '--label', f'com.docker.compose.project={project}',
             '--label', f'com.docker.compose.network={key}', spec['name']]
    return args


def prepare(config: dict) -> None:
    network_specs = networks(config)
    docker = os.environ.get('AWEB_CANDIDATE_REAL_DOCKER', '/usr/bin/docker')
    runner = os.environ['CANDIDATE_RUNNER_NAME']
    label = os.environ['AWEB_CANDIDATE_RESOURCE_LABEL']
    project = config['name']

    def run(*args: str) -> str:
        return subprocess.run([docker, *args], check=True, capture_output=True,
                              text=True, timeout=30).stdout

    info = json.loads(run('inspect', runner))[0]
    if info['Config']['Labels'].get('aweb.candidate-gate') != label:
        raise ValueError(f'candidate runner ownership mismatch: {runner}')
    for key, spec in network_specs.items():
        name = spec['name']
        # List succeeds even when the exact name is absent; daemon errors must
        # not be interpreted as permission to create a replacement network.
        existing = run('network', 'ls', '--format', '{{.Name}}').splitlines()
        if name not in existing:
            run(*create_args(key, spec, project, label))
        current = json.loads(run('network', 'inspect', name))[0]
        labels = current.get('Labels') or {}
        if (labels.get('aweb.candidate-gate') != label
                or labels.get('com.docker.compose.project') != project
                or labels.get('com.docker.compose.network') != key):
            raise ValueError(f'candidate network ownership mismatch: {name}')
        if name not in info['NetworkSettings']['Networks']:
            run('network', 'connect', name, runner)


def disconnect(project: str) -> None:
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
        if name in attached:
            run('network', 'disconnect', network_id, runner)


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'override':
            print(override(json.load(sys.stdin)), end='')
        elif sys.argv[1] == 'prepare':
            prepare(json.load(sys.stdin))
        elif sys.argv[1] == 'disconnect':
            disconnect(sys.argv[2])
        else:
            raise ValueError(f'unknown network operation: {sys.argv[1]}')
    except (ValueError, subprocess.SubprocessError) as error:
        print(f'candidate journey network failure: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        raise SystemExit(1)

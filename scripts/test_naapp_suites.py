#!/usr/bin/env python3
"""Run the existing naapp package targets concurrently, retaining every log."""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

from gate_settings import load_settings
from isolated_suites import run_groups
from secrets_shards import qualify


def package_commands(packages, shards, scratch):
    def secrets_command(number):
        root = scratch / f'shard-{number}'
        root.mkdir(parents=True, exist_ok=True)
        args = [f'--basetemp={root / "pytest"}', '-o', f'cache_dir={root / "cache"}',
                *shards[number - 1]]
        return ['make', '-C', 'naapp/secrets', 'test',
                f'SECRETS_REPORT_NAME=naapp-secrets-{number}',
                'SECRETS_PYTEST_ARGS=' + shlex.join(args)]

    commands = {}
    for package in packages:
        if package == 'naapp/secrets':
            commands['naapp-secrets-1'] = secrets_command(1)
        else:
            commands[package.replace('/', '-')] = ['make', '-C', package, 'test']
    if 'naapp/secrets' in packages:
        commands['naapp-secrets-2'] = secrets_command(2)
    return commands


def main():
    packages = sys.argv[1:]
    if not packages:
        raise SystemExit('package paths are required')
    evidence = Path(os.environ.get('NAAPP_UNIT_LOG_DIR', '/tmp/naapp-unit-logs'))
    shards = qualify(Path('naapp/secrets'), Path('candidate-gate/secrets-shards.json'),
                     evidence / 'secrets-collection') if 'naapp/secrets' in packages else []
    with tempfile.TemporaryDirectory(prefix='aweb-secrets-shards-') as scratch:
        commands = package_commands(packages, shards, Path(scratch))
        # Keep the original five slots; shard two queues behind the other packages.
        status = run_groups(commands, evidence, len(packages), budget=load_settings()['budgets']['unit'])
    locks = subprocess.run(['git', 'diff', '--exit-code', '--', *(p + '/uv.lock' for p in packages)])
    return status or locks.returncode


if __name__ == '__main__':
    raise SystemExit(main())

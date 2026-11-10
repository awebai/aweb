#!/usr/bin/env python3
"""Run the existing naapp package targets concurrently, retaining every log."""
import os
from pathlib import Path
import subprocess
import sys

from isolated_suites import run_groups
from gate_settings import load_settings


def main():
    packages = sys.argv[1:]
    if not packages:
        raise SystemExit('package paths are required')
    evidence = Path(os.environ.get('NAAPP_UNIT_LOG_DIR', '/tmp/naapp-unit-logs'))
    commands = {package.replace('/', '-'): ['make', '-C', package, 'test'] for package in packages}
    status = run_groups(commands, evidence, len(packages), budget=load_settings()['budgets']['unit'])
    locks = subprocess.run(['git', 'diff', '--exit-code', '--', *(p + '/uv.lock' for p in packages)])
    return status or locks.returncode


if __name__ == '__main__':
    raise SystemExit(main())

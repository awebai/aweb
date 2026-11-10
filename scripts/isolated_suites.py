#!/usr/bin/env python3
"""Prepare once, run the shared unit groups, retain every result, restore limits."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from gate_settings import groups, load_settings, resource_args

ROOT = Path(__file__).resolve().parents[1]


def run_groups(commands, evidence, concurrency, budget):
    evidence.mkdir(parents=True, exist_ok=True)

    def run(name, command):
        started = time.monotonic()
        with (evidence / f'{name}.log').open('w') as log:
            try:
                status = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
            except OSError as error:
                log.write(str(error) + '\n')
                status = 126
        duration = time.monotonic() - started
        return name, status, duration

    # Wait for every group even after a failure: its cleanup and log must finish
    # before the parent gate measures residue or restores the outer resources.
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(run, name, command) for name, command in commands.items()]
        results = [future.result() for future in futures]
    with (evidence / 'summary.tsv').open('w') as summary:
        for name, status, duration in results:
            row = f'{name}\t{"FAILED" if status else "PASSED"}\t{name}.log\t{duration:.3f}s\t{budget}s\n'
            summary.write(row)
            print(row.rstrip(), flush=True)
    return 1 if any(status for _, status, _ in results) else 0


@contextmanager
def unit_allocation(containers, reserve, receipt, docker='docker'):
    """Only named containers owned by this gate; restoration also covers failure."""
    originals = {}
    receipt.parent.mkdir(parents=True, exist_ok=True)

    def inspect(name):
        return json.loads(subprocess.check_output([docker, 'inspect', name], text=True))[0]['HostConfig']

    def record(phase, role, name):
        actual = inspect(name)
        with receipt.open('a') as log:
            log.write(f'{phase}/{role}\tcpus={actual["NanoCpus"]/1e9:g}\t'
                      f'memory={actual["Memory"]}\tpids={actual["PidsLimit"]}\n')
        return actual

    try:
        for role, name in containers.items():
            originals[name] = inspect(name)
            limits = reserve[role]
            subprocess.run([docker, 'update', *resource_args(limits), name], check=True,
                           stdout=subprocess.DEVNULL)
            actual = record('unit', role, name)
            if actual['NanoCpus'] != round(limits['cpus'] * 1e9) or actual['Memory'] != limits['memory_mib'] * 1024**2:
                raise RuntimeError(f'unit allocation not applied: {role}')
        yield
    finally:
        errors = []
        for role, name in reversed(list(containers.items())):
            if name not in originals:
                continue
            old = originals[name]
            try:
                subprocess.run([docker, 'update', '--cpus', str(old['NanoCpus']/1e9),
                                '--memory', str(old['Memory']), '--memory-swap', str(old['MemorySwap']),
                                '--pids-limit', str(old['PidsLimit']), name], check=True,
                               stdout=subprocess.DEVNULL)
                actual = record('restored', role, name)
                if any(actual[key] != old[key] for key in ('NanoCpus', 'Memory', 'MemorySwap', 'PidsLimit')):
                    raise RuntimeError(f'outer limits not restored: {role}')
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError('; '.join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--profile', choices=['release', 'lane'], default=os.environ.get('AWEB_GATE_PROFILE', 'lane'))
    args = parser.parse_args()
    settings = load_settings()
    profile = settings['profiles'][args.profile]
    args.evidence.mkdir(parents=True, exist_ok=False)
    image = 'aw-unit-' + uuid.uuid4().hex[:12]
    driver = [sys.executable, str(ROOT / 'scripts/test-egress/docker.py')]
    containers = {role: os.environ[key] for role, key in {
        'outer': 'CANDIDATE_RUNNER_NAME', 'builder': 'CANDIDATE_BUILDER_NAME',
        'postgres': 'CANDIDATE_POSTGRES_NAME', 'redis': 'CANDIDATE_REDIS_NAME',
    }.items() if os.environ.get(key)}
    try:
        subprocess.run([*driver, '--evidence', str(args.evidence / 'prepare'),
                        '--build-image', image], check=True)
        receipt = Path(os.environ.get('CANDIDATE_LOG_DIR', args.evidence)) / 'resource-limits.tsv'
        with unit_allocation(containers, profile['reserve'], receipt):
            commands = {group: [*driver, '--evidence', str(args.evidence / group), '--image', image,
                                '--profile', args.profile, '--group', group]
                        for group in groups(settings)}
            result = run_groups(commands, args.evidence, profile['concurrency'], settings['budgets']['unit'])
        with receipt.open('a') as log:
            for group in groups(settings):
                path = args.evidence / group / 'resource-limits.tsv'
                if path.exists():
                    log.write(path.read_text())
        return result
    finally:
        subprocess.run(['docker', 'image', 'rm', image], check=True, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    raise SystemExit(main())

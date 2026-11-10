"""Reviewed budgets and allocations shared by CI, lanes and release gates."""
import argparse
import json
from pathlib import Path

SETTINGS = Path(__file__).resolve().parents[1] / 'candidate-gate/unit-settings.json'


def groups(settings):
    return [*(f'server-{n}' for n in range(1, settings['server_shards'] + 1)),
            'awid', 'naapp', 'cli', 'channel-pi']


def allocation(settings, profile, group):
    if group not in groups(settings):
        raise ValueError(f'unknown isolated group: {group}')
    return settings['profiles'][profile]['groups']['server' if group.startswith('server-') else group]


def validate(settings):
    if settings['server_shards'] < 1 or settings['server_workers'] < 1:
        raise ValueError('server shard and worker counts must be positive')
    for name, profile in settings['profiles'].items():
        if not 1 <= profile['concurrency'] <= len(groups(settings)):
            raise ValueError('invalid group concurrency')
        for field in ('cpus', 'memory_mib'):
            reserve = sum(row[field] for row in profile['reserve'].values())
            costs = [sum(row[field] for row in allocation(settings, name, group).values())
                     for group in groups(settings)]
            total = reserve + sum(sorted(costs, reverse=True)[:profile['concurrency']])
            if total > profile[field] + .000001:
                raise ValueError(f'{name} allocation exceeds {field}: {total} > {profile[field]}')
        for section in [profile['reserve'], *profile['groups'].values()]:
            for row in section.values():
                if any(row[key] <= 0 for key in ('cpus', 'memory_mib', 'pids')):
                    raise ValueError('resource limits must be positive')


def load_settings():
    settings = json.loads(SETTINGS.read_text())
    validate(settings)
    return settings


def resource_args(limits):
    memory = str(limits['memory_mib'] * 1024**2)
    return ['--cpus', str(limits['cpus']), '--memory', memory,
            '--memory-swap', memory, '--pids-limit', str(limits['pids'])]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('field', choices=['server_shards', 'server_workers', 'matrix', 'budget', 'profile'])
    parser.add_argument('name', nargs='?')
    args = parser.parse_args()
    settings = load_settings()
    if args.field == 'matrix':
        print(json.dumps({'suite': groups(settings)}))
    elif args.field == 'budget':
        print(settings['budgets'].get(args.name, 0))
    elif args.field == 'profile':
        p = settings['profiles'][args.name]
        print(p['cpus'], str(p['memory_mib']) + 'm')
    else:
        print(settings[args.field])

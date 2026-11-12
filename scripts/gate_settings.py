"""Reviewed budgets and allocations shared by CI, lanes and release gates."""
import argparse
import copy
import json
import os
from pathlib import Path

SETTINGS = Path(__file__).resolve().parents[1] / 'candidate-gate/unit-settings.json'


def groups(settings):
    return [*(f'server-{n}' for n in range(1, settings['server_shards'] + 1)),
            'awid', 'naapp', 'cli', 'channel-pi']


def allocation(settings, profile, group):
    if group not in groups(settings):
        raise ValueError(f'unknown isolated group: {group}')
    return settings['profiles'][profile]['groups']['server' if group.startswith('server-') else group]


def server_connection_capacity(settings, workers):
    # route_pair owns two nodes per worker; each retains registry/server,
    # pgdbm test and admin pools. These are maxima, not average active queries.
    pools = settings['vm']['server_connections']
    if any(not isinstance(value, int) or value < 1 for value in pools.values()):
        raise ValueError('server connection capacity inputs must be positive integers')
    return (workers * pools['nodes_per_worker'] *
            (pools['service_pools_per_node'] * pools['service_pool_max'] +
             pools['test_pool_max'] + pools['admin_pool_max']) + pools['control_reserve'])


def validate(settings):
    if settings['server_shards'] < 1 or settings['server_workers'] < 1:
        raise ValueError('server shard and worker counts must be positive')
    for name, profile in settings['profiles'].items():
        if name == 'vm' and settings['server_workers'] > profile['groups']['server']['runner']['cpus']:
            raise ValueError('VM server workers exceed runner CPUs')
        if name == 'vm' and profile['groups']['server']['postgres']['max_connections'] < server_connection_capacity(settings, settings['server_workers']):
            raise ValueError('VM PostgreSQL connection capacity is below the worker pool envelope')
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


def load_settings(profile=None, *, host_cpus=None):
    settings = json.loads(SETTINGS.read_text())
    profile = profile or os.environ.get('AWEB_GATE_PROFILE', 'lane')
    if profile == 'vm':
        if host_cpus is None:
            host_cpus = int(os.environ.get('AWEB_GATE_HOST_CPUS', '0'))
        if not isinstance(host_cpus, int) or host_cpus < 1:
            raise ValueError('VM profile requires the measured host CPU count')
        vm = settings['vm']
        limits = copy.deepcopy(settings['profiles']['release'])
        limits['cpus'] = host_cpus - vm['host_cpu_reserve']
        limits['concurrency'] = vm['concurrency']
        for role, cpus in vm['reserve_cpus'].items():
            limits['reserve'][role]['cpus'] = cpus
        for group, roles in vm['group_cpus'].items():
            for role, cpus in roles.items():
                limits['groups'][group][role]['cpus'] = cpus
        limits['groups']['server']['postgres']['max_connections'] = server_connection_capacity(settings, vm['server_workers'])
        settings['profiles']['vm'] = limits
        settings['server_workers'] = vm['server_workers']
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
    settings = load_settings(args.name if args.field == 'profile' else None)
    if args.field == 'matrix':
        print(json.dumps({'suite': groups(settings)}))
    elif args.field == 'budget':
        print(settings['budgets'].get(args.name, 0))
    elif args.field == 'profile':
        p = settings['profiles'][args.name]
        print(p['cpus'], str(p['memory_mib']) + 'm')
    else:
        print(settings[args.field])

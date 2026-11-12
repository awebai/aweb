"""VM resource policy controls; no Docker or product test substitution."""
import copy
import json
import itertools
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest

from gate_settings import allocation, groups, load_settings, server_connection_capacity, validate

ROOT = Path(__file__).resolve().parents[1]


class VMSettings(unittest.TestCase):
    def test_host_cpu_budget_reserves_one_core_and_refuses_small_hosts(self):
        for cpus in (16, 32):
            settings = load_settings('vm', host_cpus=cpus)
            self.assertEqual(settings['profiles']['vm']['cpus'], cpus - 1)
        with self.assertRaisesRegex(ValueError, 'allocation exceeds cpus'):
            load_settings('vm', host_cpus=8)

    def test_vm_is_opt_in_and_preserves_shared_host_profiles(self):
        raw = json.loads((ROOT / 'candidate-gate/unit-settings.json').read_text())
        for profile in ('release', 'lane'):
            loaded = load_settings(profile, host_cpus=2)
            self.assertEqual(loaded['profiles'][profile], raw['profiles'][profile])
            self.assertEqual(loaded['server_workers'], 4)

    def test_vm_database_allocation_and_worker_cpu_bound(self):
        settings = load_settings('vm', host_cpus=16)
        server = allocation(settings, 'vm', 'server-1')
        self.assertEqual(server['postgres']['cpus'], 2)
        self.assertEqual(server['runner']['cpus'], 2.25)
        self.assertEqual(settings['server_workers'], 2)
        self.assertEqual(groups(settings), ['server-1', 'server-2', 'awid', 'naapp', 'cli', 'channel-pi'])
        bad = copy.deepcopy(settings)
        bad['server_workers'] = 3
        with self.assertRaisesRegex(ValueError, 'workers exceed runner CPUs'):
            validate(bad)

    def test_every_admitted_vm_group_combination_fits(self):
        settings = load_settings('vm', host_cpus=16)
        profile = settings['profiles']['vm']
        self.assertEqual(profile['concurrency'], 4)
        reserve = sum(row['cpus'] for row in profile['reserve'].values())
        for admitted in itertools.combinations(groups(settings), profile['concurrency']):
            total = reserve + sum(sum(row['cpus'] for row in allocation(settings, 'vm', group).values())
                                  for group in admitted)
            self.assertLessEqual(total, 15, admitted)
        bad = copy.deepcopy(settings)
        bad['profiles']['vm']['concurrency'] = 5
        with self.assertRaisesRegex(ValueError, 'allocation exceeds cpus'):
            validate(bad)

    def test_vm_postgres_capacity_covers_full_worker_pool_envelope(self):
        settings = load_settings('vm', host_cpus=16)
        # Two nodes per route_pair; each has server + registry pools (20 each),
        # a test pool (5), and an admin pool (2). Keep eight control connections.
        server = allocation(settings, 'vm', 'server-1')
        self.assertEqual(server['postgres']['max_connections'], 196)
        self.assertEqual(server_connection_capacity(settings, 4), 384)
        spec = importlib.util.spec_from_file_location('egress_driver', ROOT / 'scripts/test-egress/docker.py')
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        self.assertIn('max_connections=196', driver.postgres_args('runner', server['postgres']))
        bad = copy.deepcopy(settings)
        bad['profiles']['vm']['groups']['server']['postgres']['max_connections'] = 100
        with self.assertRaisesRegex(ValueError, 'connection capacity'):
            validate(bad)

    def test_cli_uses_forwarded_host_capacity_and_vm_worker_count(self):
        env = dict(os.environ, AWEB_GATE_PROFILE='vm', AWEB_GATE_HOST_CPUS='16')
        for arguments, expected in ((['profile', 'vm'], '15 32768m'), (['server_workers'], '2')):
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/gate_settings.py'), *arguments],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)


if __name__ == '__main__':
    unittest.main()

"""The gate's CPU plan: weighted shares that never oversubscribe the budget."""

import json
import math
import threading
import time
import unittest
from pathlib import Path

from vm_gate import budget

ROOT = Path(budget.__file__).resolve().parents[3]
WORK = json.loads((ROOT / "candidate-gate/measured-work.json").read_text())
LANES = ["checks", "user-paths", "unit", "artifacts", "integration"]
# Machine shapes as (CPUs, MiB): small, 10 and 12 CPUs, arm64 native hosts,
# Hetzner's dedicated sizes. The plan sees only numbers.
SHAPES = [
    (1, 2048),
    (2, 4096),
    (3, 8192),
    (4, 8192),
    (5, 16384),
    (6, 30720),
    (8, 32768),
    (10, 45056),
    (12, 51642),
    (12, 32768),
    (14, 98304),
    (16, 65536),
    (32, 131072),
    (48, 196608),
    (96, 393216),
]


def worker_memory(workers):
    return 3072 + (workers - 1) * 1408


class Weights(unittest.TestCase):
    def test_the_target_weight_is_half_the_measured_cpu_seconds(self):
        self.assertEqual(budget.cpu_weight(15800), 7900)
        self.assertEqual(budget.cpu_weight(11951), 5976)
        self.assertEqual(budget.cpu_weight(106), 53)
        self.assertEqual(budget.cpu_weight(1), 1)
        self.assertEqual(budget.cpu_weight(10**6), 10000)

    def test_the_engines_mapping_is_named_by_its_probe(self):
        self.assertEqual(budget.mapping_from_probe("100"), "runc-1.3")
        self.assertEqual(budget.mapping_from_probe("39\n"), "linear")
        for other in ("40", "1024", "", "x"):
            with self.subTest(other=other), self.assertRaisesRegex(ValueError, "cpu.weight"):
                budget.mapping_from_probe(other)

    def test_each_mapping_matches_the_kernel_values(self):
        # Measured with docker run --cpu-shares S on runc 1.5 (runc-1.3 curve).
        for shares, weight in [(2, 1), (106, 18), (1024, 100), (2681, 215), (15800, 914), (262144, 10000)]:
            self.assertEqual(budget.weight_of(shares, "runc-1.3"), weight)
        self.assertEqual(budget.weight_of(1024, "linear"), 39)
        self.assertEqual(budget.weight_of(262144, "linear"), 10000)

    def test_the_shares_give_exactly_the_target_weight_in_either_mapping(self):
        for mapping in budget.MAPPINGS:
            for weight in range(1, 10001):
                shares = budget.cpu_shares_for(weight, mapping)
                self.assertTrue(2 <= shares <= 262144)
                self.assertEqual(budget.weight_of(shares, mapping), weight, (mapping, weight))

    def test_workers_are_the_rounded_share_and_at_least_one(self):
        for share, workers in [(0.07, 1), (0.5, 1), (1.49, 1), (1.5, 2), (4.21, 4), (18.89, 19)]:
            with self.subTest(share=share):
                self.assertEqual(budget.workers(share), workers)


class ReleaseSplit(unittest.TestCase):
    def test_cpus_are_proportional_and_unrounded_memory_is_floored(self):
        split = budget.release_split(12, 50513, {"aweb": 15235, "cloud": 18789})
        self.assertEqual(split["aweb"], {"cpus": 5.37, "memory_mib": 22618})
        self.assertEqual(split["cloud"], {"cpus": 6.63, "memory_mib": 27894})
        self.assertEqual(split["measured"], {"cpus": 12, "memory_mib": 50513})

    def test_a_cloud_only_release_gives_cloud_the_whole_guest(self):
        split = budget.release_split(12, 50513, {"cloud": 18789})
        self.assertEqual(split["cloud"], {"cpus": 12, "memory_mib": 50513})


class Plan(unittest.TestCase):
    def plan(self, cpus, memory_mib, lanes=LANES, mapping="runc-1.3"):
        return budget.plan(
            cpus,
            memory_mib,
            lanes=lanes,
            work=WORK,
            mapping=mapping,
            service_memory_mib=worker_memory,
            max_workers=64,
        )

    def test_a_parts_workers_per_busy_cpu_comes_from_its_measured_run(self):
        # vm-cc7cf483: test-server ran 4 workers for 1636 s on 4872 CPU-s; the
        # serial pool's suites ran 3721 slot-seconds on 3234 CPU-s.
        self.assertAlmostEqual(budget.workers_per_busy_cpu(4872, {"workers": 4, "elapsed_seconds": 1636}), 1.343, places=3)
        self.assertAlmostEqual(budget.workers_per_busy_cpu(3234, {"workers": 3, "slot_seconds": 3721}), 1.151, places=3)

    def test_unit_workers_keep_their_share_busy(self):
        # (gate CPUs) -> (server, naapp-lib, serial pool): a suite's workers
        # are max(1, round(share x workers per busy CPU)); the pool's slots
        # round up, from measured-work.json.
        expected = {
            4: (2, 1, 2),
            4.83: (3, 1, 2),
            12: (6, 1, 4),
            48: (26, 5, 15),
        }
        for cpus, (server, naapp, pool) in expected.items():
            with self.subTest(cpus=cpus):
                unit = self.plan(cpus, 1_000_000)["unit"]
                self.assertEqual(unit["workers"]["test-server"], server)
                self.assertEqual(unit["workers"]["test-naapp-lib"], naapp)
                self.assertEqual(unit["serial_slots"], pool)

    def test_the_prediction_is_cpu_seconds_over_busy_cpus(self):
        plan = self.plan(4.83, 22618)
        unit = plan["unit"]
        # test-server: 4872 CPU-s at 3 workers / 1.343 workers per busy CPU.
        self.assertEqual(unit["predicted_seconds"]["test-server"], 2181)
        # The serial pool's 3234 CPU-s at 2 slots / 1.151 workers per busy CPU.
        self.assertEqual(unit["predicted_seconds"]["serial"], 1861)
        self.assertEqual(plan["lanes"]["unit"]["predicted_seconds"], 733 + 2181)
        self.assertEqual(plan["lanes"]["checks"]["predicted_seconds"], 1581)
        # Under full contention a part gets no more than its CPU share:
        # CPU-s / min(the CPUs its workers keep busy, its share).
        self.assertEqual(unit["contended_seconds"]["test-server"], int(4872 / unit["exact_shares"]["test-server"] + 0.5))
        self.assertEqual(plan["lanes"]["checks"]["contended_seconds"], int(1333 / plan["lanes"]["checks"]["exact_share"] + 0.5))
        self.assertEqual(
            plan["lanes"]["unit"]["contended_seconds"], 733 + max(unit["contended_seconds"].values())
        )
        # More slots than the work needs: the longest serial suite bounds it.
        self.assertEqual(self.plan(12, 1_000_000)["unit"]["predicted_seconds"]["serial"], 1640)

    def test_every_lane_and_unit_suite_is_weighted_by_its_measured_work(self):
        for mapping in budget.MAPPINGS:
            plan = self.plan(12, 51642, mapping=mapping)
            for lane in LANES:
                weight = budget.cpu_weight(WORK["lanes"][lane])
                self.assertEqual(plan["lanes"][lane]["cpu_weight"], weight)
                self.assertEqual(budget.weight_of(plan["lanes"][lane]["cpu_shares"], mapping), weight)
            unit = plan["unit"]
            self.assertEqual(set(unit["cpu_shares"]), set(WORK["unit_suites"]))
            for suite, shares in unit["cpu_shares"].items():
                self.assertEqual(
                    budget.weight_of(shares, mapping), budget.cpu_weight(WORK["unit_suites"][suite])
                )

    def test_workers_keep_each_share_busy_and_no_more(self):
        # Each part's workers, divided by its workers per busy CPU, is its
        # CPU share within half a worker (or 1 worker when the share is small).
        for cpus, memory_mib in SHAPES:
            with self.subTest(cpus=cpus):
                unit = self.plan(cpus, memory_mib)["unit"]
                for part, share in unit["shares"].items():
                    workers = unit["serial_slots"] if part == "serial" else unit["workers"][part]
                    ratio = unit["workers_per_busy_cpu"][part]
                    if part == "serial":
                        # Independent suites: the pool rounds up, one slot at most.
                        # (share and ratio are rounded in the plan.)
                        self.assertIn(workers, {max(1, math.ceil(share * ratio - d)) for d in (-0.02, 0.02)})
                        continue
                    if workers > 1 and unit["memory_bound"].get(part):
                        continue
                    self.assertLessEqual(workers, max(1, share * ratio + 0.5) + 0.01)
                    if workers > 1:
                        self.assertGreaterEqual(workers, share * ratio - 0.5 - 0.01)

    def test_worker_services_fit_half_of_units_memory(self):
        for cpus, memory_mib in SHAPES:
            with self.subTest(cpus=cpus, memory_mib=memory_mib):
                unit = self.plan(cpus, memory_mib)["unit"]
                for workers in unit["workers"].values():
                    if workers > 1:
                        self.assertLessEqual(worker_memory(workers), unit["memory_mib"] // 2)

    def test_every_lane_runs_at_once_at_any_size(self):
        for cpus, memory_mib in SHAPES:
            with self.subTest(cpus=cpus):
                self.assertNotIn("concurrent", self.plan(cpus, memory_mib))


class Scheduler(unittest.TestCase):
    def test_running_slots_never_exceed_the_capacity(self):
        for capacity, requests in [
            (5, {"a": 3, "b": 2, "c": 1, "d": 1, "e": 1}),
            (2, {"a": 2, "b": 2, "c": 1}),
            (1, {"a": 1, "b": 1, "c": 1}),
        ]:
            with self.subTest(capacity=capacity):
                lock = threading.Lock()
                running = [0]
                peak = [0]

                def work(name):
                    with lock:
                        running[0] += requests[name]
                        peak[0] = max(peak[0], running[0])
                    time.sleep(0.05)
                    with lock:
                        running[0] -= requests[name]
                    return name

                done = budget.run_within(capacity, requests, work)
                self.assertEqual(sorted(done), sorted(requests))
                self.assertLessEqual(peak[0], capacity)

    def test_a_request_above_the_capacity_is_refused(self):
        with self.assertRaises(ValueError):
            budget.run_within(2, {"a": 3}, lambda name: name)


if __name__ == "__main__":
    unittest.main()

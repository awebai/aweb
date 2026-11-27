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


class Workers(unittest.TestCase):
    def test_workers_are_the_rounded_share_and_at_least_one(self):
        for share, workers in [
            (0.07, 1),
            (0.5, 1),
            (1.49, 1),
            (1.5, 2),
            (4.21, 4),
            (18.89, 19),
        ]:
            with self.subTest(share=share):
                self.assertEqual(budget.workers(share), workers)


class Plan(unittest.TestCase):
    def plan(self, cpus, memory_mib, lanes=LANES):
        return budget.plan(
            cpus,
            memory_mib,
            lanes=lanes,
            work=WORK,
            service_memory_mib=worker_memory,
            max_workers=64,
        )

    def test_a_parts_workers_per_busy_cpu_comes_from_its_measured_run(self):
        # vm-cc7cf483: test-server ran 4 workers for 1636 s on 4872 CPU-s; the
        # serial pool's suites ran 3721 slot-seconds on 3234 CPU-s.
        self.assertAlmostEqual(
            budget.workers_per_busy_cpu(4872, {"workers": 4, "elapsed_seconds": 1636}),
            1.343,
            places=3,
        )
        self.assertAlmostEqual(
            budget.workers_per_busy_cpu(3234, {"workers": 3, "slot_seconds": 3721}),
            1.151,
            places=3,
        )

    def test_unit_workers_keep_their_share_busy(self):
        # (gate CPUs) -> (server, naapp-lib, serial pool): a suite's workers
        # are max(1, round(share x workers per busy CPU)); the pool's slots
        # round up, from measured-work.json.
        expected = {
            4: (2, 1, 2),
            4.83: (3, 1, 2),
            12: (6, 1, 4),
            # test-key-holder's measured 44 CPU-s in the serial pool moves
            # the server's share at 48 CPUs from 26 workers to 25.
            48: (25, 5, 15),
        }
        for cpus, (server, naapp, pool) in expected.items():
            with self.subTest(cpus=cpus):
                unit = self.plan(cpus, 1_000_000)["unit"]
                self.assertEqual(unit["workers"]["test-server"], server)
                self.assertEqual(unit["workers"]["test-naapp-lib"], naapp)
                self.assertEqual(unit["serial_slots"], pool)

    def test_the_plan_sets_no_cpu_weight(self):
        plan = self.plan(12, 51642)
        self.assertNotIn("cpu_shares", json.dumps(plan))
        self.assertEqual(plan["unit"]["cpu_seconds"], WORK["unit_suites"])

    def test_the_plan_predicts_no_times(self):
        plan = self.plan(4.83, 22618)
        text = json.dumps(plan)
        for removed in ("predicted", "contended", "setup", "critical", "mapping"):
            self.assertNotIn(removed, text)

    def test_workers_keep_each_share_busy_and_no_more(self):
        # Each part's workers, divided by its workers per busy CPU, is its
        # CPU share within half a worker (or 1 worker when the share is small).
        for cpus, memory_mib in SHAPES:
            with self.subTest(cpus=cpus):
                unit = self.plan(cpus, memory_mib)["unit"]
                for part, share in unit["shares"].items():
                    workers = (
                        unit["serial_slots"]
                        if part == "serial"
                        else unit["workers"][part]
                    )
                    ratio = unit["workers_per_busy_cpu"][part]
                    if part == "serial":
                        # Independent suites: the pool rounds up, one slot at most.
                        # (share and ratio are rounded in the plan.)
                        self.assertIn(
                            workers,
                            {
                                max(1, math.ceil(share * ratio - d))
                                for d in (-0.02, 0.02)
                            },
                        )
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
                        self.assertLessEqual(
                            worker_memory(workers), unit["memory_mib"] // 2
                        )

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

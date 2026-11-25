"""The gate's CPU plan: weighted shares that never oversubscribe the budget."""

import json
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


class Shares(unittest.TestCase):
    def test_shares_sum_to_the_total_and_none_is_below_one(self):
        weights = WORK["lanes"]
        for total in range(len(weights), 200):
            with self.subTest(total=total):
                shares = budget.shares(total, weights)
                self.assertEqual(sum(shares.values()), total)
                self.assertTrue(all(share >= 1 for share in shares.values()))
                # More work never gets fewer CPUs.
                ordered = sorted(weights, key=weights.get)
                self.assertEqual(
                    [shares[k] for k in ordered], sorted(shares[k] for k in ordered)
                )

    def test_a_total_below_the_parties_is_refused(self):
        for total in range(0, len(LANES)):
            with self.subTest(total=total), self.assertRaises(ValueError):
                budget.shares(total, WORK["lanes"])


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

    def test_no_machine_shape_is_oversubscribed(self):
        for cpus, memory_mib in SHAPES:
            for lanes in (LANES, ["unit"], ["checks", "unit"], ["integration"]):
                with self.subTest(cpus=cpus, memory_mib=memory_mib, lanes=lanes):
                    plan = self.plan(cpus, memory_mib, lanes)
                    shares = plan["lanes"]
                    self.assertEqual(set(shares), set(lanes))
                    self.assertTrue(all(share >= 1 for share in shares.values()))
                    if plan["concurrent"]:
                        # Every lane at once: the shares are the budget.
                        self.assertEqual(sum(shares.values()), cpus)
                    else:
                        # Too few CPUs for every lane: one lane at a time, each
                        # with the budget, never more.
                        self.assertLess(cpus, len(lanes))
                        self.assertTrue(all(s == cpus for s in shares.values()))
                    if "unit" not in lanes:
                        continue
                    unit = plan["unit"]
                    self.assertEqual(unit["cpus"], shares["unit"])
                    slots = unit["slots"]
                    self.assertTrue(all(1 <= s <= unit["cpus"] for s in slots.values()))
                    for suite, workers in unit["workers"].items():
                        self.assertLessEqual(workers, slots[suite])
                        self.assertNotEqual(workers, 1)
                        if workers:
                            unit_memory = memory_mib * unit["cpus"] // cpus
                            self.assertLessEqual(
                                worker_memory(workers), unit_memory // 2
                            )
                    if unit["concurrent"]:
                        parallel = sum(slots[s] for s in budget.PARALLEL_SUITES if s in slots)
                        self.assertEqual(parallel + unit["serial_slots"], unit["cpus"])

    def test_twelve_cpus_give_unit_most_of_the_machine(self):
        plan = self.plan(12, 51642)
        self.assertTrue(plan["concurrent"])
        self.assertEqual(max(plan["lanes"], key=plan["lanes"].get), "unit")
        self.assertGreater(plan["lanes"]["unit"], 12 // 2)


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

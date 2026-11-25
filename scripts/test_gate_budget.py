"""The gate's sizes come from its CPU and memory budget, and never exceed it."""

import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "gate_budget", ROOT / "scripts/gate_budget.py"
)
gate_budget = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate_budget)

worker_spec = importlib.util.spec_from_file_location(
    "worker_services", ROOT / "server/tests/worker_services.py"
)
worker_services = importlib.util.module_from_spec(worker_spec)
worker_spec.loader.exec_module(worker_services)

MACHINES = [
    (cpus, memory_mib)
    for cpus in range(1, 129)
    for memory_mib in (2048, 8192, 16384, 31_000, 45_000, 64_000, 256_000)
]


class BudgetTests(unittest.TestCase):
    def test_every_cap_and_worker_plan_fits_the_budget(self):
        for cpus, memory_mib in MACHINES:
            with self.subTest(cpus=cpus, memory_mib=memory_mib):
                sizes = gate_budget.size(cpus, memory_mib)
                for cap in ("runner_cpus", "builder_cpus", "sibling_cpus"):
                    self.assertGreater(sizes[cap], 0)
                    self.assertLessEqual(sizes[cap], cpus)
                workers = sizes["server_workers"]
                self.assertGreaterEqual(workers, 0)
                self.assertLessEqual(workers, max(cpus - 1, 0))
                self.assertLessEqual(workers, worker_services.MAX_WORKERS)
                self.assertNotEqual(workers, 1)
                # The parallel plan's real service limits fit half the memory.
                if workers:
                    self.assertLessEqual(
                        worker_services.service_memory_mib(workers), memory_mib // 2
                    )

    def test_a_larger_machine_never_gets_fewer_workers(self):
        for memory_mib in (8192, 45_000, 256_000):
            counts = [gate_budget.size(c, memory_mib)["server_workers"] for c in range(1, 129)]
            self.assertEqual(counts, sorted(counts))
        self.assertEqual(gate_budget.size(10, 45_000)["server_workers"], 9)
        self.assertEqual(gate_budget.size(2, 8192)["server_workers"], 0)

    def test_invalid_budgets_are_refused(self):
        for cpus, memory_mib in [(0, 1024), (2, 0), (-1, 1024)]:
            with self.subTest(cpus=cpus, memory_mib=memory_mib):
                with self.assertRaises(ValueError):
                    gate_budget.size(cpus, memory_mib)

    def test_an_explicit_budget_is_used_and_a_bad_one_refused(self):
        env = dict(os.environ, GATE_CPUS="6", GATE_MEMORY_MIB="20000")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/gate_budget.py")],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = dict(line.split("=", 1) for line in result.stdout.split())
        self.assertEqual(values["GATE_CPUS"], "6")
        self.assertEqual(values["GATE_MEMORY_MIB"], "20000")
        self.assertEqual(values["GATE_BUDGET_SOURCE"], "cpus=input,memory=input")
        self.assertEqual(values["CANDIDATE_SERVER_WORKERS"], "5")
        for bad in ("0", "two", "1.5"):
            env["GATE_CPUS"] = bad
            refused = subprocess.run(
                [sys.executable, str(ROOT / "scripts/gate_budget.py")],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(refused.returncode, 2, bad)
            self.assertIn("GATE_CPUS", refused.stderr)


if __name__ == "__main__":
    unittest.main()

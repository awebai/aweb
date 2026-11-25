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

WORK = gate_budget.WORK


def run_budget(**env):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/gate_budget.py")],
        env=dict(os.environ, **env),
        capture_output=True,
        text=True,
        timeout=30,
    )


class BudgetTests(unittest.TestCase):
    def test_a_releases_fractional_share_is_the_budget(self):
        result = run_budget(
            GATE_CPUS="4.83",
            GATE_MEMORY_MIB="20333",
            GATE_LANES="checks user-paths unit artifacts integration",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = dict(line.split("=", 1) for line in result.stdout.split())
        self.assertEqual(values["GATE_CPUS"], "4.83")
        self.assertEqual(values["GATE_BUDGET_SOURCE"], "cpus=input,memory=input")
        # The release's aweb share on merak gives unit 4.83 x 9576 / 12660.
        self.assertEqual(values["GATE_UNIT_CPUS"], "3.65")
        # Every lane's containers carry its measured CPU-seconds as --cpu-shares.
        for lane, seconds in WORK["lanes"].items():
            name = "GATE_LANE_CPU_SHARES_" + lane.upper().replace("-", "_")
            self.assertEqual(values[name], str(seconds))
        self.assertEqual(values["GATE_BUILDER_CPU_SHARES"], str(WORK["lanes"]["unit"]))
        for removed in ("GATE_CPU_MAPPING", "GATE_LANE_CPU_WEIGHT_UNIT"):
            self.assertNotIn(removed, values)

    def test_no_cpu_cap_is_planned(self):
        result = run_budget(GATE_CPUS="12", GATE_MEMORY_MIB="51642", GATE_LANES="unit checks")
        self.assertEqual(result.returncode, 0, result.stderr)
        names = {line.split("=", 1)[0] for line in result.stdout.split()}
        for cap in ("GATE_RUNNER_CPUS", "GATE_BUILDER_CPUS", "GATE_SIBLING_CPUS", "GATE_LANES_CONCURRENT"):
            self.assertNotIn(cap, names)
        self.assertFalse(any(n.startswith("GATE_LANE_CPUS_") for n in names), names)

    def test_a_bad_budget_is_refused(self):
        for bad in ("0", "two", "-1", "1.5.2", "0.0"):
            with self.subTest(bad=bad):
                refused = run_budget(GATE_CPUS=bad, GATE_MEMORY_MIB="20000")
                self.assertEqual(refused.returncode, 2, bad)
                self.assertIn("GATE_CPUS", refused.stderr)


if __name__ == "__main__":
    unittest.main()

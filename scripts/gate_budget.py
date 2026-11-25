#!/usr/bin/env python3
"""The aweb gate's CPU plan, from the release's one budget computation.

GATE_CPUS and GATE_MEMORY_MIB are the gate's budget: a release passes its
proportional share (CPUs may be fractional); a standalone gate measures the
Docker engine it runs on. The plan caps no CPU: it gives each lane's
containers their measured CPU-seconds as --cpu-shares, and sizes workers.
GATE_LANES names the lanes that run after static (default: unit alone). The plan comes
from scripts/vm-gate/vm_gate/budget.py, weighted by candidate-gate/
measured-work.json. The budget sizes a run and is not a gate input: it stays
out of the ledger key and goes into the run's evidence.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


budget = load("release_budget", "scripts/vm-gate/vm_gate/budget.py")
workers = load("server_worker_services", "server/tests/worker_services.py")
WORK = json.loads((ROOT / "candidate-gate/measured-work.json").read_text())


def plan(cpus, memory_mib, lanes):
    return budget.plan(
        cpus,
        memory_mib,
        lanes=lanes,
        work=WORK,
        service_memory_mib=workers.service_memory_mib,
        max_workers=workers.MAX_WORKERS,
    )


def main():
    try:
        cpus, memory_mib, source = budget.budget_from(os.environ)
        lanes = os.environ.get("GATE_LANES", "unit").split()
        unknown = [lane for lane in lanes if lane not in WORK["lanes"]]
        if unknown:
            raise ValueError(f"no measured work for lanes {unknown}")
        run = plan(cpus, memory_mib, lanes)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"gate budget refused: {error}", file=sys.stderr)
        return 2
    lines = [
        ("GATE_CPUS", cpus),
        ("GATE_MEMORY_MIB", memory_mib),
        ("GATE_BUDGET_SOURCE", source),
        # The run's builder serves unit's images, the largest part of its work.
        ("GATE_BUILDER_CPU_SHARES", budget.cpu_shares(WORK["lanes"]["unit"])),
    ]
    for lane, lane_plan in sorted(run["lanes"].items()):
        name = lane.upper().replace("-", "_")
        lines.append(("GATE_LANE_CPU_SHARES_" + name, lane_plan["cpu_shares"]))
        lines.append(("GATE_LANE_SHARE_" + name, lane_plan["cpus"]))
    if "unit" in run:
        lines += [
            ("GATE_UNIT_CPUS", run["unit"]["cpus"]),
            ("GATE_UNIT_MEMORY_MIB", run["unit"]["memory_mib"]),
        ]
    for name, value in lines:
        print(f"{name}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

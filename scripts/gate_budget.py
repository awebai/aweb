#!/usr/bin/env python3
"""The aweb gate's CPU plan, from the release's one budget computation.

GATE_CPUS and GATE_MEMORY_MIB are the gate's budget: a release passes its
share; a standalone gate measures the Docker engine it runs on. GATE_LANES
names the lanes that run after static (default: unit alone). The plan comes
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


def size(cpus, memory_mib):
    return budget.size(
        cpus,
        memory_mib,
        service_memory_mib=workers.service_memory_mib,
        max_workers=workers.MAX_WORKERS,
    )


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
        sizes = size(cpus, memory_mib)
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
        ("GATE_RUNNER_CPUS", sizes["runner_cpus"]),
        ("GATE_BUILDER_CPUS", sizes["builder_cpus"]),
        ("GATE_SIBLING_CPUS", sizes["sibling_cpus"]),
        ("GATE_LANES_CONCURRENT", int(run["concurrent"])),
    ]
    for lane, share in sorted(run["lanes"].items()):
        lines.append(("GATE_LANE_CPUS_" + lane.upper().replace("-", "_"), share))
    if "unit" in run:
        unit_memory = (
            memory_mib * run["unit"]["cpus"] // cpus if run["concurrent"] else memory_mib
        )
        lines += [
            ("GATE_UNIT_CPUS", run["unit"]["cpus"]),
            ("GATE_UNIT_MEMORY_MIB", unit_memory),
        ]
    for name, value in lines:
        print(f"{name}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

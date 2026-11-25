#!/usr/bin/env python3
"""The aweb gate's CPU plan, from the release's one budget computation.

GATE_CPUS and GATE_MEMORY_MIB are the gate's budget: a release passes its
proportional share (CPUs may be fractional); a standalone gate measures the
Docker engine it runs on. The plan caps no CPU: it gives each lane's
containers their measured CPU-seconds as cgroup weight, and sizes workers.
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


def plan(cpus, memory_mib, lanes, mapping="runc-1.3"):
    return budget.plan(
        cpus,
        memory_mib,
        lanes=lanes,
        work=WORK,
        mapping=mapping,
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
        # The plan's weights need the engine's mapping, which the wrapper
        # probes once it runs Docker; without the probe, only the budget.
        probe = os.environ.get("GATE_CPU_WEIGHT_PROBE")
        mapping = budget.mapping_from_probe(probe) if probe is not None else None
        run = plan(cpus, memory_mib, lanes, mapping) if mapping else None
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"gate budget refused: {error}", file=sys.stderr)
        return 2
    lines = [
        ("GATE_CPUS", cpus),
        ("GATE_MEMORY_MIB", memory_mib),
        ("GATE_BUDGET_SOURCE", source),
    ]
    if run is None:
        for name, value in lines:
            print(f"{name}={value}")
        return 0
    lines += [
        ("GATE_CPU_MAPPING", mapping),
        # The run's builder serves unit's images, the largest part of its work.
        ("GATE_BUILDER_CPU_SHARES", budget.lane_shares(WORK["lanes"]["unit"], mapping)),
    ]
    for lane, lane_plan in sorted(run["lanes"].items()):
        name = lane.upper().replace("-", "_")
        lines.append(("GATE_LANE_CPU_WEIGHT_" + name, lane_plan["cpu_weight"]))
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

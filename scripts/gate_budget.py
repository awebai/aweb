#!/usr/bin/env python3
"""The aweb gate's sizes, from the release's one budget computation.

GATE_CPUS and GATE_MEMORY_MIB are the gate's budget: a release passes its
share; a standalone gate measures the Docker engine it runs on. The sizes come
from scripts/vm-gate/vm_gate/budget.py with the server worker plan's service
memory. The budget sizes a run and is not a gate input: it stays out of the
ledger key and goes into the run's evidence.
"""

import importlib.util
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


def size(cpus, memory_mib):
    return budget.size(
        cpus,
        memory_mib,
        service_memory_mib=workers.service_memory_mib,
        max_workers=workers.MAX_WORKERS,
    )


def main():
    try:
        cpus, memory_mib, source = budget.budget_from(os.environ)
        sizes = size(cpus, memory_mib)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"gate budget refused: {error}", file=sys.stderr)
        return 2
    for name, value in (
        ("GATE_CPUS", cpus),
        ("GATE_MEMORY_MIB", memory_mib),
        ("GATE_BUDGET_SOURCE", source),
        ("GATE_RUNNER_CPUS", sizes["runner_cpus"]),
        ("GATE_BUILDER_CPUS", sizes["builder_cpus"]),
        ("GATE_SIBLING_CPUS", sizes["sibling_cpus"]),
        ("CANDIDATE_SERVER_WORKERS", sizes["server_workers"]),
    ):
        print(f"{name}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

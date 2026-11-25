"""The release's one budget computation, from capacity measured at run time.

Whatever runs the tests is measured when the job runs: the Docker engine's CPU
count and memory, inside a VM guest or on a native host. The release splits
that between its Cloud and aweb gates; each gate sizes its workers and
container caps from its share. No machine is named and no size is assumed. An
operator override is optional input, never a default. Standard library only:
a release guest runs this before either gate starts, and the aweb gate loads
it by path.
"""

import json
import re
import subprocess
import sys
from pathlib import Path


def measure():
    """The Docker engine's CPU count and memory in MiB, measured now."""
    out = subprocess.run(
        ["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.split()
    return int(out[0]), int(out[1]) // (1024 * 1024)


def positive(cpus, memory_mib):
    if type(cpus) is not int or type(memory_mib) is not int:
        raise ValueError("a budget is whole CPUs and MiB")
    if cpus < 1 or memory_mib < 1:
        raise ValueError("a budget needs at least 1 CPU and 1 MiB")


def release_split(cpus, memory_mib, aweb=True):
    """The measured capacity divided between the release's gates.

    With an aweb gate the capacity is halved, Cloud taking the odd CPU and
    MiB; without one, Cloud has all of it. The shares sum to exactly the
    capacity: nothing oversubscribed, nothing left idle.
    """
    positive(cpus, memory_mib)
    measured = {"cpus": cpus, "memory_mib": memory_mib}
    if not aweb:
        return {"measured": measured, "cloud": dict(measured)}
    if cpus < 2 or memory_mib < 2:
        raise ValueError("two gates need at least 2 CPUs and 2 MiB")
    aweb_cpus, aweb_memory = cpus // 2, memory_mib // 2
    return {
        "measured": measured,
        "aweb": {"cpus": aweb_cpus, "memory_mib": aweb_memory},
        "cloud": {"cpus": cpus - aweb_cpus, "memory_mib": memory_mib - aweb_memory},
    }


def size(cpus, memory_mib, *, service_memory_mib, max_workers):
    """One gate's caps from its budget.

    Every container CPU cap is the whole budget: caps are quotas, so
    concurrent containers share every CPU. Parallel server workers leave one
    CPU for the rest of the unit stage, and their Postgres and Redis limits
    (`service_memory_mib(workers)`) use at most half the memory. A plan of one
    worker is no faster than the serial suite, so it is serial (0).
    """
    positive(cpus, memory_mib)
    workers = 0
    for candidate in range(2, min(cpus, max_workers + 1)):
        if service_memory_mib(candidate) > memory_mib // 2:
            break
        workers = candidate
    return {
        "cpus": cpus,
        "memory_mib": memory_mib,
        "runner_cpus": cpus,
        "builder_cpus": cpus,
        "sibling_cpus": cpus,
        "server_workers": workers,
    }


def budget_from(environ):
    """GATE_CPUS and GATE_MEMORY_MIB when given, each measured otherwise."""
    given = {}
    for name in ("GATE_CPUS", "GATE_MEMORY_MIB"):
        value = environ.get(name, "")
        if value and not re.fullmatch(r"[1-9][0-9]*", value):
            raise ValueError(f"{name} must be a positive integer, not {value!r}")
        if value:
            given[name] = int(value)
    if len(given) < 2:
        cpus, memory_mib = measure()
        given.setdefault("GATE_CPUS", cpus)
        given.setdefault("GATE_MEMORY_MIB", memory_mib)
    source = ",".join(
        f"{label}={'input' if environ.get(name) else 'measured'}"
        for label, name in (("cpus", "GATE_CPUS"), ("memory", "GATE_MEMORY_MIB"))
    )
    return given["GATE_CPUS"], given["GATE_MEMORY_MIB"], source


def write_split(path, aweb):
    """In the release job: measure, split, record, and print the shares."""
    shares = release_split(*measure(), aweb)
    Path(path).write_text(json.dumps(shares, sort_keys=True) + "\n")
    gates = [shares["cloud"], shares.get("aweb", {"cpus": 0, "memory_mib": 0})]
    print(" ".join(str(gate[key]) for gate in gates for key in ("cpus", "memory_mib")))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "split" and sys.argv[3] in ("aweb", "cloud-only"):
        write_split(sys.argv[2], sys.argv[3] == "aweb")
    else:
        raise SystemExit("usage: python3 -m vm_gate.budget split PATH aweb|cloud-only")

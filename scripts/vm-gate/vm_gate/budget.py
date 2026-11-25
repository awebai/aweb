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
import threading
from pathlib import Path

# The unit suites that run xdist workers on an owned service plan.
PARALLEL_SUITES = ("test-server", "test-naapp-lib")


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


def release_split(cpus, memory_mib, weights):
    """The measured capacity divided between the release's gates.

    weights holds each gate's measured CPU-seconds ("cloud", and "aweb" when
    the release runs an aweb gate). CPUs and memory are both divided by the
    lanes' rule (shares): in proportion to the weights, each gate at least 1,
    summing to exactly the measurement.
    """
    positive(cpus, memory_mib)
    if set(weights) not in ({"cloud"}, {"cloud", "aweb"}):
        raise ValueError("a release splits between cloud and, optionally, aweb")
    if any(type(w) is not int or w < 1 for w in weights.values()):
        raise ValueError("gate weights must be positive whole CPU-seconds")
    cpu_shares = shares(cpus, weights)
    memory_shares = shares(memory_mib, weights)
    split = {"measured": {"cpus": cpus, "memory_mib": memory_mib}, "weights": dict(weights)}
    for gate in weights:
        split[gate] = {"cpus": cpu_shares[gate], "memory_mib": memory_shares[gate]}
    return split


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


def shares(total, weights):
    """Whole CPUs for each party, in proportion to its weight.

    Each party's proportional share is rounded down; a share below 1 is raised
    to 1, taking that CPU from the share furthest above its proportion; CPUs
    left go to the largest remainders. The shares sum to the total and none is
    below 1. A total below the number of parties is refused.
    """
    names = sorted(weights)
    if type(total) is not int or total < len(names):
        raise ValueError(f"{total} CPUs cannot give {len(names)} parties a CPU each")
    weight = sum(weights[n] for n in names)
    raw = {
        n: (total * weights[n] / weight if weight else total / len(names))
        for n in names
    }
    result = {n: max(1, int(raw[n])) for n in names}
    while sum(result.values()) > total:
        over = max(
            (n for n in names if result[n] > 1),
            key=lambda n: (result[n] - raw[n], result[n], n),
        )
        result[over] -= 1
    for n in sorted(names, key=lambda n: (-(raw[n] - result[n]), -weights[n], n)):
        if sum(result.values()) == total:
            break
        result[n] += 1
    return result


def plan(cpus, memory_mib, *, lanes, work, service_memory_mib, max_workers):
    """The run's CPU plan from its budget and the measured work.

    After static, the pending lanes run at once with shares weighted by their
    measured work; with fewer CPUs than lanes they run one at a time, each with
    the budget. Unit's share is divided between its parallel suites and one
    pool for the serial suites, by the same rule; with too few CPUs for that,
    every suite may use the whole share, and the scheduler runs them one at a
    time. A parallel suite's xdist workers are its slots, while their service
    memory fits half of unit's part of the memory; one worker is serial.
    """
    positive(cpus, memory_mib)
    lanes = list(lanes)
    concurrent = cpus >= len(lanes)
    lane_cpus = (
        shares(cpus, {lane: work["lanes"][lane] for lane in lanes})
        if concurrent
        else {lane: cpus for lane in lanes}
    )
    result = {"concurrent": concurrent, "lanes": lane_cpus}
    if "unit" in lanes:
        result["unit"] = unit_plan(
            lane_cpus["unit"],
            memory_mib * lane_cpus["unit"] // cpus if concurrent else memory_mib,
            work["unit_suites"],
            service_memory_mib=service_memory_mib,
            max_workers=max_workers,
        )
    return result


def unit_plan(cpus, memory_mib, suites, *, service_memory_mib, max_workers):
    parallel = [s for s in PARALLEL_SUITES if s in suites]
    serial = [s for s in suites if s not in parallel]
    weights = {s: suites[s] for s in parallel}
    if serial:
        weights["serial"] = sum(suites[s] for s in serial)
    concurrent = cpus >= len(weights)
    divided = shares(cpus, weights) if concurrent else {k: cpus for k in weights}
    slots = {s: divided[s] for s in parallel}
    slots.update({s: 1 for s in serial})
    workers = {}
    for suite in parallel:
        count = 0
        for candidate in range(2, min(slots[suite], max_workers) + 1):
            if service_memory_mib(candidate) > memory_mib // 2:
                break
            count = candidate
        workers[suite] = count
    return {
        "cpus": cpus,
        "concurrent": concurrent,
        "slots": slots,
        "serial_slots": divided.get("serial", 0),
        "workers": workers,
    }


def run_within(capacity, requests, work):
    """Run work(name) for every name, at most `capacity` slots at once.

    Larger requests start first. A name starts only when its slots are free,
    so the running total never exceeds the capacity. Returns each name's result,
    or the exception it raised.
    """
    if any(r < 1 or r > capacity for r in requests.values()):
        raise ValueError(f"every request must be between 1 and {capacity} slots")
    order = sorted(requests, key=lambda n: -requests[n])
    free = [capacity]
    results = {}
    condition = threading.Condition()

    def run(name):
        try:
            results[name] = work(name)
        except Exception as error:  # noqa: BLE001 -- reported per name
            results[name] = error
        with condition:
            free[0] += requests[name]
            condition.notify_all()

    threads = []
    for name in order:
        with condition:
            condition.wait_for(lambda: free[0] >= requests[name])
            free[0] -= requests[name]
        thread = threading.Thread(target=run, args=(name,))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    return results


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


def write_split(path, weights):
    """In the release job: measure, split, record, and print the shares."""
    shares = release_split(*measure(), weights)
    Path(path).write_text(json.dumps(shares, sort_keys=True) + "\n")
    gates = [shares["cloud"], shares.get("aweb", {"cpus": 0, "memory_mib": 0})]
    print(" ".join(str(gate[key]) for gate in gates for key in ("cpus", "memory_mib")))


def parse_weights(arguments):
    """GATE=CPU-SECONDS arguments, as the dispatcher passes the measured weights."""
    weights = {}
    for argument in arguments:
        gate, _, value = argument.partition("=")
        if gate not in ("cloud", "aweb") or gate in weights or not re.fullmatch(r"[1-9][0-9]*", value):
            raise ValueError(f"invalid gate weight {argument!r}")
        weights[gate] = int(value)
    return weights


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "split":
        write_split(sys.argv[2], parse_weights(sys.argv[3:]))
    else:
        raise SystemExit("usage: python3 -m vm_gate.budget split PATH cloud=N [aweb=N]")

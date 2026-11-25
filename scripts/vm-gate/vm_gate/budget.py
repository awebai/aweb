"""The release's one budget computation, from capacity measured at run time.

Whatever runs the tests is measured when the job runs: the Docker engine's CPU
count and memory, inside a VM guest or on a native host. No machine is named
and no size is assumed; an operator override is optional input, never a
default. Standard library only: a release guest runs this before either gate
starts, and the aweb gate loads it by path.

Nothing caps a container's CPU and nothing weights it: every container runs
at Docker's default, and the engine's CPU count is the only bound. What keeps
the machine from being oversubscribed is how much each part runs at once.

CPU counts size only how much a part runs at once. A part's workers are its
proportional CPU share times the workers per busy CPU it showed in the
measured run (workers wait on databases and serial setup), rounded, at least
1 (unit_plan): enough to keep its own share busy, and no more. That does not
repeat vm-7b34f721, where every runner was capped at the whole budget and the
two xdist suites ran 11 workers each beside the serial suites (about twice
the CPUs, each worker building aw): each part is sized to its share, and aw
is built once.
"""

import json
import math
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


def workers(share):
    """How many processes a part runs: its CPU share, rounded half up, at least 1."""
    return max(1, int(share + 0.5))


def proportional(total, weights):
    weight = sum(weights.values())
    return {name: total * w / weight for name, w in weights.items()}


def release_split(cpus, memory_mib, weights):
    """The measured capacity divided between the release's gates.

    weights holds each gate's measured CPU-seconds ("cloud", and "aweb" when
    the release runs an aweb gate). Each gate's CPUs are its proportional
    share, unrounded (two decimals): they size its workers and cap nothing.
    Its memory is the same proportion, rounded down to whole MiB.
    """
    positive(cpus, memory_mib)
    if set(weights) not in ({"cloud"}, {"cloud", "aweb"}):
        raise ValueError("a release splits between cloud and, optionally, aweb")
    if any(type(w) is not int or w < 1 for w in weights.values()):
        raise ValueError("gate weights must be positive whole CPU-seconds")
    split = {"measured": {"cpus": cpus, "memory_mib": memory_mib}, "weights": dict(weights)}
    for gate, share in proportional(cpus, weights).items():
        split[gate] = {
            "cpus": cpus if len(weights) == 1 else round(share, 2),
            "memory_mib": memory_mib * weights[gate] // sum(weights.values()),
        }
    return split


def workers_per_busy_cpu(cpu_seconds, run):
    """How many workers a part ran per CPU it kept busy, in its measured run.

    workers x elapsed / CPU-seconds; for the serial pool, its slot-seconds
    (each suite's elapsed, summed) / CPU-seconds. Above 1 where workers wait
    (on a database, on serial setup).
    """
    worker_seconds = run.get("slot_seconds", run.get("workers", 1) * run.get("elapsed_seconds", 0))
    return worker_seconds / cpu_seconds


def plan(cpus, memory_mib, *, lanes, work, service_memory_mib, max_workers):
    """The run's CPU plan from its budget and the measured work.

    After static, every pending lane runs at once, whatever the machine's
    size, so no lane waits for another. A lane other than unit is one
    process. Unit's share is divided among its parallel suites and one pool
    for the serial suites (unit_plan).
    """
    if not cpus > 0 or type(memory_mib) is not int or memory_mib < 1:
        raise ValueError("a budget needs CPUs above 0 and at least 1 MiB")
    lanes = list(lanes)
    measured = {lane: work["lanes"][lane] for lane in lanes}
    lane_cpus = proportional(cpus, measured)
    result = {
        "lanes": {
            lane: {"cpus": round(lane_cpus[lane], 2)}
            for lane in lanes
        }
    }
    if "unit" in lanes:
        unit = unit_plan(
            lane_cpus["unit"],
            memory_mib * measured["unit"] // sum(measured.values()),
            work["unit_suites"],
            runs=work["unit_runs"],
            service_memory_mib=service_memory_mib,
            max_workers=max_workers,
        )
        result["unit"] = unit
    return result


def unit_plan(cpus, memory_mib, suites, *, runs, service_memory_mib, max_workers):
    """Unit's share divided by its suites' measured CPU-seconds.

    Each part (a parallel suite, or the pool of serial suites) runs
    max(1, round(its CPU share x its workers per busy CPU)) workers: enough to
    keep its own share busy, since its workers wait part of the time, and no
    more. A parallel suite's xdist workers are also bounded by their services
    fitting half of unit's memory (1 is a serial run). The serial suites run
    in one pool, the heaviest first (run_within), whose slots are its share
    times its workers per busy CPU rounded up; the pool bounds how many run at
    once, so they do not all start together.

    Sized to its own share, a part never adds load beyond it: that is why this
    does not repeat vm-7b34f721, where two xdist suites ran 11 workers each
    beside the serial suites at about twice the CPUs.
    """
    parallel = [s for s in PARALLEL_SUITES if s in suites]
    serial = [s for s in suites if s not in parallel]
    weights = {s: suites[s] for s in parallel}
    if serial:
        weights["serial"] = sum(suites[s] for s in serial)
    share = proportional(cpus, weights)
    ratio = {part: workers_per_busy_cpu(weights[part], runs[part]) for part in weights}
    counts, bound = {}, {}
    for suite in parallel:
        wanted = min(workers(share[suite] * ratio[suite]), max_workers)
        count = 1
        for candidate in range(2, wanted + 1):
            if service_memory_mib(candidate) > memory_mib // 2:
                break
            count = candidate
        counts[suite] = count
        bound[suite] = count < wanted
    # The serial suites are independent of one another: rounding the pool down
    # to one slot would run them end to end, so it rounds up, at most one slot
    # (under one busy CPU) above its share.
    slots = max(1, math.ceil(share["serial"] * ratio["serial"])) if serial else 0
    return {
        "cpus": round(cpus, 2),
        "memory_mib": memory_mib,
        "shares": {name: round(value, 2) for name, value in share.items()},
        "workers_per_busy_cpu": {name: round(value, 3) for name, value in ratio.items()},
        "serial_slots": slots,
        "workers": counts,
        "memory_bound": bound,
        "cpu_seconds": dict(suites),
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
    """GATE_CPUS and GATE_MEMORY_MIB when given, each measured otherwise.

    A release passes its gate's proportional CPU share, which may be
    fractional (GATE_CPUS=5.37); memory is whole MiB.
    """
    given = {}
    for name, pattern in (
        ("GATE_CPUS", r"[0-9]+(\.[0-9]+)?"),
        ("GATE_MEMORY_MIB", r"[1-9][0-9]*"),
    ):
        value = environ.get(name, "")
        if value and not (re.fullmatch(pattern, value) and float(value) > 0):
            raise ValueError(f"{name} must be a positive number, not {value!r}")
        if value:
            given[name] = float(value) if "." in value else int(value)
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

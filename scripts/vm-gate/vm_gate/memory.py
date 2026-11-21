#!/usr/bin/env python3
"""Sample host/cgroup memory, retaining partial reads and their exact context."""

import json
import signal
import subprocess
import sys
import time
from pathlib import Path

FIELDS = (
    "memory.current",
    "memory.peak",
    "memory.swap.current",
    "memory.events",
    "cpu.stat",
    "cpu.max",
    "cpuset.cpus.effective",
)
alive = True


def stop(*_):
    global alive
    alive = False


def cmd(args):
    return subprocess.check_output(args, text=True, timeout=10)


def read_error(cid, exc, pid=None, cgroup=None, filename=None):
    return {
        "id": cid,
        "type": type(exc).__name__,
        "pid": pid,
        "cgroup": cgroup,
        "filename": str(filename) if filename is not None else None,
        "errno": getattr(exc, "errno", None),
    }


def container_sample(cid, proc_root, cgroup_root):
    row = {"id": cid, "pid": None, "cgroup": None, "complete": False}
    errors = []
    filename = None
    try:
        d = json.loads(cmd(["docker", "inspect", cid]))[0]
        row.update(
            id=d["Id"],
            name=d["Name"],
            image=d["Config"]["Image"],
            labels=d["Config"].get("Labels"),
            pid=d["State"]["Pid"],
        )
        filename = proc_root / str(row["pid"]) / "cgroup"
        row["cgroup"] = next(
            line.split(":", 2)[2]
            for line in filename.read_text().splitlines()
            if line.startswith("0::")
        )
        root = cgroup_root / row["cgroup"].lstrip("/")
        for name in FIELDS:
            filename = root / name
            try:
                row[name] = filename.read_text().strip()
            except OSError as exc:
                errors.append(read_error(cid, exc, row["pid"], row["cgroup"], filename))
        filename = None
        row["host_config"] = {
            k: d["HostConfig"].get(k)
            for k in ("NetworkMode", "NanoCpus", "Memory", "PidsLimit")
        }
        row["complete"] = not errors
    except (
        OSError,
        ValueError,
        LookupError,
        StopIteration,
        TypeError,
        subprocess.SubprocessError,
    ) as exc:
        errors.append(read_error(cid, exc, row["pid"], row["cgroup"], filename))
    row.update(observed_time=time.time(), observed_monotonic=time.monotonic())
    return row, errors


def sample(proc_root=Path("/proc"), cgroup_root=Path("/sys/fs/cgroup")):
    record = {
        "time": time.time(),
        "monotonic": time.monotonic(),
        "containers": [],
        "containers_expected": None,
    }
    try:
        record["meminfo_kib"] = {
            k: int(v.strip().split()[0])
            for k, v in (
                line.split(":", 1)
                for line in (proc_root / "meminfo").read_text().splitlines()
            )
        }
        ids = cmd(["docker", "ps", "-q"]).split()
        record["containers_expected"] = len(ids)
        for cid in ids:
            if not alive:
                record["sampling_interrupted"] = True
                break
            row, errors = container_sample(cid, proc_root, cgroup_root)
            record["containers"].append(row)
            if errors:
                record.setdefault("container_errors", []).extend(errors)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        record["sample_error"] = type(exc).__name__
        record["sample_error_filename"] = getattr(exc, "filename", None)
    record["container_completeness"] = completeness(record)
    return record


def current_bytes(row):
    try:
        value = int(row["memory.current"])
        return value if value >= 0 else None
    except (KeyError, TypeError, ValueError):
        return None


def completeness(record):
    rows = record.get("containers", [])
    errors = record.get("container_errors", [])
    expected = record.get("containers_expected")
    source = "docker_ps"
    if "containers_expected" not in record:
        # Without a listed count, each recorded ID is a row or an error.
        ids = {row.get("id", f"row:{n}") for n, row in enumerate(rows)}
        for error in errors:
            cid = error.get("id")
            if cid and not any(i.startswith(cid) or cid.startswith(i) for i in ids):
                ids.add(cid)
        expected = None if record.get("sample_error") else len(ids)
        source = "recorded_rows_and_errors"
    elif expected is None:
        source = "unavailable"
    observed = sum(current_bytes(row) is not None for row in rows)
    fully_read = sum(row.get("complete", True) is True for row in rows)
    complete = (
        expected is not None
        and observed == expected
        and fully_read == expected
        and not errors
        and not record.get("sample_error")
        and not record.get("sampling_interrupted")
    )
    return {
        "expected": expected,
        "expected_source": source,
        "memory_current_read": observed,
        "fully_read": fully_read,
        "complete": complete,
    }


def summarize_samples(samples):
    valid = [s for s in samples if "meminfo_kib" in s and not s.get("sample_error")]
    coverage = [
        dict(sample=n, time=s.get("time"), **completeness(s))
        for n, s in enumerate(samples)
    ]
    peak = None
    for n, s in enumerate(samples):
        c = coverage[n]
        if not c["memory_current_read"] and c["expected"] != 0:
            continue
        total = sum(
            value
            for row in s.get("containers", [])
            if (value := current_bytes(row)) is not None
        )
        if peak is None or total > peak["bytes"]:
            expected = c["expected"] if c["expected"] is not None else "unknown"
            peak = dict(
                bytes=total,
                sample=n,
                time=s.get("time"),
                **completeness(s),
                label=f"lower bound, {c['memory_current_read']} of {expected} containers read",
            )
    return {
        "samples": len(samples),
        "valid": len(valid),
        "host_sample_errors": sum("sample_error" in s for s in samples),
        "container_read_errors": sum(
            len(s.get("container_errors", [])) for s in samples
        ),
        "host_sampled_used_peak_bytes": max(
            (
                (s["meminfo_kib"]["MemTotal"] - s["meminfo_kib"]["MemAvailable"]) * 1024
                for s in valid
            ),
            default=None,
        ),
        "concurrent_cgroup_current_peak_sum_bytes": peak["bytes"] if peak else None,
        "concurrent_cgroup_current_peak": peak,
        "sample_completeness": coverage,
    }


def load_samples(path):
    samples = []
    with path.open() as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise TypeError("sample is not an object")
            except (ValueError, TypeError) as exc:
                record = {
                    "sample_error": type(exc).__name__,
                    "sample_error_filename": str(path),
                    "sample_error_line": number,
                    "containers_expected": None,
                }
            samples.append(record)
    return samples


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with open(sys.argv[1], "a", buffering=1) as output:
        while alive:
            started = time.monotonic()
            output.write(json.dumps(sample()) + "\n")
            for _ in range(max(0, int((5 - (time.monotonic() - started)) * 10))):
                if not alive:
                    break
                time.sleep(0.1)


if __name__ == "__main__":
    main()

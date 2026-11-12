#!/usr/bin/env python3
"""5s whole-host sampling plus high-water cgroup v2 readings for living containers."""

import json, subprocess, time, signal, sys
from pathlib import Path

alive = True


def stop(*_):
    global alive
    alive = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)


def cmd(args):
    return subprocess.check_output(args, text=True, timeout=10)


with open(sys.argv[1], "a", buffering=1) as f:
    while alive:
        started = time.monotonic()
        record = {"time": time.time(), "monotonic": started}
        try:
            record["meminfo_kib"] = {
                k: int(v.strip().split()[0])
                for k, v in (
                    line.split(":", 1)
                    for line in Path("/proc/meminfo").read_text().splitlines()
                )
            }
            ids = cmd(["docker", "ps", "-q"]).split()
            record["containers"] = []
            for cid in ids:
                try:
                    d = json.loads(cmd(["docker", "inspect", cid]))[0]
                    pid = d["State"]["Pid"]
                    cg = next(
                        line.split(":", 2)[2]
                        for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()
                        if line.startswith("0::")
                    )
                    root = Path("/sys/fs/cgroup") / cg.lstrip("/")
                    row = {
                        "id": d["Id"],
                        "name": d["Name"],
                        "image": d["Config"]["Image"],
                        "labels": d["Config"].get("Labels"),
                        "pid": pid,
                        "cgroup": cg,
                    }
                    for name in (
                        "memory.current",
                        "memory.peak",
                        "memory.swap.current",
                        "memory.events",
                        "cpu.stat",
                        "cpu.max",
                        "cpuset.cpus.effective",
                    ):
                        row[name] = (root / name).read_text().strip()
                    row["host_config"] = {
                        k: d["HostConfig"].get(k)
                        for k in ["NetworkMode", "NanoCpus", "Memory", "PidsLimit"]
                    }
                    row["observed_time"] = time.time()
                    row["observed_monotonic"] = time.monotonic()
                    record["containers"].append(row)
                except Exception as exc:
                    record.setdefault("container_errors", []).append(
                        {"id": cid, "type": type(exc).__name__}
                    )
        except Exception as exc:
            record["sample_error"] = type(exc).__name__
        f.write(json.dumps(record) + "\n")
        # A removed container may disappear between listing and reading; retain the race explicitly.
        for _ in range(max(0, int((5 - (time.monotonic() - started)) * 10))):
            if not alive:
                break
            time.sleep(0.1)

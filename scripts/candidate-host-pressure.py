#!/usr/bin/env python3
"""Keep macOS kernel-file counts distinct from Docker VM lsof rows."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import re
import subprocess
import time


def command(*argv: str) -> str:
    return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE, timeout=30)


def lsof_counts(raw: str) -> tuple[int, int]:
    lines = raw.splitlines()
    if not lines or not lines[0].startswith("COMMAND"):
        raise ValueError("lsof output has no header; refusing an unknown count")
    rows = [line for line in lines[1:] if line.strip()]
    numeric = sum(len(parts := line.split()) > 3 and bool(re.fullmatch(r"\d+[rwu]?", parts[3])) for line in rows)
    return len(rows), numeric


def _capture(destination: Path) -> dict:
    result = {"timestamp": datetime.now(timezone.utc).isoformat(), "platform": platform.system()}
    if result["platform"] != "Darwin":
        result["status"] = "not_applicable"
    else:
        raw_kernel = command("sysctl", "-n", "kern.num_files")
        destination.with_suffix(".kernel.txt").write_text(raw_kernel)
        processes = command("ps", "-axo", "pid=,comm=")
        destination.with_suffix(".processes.txt").write_text(processes)
        pids = [int(parts[0]) for line in processes.splitlines()
                if len(parts := line.strip().split(None, 1)) == 2
                and Path(parts[1]).name in {"com.docker.virtualization", "com.docker.hyperkit"}]
        if not pids:
            raise RuntimeError("Docker VM process not found; cannot measure recovery")
        rows = numeric = 0
        for pid in pids:
            raw = command("lsof", "-nP", "-p", str(pid))
            destination.with_suffix(f".vm-{pid}.lsof.txt").write_text(raw)
            count, fd_count = lsof_counts(raw)
            rows += count
            numeric += fd_count
        result.update(status="measured", vm_pids=sorted(pids), **{
            "kern.num_files": int(raw_kernel.strip()), "vm_lsof_rows": rows,
            "vm_numeric_fd_rows": numeric,
        })
    destination.write_text(json.dumps(result, indent=2) + "\n")
    return result


def capture(destination: Path) -> dict:
    try:
        return _capture(destination)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result = {"timestamp": datetime.now(timezone.utc).isoformat(),
                  "platform": platform.system(), "status": "unavailable", "error": str(exc)}
        destination.write_text(json.dumps(result, indent=2) + "\n")
        raise


def compare(before: dict, after: dict) -> dict:
    if before.get("platform") != after.get("platform"):
        raise ValueError("platform changed between measurements")
    if before.get("status") == after.get("status") == "not_applicable":
        return {"status": "not_applicable", "platform": before["platform"]}
    if before.get("status") != "measured" or after.get("status") != "measured":
        raise ValueError("incomplete host-pressure measurements")
    # A VM restart changes the measuring subject. Recovery requires an explicit
    # operator receipt, not an automatic passing comparison to a new process.
    same_vm = before["vm_pids"] == after["vm_pids"]
    deltas = {key: after[key] - before[key] for key in ("kern.num_files", "vm_lsof_rows", "vm_numeric_fd_rows")}
    return {"status": "passed" if same_vm and all(deltas[k] <= 5000 for k in ("kern.num_files", "vm_lsof_rows")) else "failed",
            "same_vm": same_vm, "deltas": deltas, "bounds": {"kern.num_files": 5000, "vm_lsof_rows": 5000}}


def settle(before_path: Path, directory: Path) -> dict:
    """Retain up to four observations with fifteen-second waits between them."""
    before = json.loads(before_path.read_text())
    samples = []
    for attempt in range(1, 5):
        if attempt > 1:
            time.sleep(15)
        sample_path = directory / f"host-after-{attempt}.json"
        try:
            after = capture(sample_path)
            result = compare(before, after)
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            result = {"status": "failed", "error": str(exc)}
        samples.append({"sample": attempt, "path": sample_path.name, **result})
        # Stable alias for evidence consumers; the numbered raw samples remain.
        if sample_path.exists():
            (directory / "host-after.json").write_bytes(sample_path.read_bytes())
        if result["status"] in {"passed", "not_applicable"}:
            break
    receipt = {**result, "samples": samples,
               "passed_sample": attempt if result["status"] == "passed" else None}
    (directory / "host-recovery.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["capture", "compare", "settle"])
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    if args.operation == "capture":
        capture(Path(args.paths[0]))
        return 0
    if args.operation == "settle":
        before, directory = map(Path, args.paths)
        result = settle(before, directory)
        print(json.dumps(result))
        return int(result["status"] == "failed")
    before, after, output = map(Path, args.paths)
    try:
        result = compare(json.loads(before.read_text()), json.loads(after.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"status": "failed", "error": str(exc)}
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return int(result["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())

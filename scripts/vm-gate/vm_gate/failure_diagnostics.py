"""Bounded, read-only guest evidence for image/daemon/storage failures."""

import argparse
import json
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

Runner = Callable[..., subprocess.CompletedProcess[str]]
OUTPUT_LIMIT = 256 * 1024


def text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


def capture(
    *, source: str, run_id: str, phase: str, runner: Runner = subprocess.run
) -> dict:
    deadline = time.monotonic() + 10
    results = []

    def observe(name: str, argv: list[str]) -> dict:
        left = deadline - time.monotonic()
        row = {
            "name": name,
            "argv": argv,
            "started_utc": datetime.now(UTC).isoformat(),
            "exit": None,
        }
        began = time.monotonic()
        if left <= 0:
            row.update(status="NOT_RUN_BUDGET", stdout="", stderr="")
        else:
            try:
                result = runner(
                    argv,
                    text=True,
                    capture_output=True,
                    timeout=min(2, left),
                    check=False,
                )
                row.update(
                    exit=result.returncode,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    timed_out=False,
                )
            except subprocess.TimeoutExpired as error:
                row.update(
                    stdout=text(error.stdout),
                    stderr=text(error.stderr),
                    timed_out=True,
                    error="TimeoutExpired",
                )
            except OSError as error:
                row.update(
                    stdout="",
                    stderr=str(error),
                    timed_out=False,
                    error=type(error).__name__,
                )
        row["wall_seconds"] = round(time.monotonic() - began, 6)
        for field in ("stdout", "stderr"):
            data = text(row[field]).encode()
            row[field + "_bytes"] = len(data)
            row[field + "_truncated"] = len(data) > OUTPUT_LIMIT
            row[field] = data[-OUTPUT_LIMIT:].decode(errors="replace")
        results.append(row)
        return row

    root_result = observe(
        "docker-root", ["docker", "info", "--format", "{{json .DockerRootDir}}"]
    )
    root = None
    if root_result["exit"] == 0:
        try:
            candidate = json.loads(root_result["stdout"])
            if isinstance(candidate, str) and candidate.startswith("/"):
                root = candidate
        except ValueError:
            pass  # Unresolved Docker root stays explicit; never assume /var/lib/docker.
    observe(
        "daemon-state",
        [
            "systemctl",
            "show",
            "docker.service",
            "containerd.service",
            "--no-pager",
            "--property=Id,ActiveState,SubState,MainPID,ExecMainCode,ExecMainStatus,NRestarts,ExecMainStartTimestamp,ExecMainExitTimestamp",
        ],
    )
    observe(
        "daemon-journal",
        [
            "journalctl",
            "--no-pager",
            "-b",
            "-u",
            "docker.service",
            "-u",
            "containerd.service",
            "-n",
            "2000",
            "-o",
            "short-iso-precise",
        ],
    )
    observe(
        "kernel-journal",
        [
            "journalctl",
            "--no-pager",
            "-b",
            "-k",
            "-n",
            "2000",
            "-o",
            "short-iso-precise",
        ],
    )
    observe("kernel-ring", ["dmesg", "--time-format", "iso", "--color=never"])
    if root is not None:
        observe("docker-root-bytes", ["df", "-P", "-B1", "--", root])
        observe("docker-root-inodes", ["df", "-Pi", "--", root])
        observe(
            "docker-root-mount",
            ["findmnt", "-T", root, "--json", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"],
        )
    observe(
        "block-devices",
        ["lsblk", "-b", "-J", "-o", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS"],
    )
    observe("memory", ["cat", "/proc/meminfo", "/proc/vmstat"])
    return {
        "source": source,
        "run_id": run_id,
        "phase": phase,
        "captured_utc": datetime.now(UTC).isoformat(),
        "docker_root": root,
        "commands": results,
        "status": "complete"
        if root is not None
        and all(
            row["exit"] == 0
            and not row["stdout_truncated"]
            and not row["stderr_truncated"]
            for row in results
        )
        else "partial",
        "scope": "read-only guest diagnostics; bounded command/tail coverage, not a diagnosis or product verdict",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "run-id", "phase", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    value = capture(source=args.source, run_id=args.run_id, phase=args.phase)
    try:
        Path(args.output).write_text(json.dumps(value, indent=2) + "\n")
    except OSError as error:
        value["output_error"] = {"type": type(error).__name__, "message": str(error)}
    # The pinned SSH caller retains these same bytes locally even on a full guest disk.
    print(json.dumps(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Fail-closed selection of a gate's cleanup-bearing Bash descendant."""

import os
import shlex
import signal
from pathlib import Path


def cleanup_wrapper(rows, make_pid, *, uid, cwd):
    """Select one complete Bash chain under this exact owned Make process.

    A fixed depth is not an identity: the observed gate has three Bash levels.
    Missing ancestry, branching wrappers or incomplete process evidence refuses.
    Callers must freshly re-read and compare start_time before sending a signal.
    """
    if any(
        type(row.get("pid")) is not int
        or row["pid"] <= 0
        or type(row.get("ppid")) is not int
        or row["ppid"] < 0
        for row in rows
    ):
        return None
    by_pid = {row["pid"]: row for row in rows}
    if len(by_pid) != len(rows):
        return None
    root = by_pid.get(make_pid)

    def owned(row):
        return (
            row
            and row.get("uid") == uid
            and row.get("cwd") == cwd
            and type(row.get("start_time")) is int
            and row["start_time"] > 0
        )

    def argv(row):
        try:
            return shlex.split(row.get("command", ""))
        except ValueError:
            return []

    if not owned(root) or argv(root) != ["make", "candidate-gate"]:
        return None
    descendants = {make_pid}
    while True:
        expanded = descendants | {
            row["pid"] for row in rows if row["ppid"] in descendants
        }
        if expanded == descendants:
            break
        descendants = expanded
    wrappers = {}
    for pid in descendants - {make_pid}:
        row = by_pid[pid]
        args = argv(row)
        if "scripts/candidate-docker-gate.sh" not in row.get("command", ""):
            continue
        if (
            len(args) != 2
            or Path(args[0]).name != "bash"
            or args[1]
            not in [
                "scripts/candidate-docker-gate.sh",
                cwd + "/scripts/candidate-docker-gate.sh",
            ]
            or not owned(row)
        ):
            return None
        wrappers[pid] = row
    chain = []
    parent = make_pid
    while True:
        children = [row for row in wrappers.values() if row["ppid"] == parent]
        if not children:
            break
        if len(children) != 1:
            return None
        child = children[0]
        if child["pid"] in chain:
            return None
        chain.append(child["pid"])
        parent = child["pid"]
    if len(chain) < 2 or set(chain) != set(wrappers):
        return None
    leaf = wrappers[chain[-1]]
    return leaf if leaf.get("term_caught") is True else None


def read_process(pid, proc_root=Path("/proc")):
    """Linux evidence, including start time to detect PID reuse at recheck."""
    path = proc_root / str(pid)
    try:
        fields = dict(
            line.split(":", 1)
            for line in (path / "status").read_text().splitlines()
            if ":" in line
        )
        stat = (path / "stat").read_text().rsplit(") ", 1)[1].split()
        return {
            "pid": pid,
            "ppid": int(fields["PPid"]),
            "uid": int(fields["Uid"].split()[0]),
            "cwd": os.readlink(path / "cwd"),
            "start_time": int(stat[19]),
            "term_caught": bool(
                int(fields["SigCgt"].strip(), 16) & (1 << (signal.SIGTERM - 1))
            ),
            "command": (path / "cmdline")
            .read_bytes()
            .replace(b"\0", b" ")
            .decode(errors="replace"),
        }
    except (OSError, ValueError, KeyError, IndexError):
        return None

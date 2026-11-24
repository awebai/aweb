"""Spool the guest's container runtime, package updater and service manager journal through evidence collection."""

import fcntl
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

SPOOL = Path("/opt/vm-gate/daemon-journal")
UNITS = (
    "docker.service", "containerd.service", "dbus.service", "dbus-broker.service",
    "apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service",
    "apt-daily-upgrade.service", "unattended-upgrades.service",
)


def drain(directory, *, finish=False):
    directory.mkdir(mode=0o700, exist_ok=True)
    checkpoint = directory / "checkpoint.json"
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        saved = json.loads(checkpoint.read_text()) if checkpoint.exists() else {}
        stop = directory / "stop"
        if finish:
            stop.touch()
        if saved.get("finished") or (stop.exists() and not finish):
            return True
        # journalctl updates this cursor when the query ends. Commit it together
        # with the byte offset so an interrupted append can be replayed exactly.
        cursor = directory / "query.cursor"
        if saved.get("cursor"):
            cursor.write_text(saved["cursor"])
        else:
            cursor.unlink(missing_ok=True)
        command = [
            "journalctl",
            "--boot",
            "--no-pager",
            "--quiet",
            "--all",
            "--output=short-iso-precise",
            f"--cursor-file={cursor}",
        ]
        # A manager-wide PID 1 match must be ORed with service entries.
        # It includes daemon re-exec and transient-scope events between restarts.
        command.append("_PID=1")
        for unit in UNITS:
            for field in ("_SYSTEMD_UNIT", "UNIT", "OBJECT_SYSTEMD_UNIT", "COREDUMP_UNIT"):
                command.extend(["+", f"{field}={unit}"])
        with (
            (directory / "daemon.log").open("ab") as log,
            (directory / "errors.log").open("ab") as errors,
        ):
            log.truncate(saved.get("bytes", 0))
            log.seek(0, 2)
            subprocess.run(command, stdout=log, stderr=errors, check=True, timeout=30)
            log.flush()
            observed = datetime.now(UTC).isoformat()
            state = {
                "bytes": log.tell(),
                "cursor": cursor.read_text() if cursor.exists() else "",
                "first_read_utc": saved.get("first_read_utc", observed),
                "last_read_utc": observed,
                "finished": finish,
            }
        tmp = checkpoint.with_suffix(".tmp")
        tmp.write_text(json.dumps(state) + "\n")
        tmp.replace(checkpoint)
        return finish


def main():
    finish = sys.argv[1] == "finish"
    while True:
        try:
            if drain(SPOOL, finish=finish):
                return
        except (OSError, subprocess.SubprocessError) as error:
            if finish:
                raise
            print(error, file=sys.stderr, flush=True)
        time.sleep(10)


if __name__ == "__main__":
    main()

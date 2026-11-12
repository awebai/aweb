"""Retain stock-host initialization diagnostics; unknown warnings refuse."""

import base64
import json
from pathlib import Path
import re
import subprocess
import sys

from .errors import Refused

# Add an exact (category, message) only after review of an observed diagnostic.
REVIEWED_RECOVERABLE_ERRORS = frozenset()
MARKER = "VM_GATE_CLOUD_INIT_DIAGNOSTICS="
FILES = (
    "wait.stdout",
    "wait.stderr",
    "status.json",
    "status.stderr",
    "warnings.log",
    "observation.json",
)


def admit_status(status, status_exit, wait_exit, allowlist):
    if not isinstance(status, dict) or status.get("status") != "done":
        raise Refused("cloud-init did not finish with status done")
    if status_exit not in {0, 2} or wait_exit not in {0, 2}:
        raise Refused("cloud-init failed or returned an unknown exit status")
    recoverable = set()
    for part in [status] + [
        status[key]
        for key in ("init-local", "init", "modules-config", "modules-final")
        if key in status
    ]:
        if not isinstance(part, dict) or part.get("errors") or part.get("error"):
            raise Refused("cloud-init reports initialization errors")
        groups = part.get("recoverable_errors", {})
        if not isinstance(groups, dict):
            raise Refused("cloud-init recoverable errors have an unknown format")
        for category, messages in groups.items():
            if (
                not isinstance(category, str)
                or not isinstance(messages, list)
                or not all(isinstance(x, str) for x in messages)
            ):
                raise Refused("cloud-init recoverable errors have an unknown format")
            recoverable.update((category, message) for message in messages)
    if recoverable - set(allowlist):
        raise Refused(
            "cloud-init has unreviewed recoverable errors; diagnostics retained"
        )
    if (status_exit == 2 or wait_exit == 2) and not recoverable:
        raise Refused("cloud-init recoverable exit has no recognized explanation")
    return sorted(recoverable)


def observe_and_admit(
    directory, *, run=subprocess.run, warning_log=Path("/var/log/cloud-init.log")
):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = {"admitted": False}

    def write(name, text):
        path = directory / name
        path.write_text(text)
        path.chmod(0o600)

    try:
        wait = run(
            ["cloud-init", "status", "--wait"],
            capture_output=True,
            text=True,
            timeout=600,
        )
        record["wait_exit"] = wait.returncode
        write("wait.stdout", wait.stdout)
        write("wait.stderr", wait.stderr)
        detailed = run(
            ["cloud-init", "status", "--long", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        record["status_exit"] = detailed.returncode
        write("status.json", detailed.stdout)
        write("status.stderr", detailed.stderr)
        log = Path(warning_log).read_text(errors="replace")
        write(
            "warnings.log",
            "\n".join(
                line
                for line in log.splitlines()
                if re.search(r"warn|error|deprecated", line, re.I)
            )
            + "\n",
        )
        record["diagnostics_retained"] = True
        # Persist before parsing or deciding; malformed JSON is also retained.
        write("observation.json", json.dumps(record, indent=2) + "\n")
        try:
            status = json.loads(detailed.stdout)
        except ValueError:
            raise Refused("cloud-init detailed status is invalid JSON") from None
        record["allowed_errors"] = admit_status(
            status, detailed.returncode, wait.returncode, REVIEWED_RECOVERABLE_ERRORS
        )
        record["admitted"] = True
        return record
    except BaseException as exc:
        record["refusal"] = str(exc)
        raise
    finally:
        write("observation.json", json.dumps(record, indent=2) + "\n")


def main():
    directory = Path(sys.argv[1])
    try:
        observe_and_admit(directory)
        return 0
    except Refused as exc:
        print(str(exc), file=sys.stderr)
        return 78
    finally:
        # The root command's private stdout is saved locally even when the
        # subsequent admission refuses, before the VM is deleted.
        bundle = {
            name: (directory / name).read_text()
            for name in FILES
            if (directory / name).is_file()
        }
        print(
            MARKER + base64.b64encode(json.dumps(bundle).encode()).decode(), flush=True
        )


if __name__ == "__main__":
    raise SystemExit(main())

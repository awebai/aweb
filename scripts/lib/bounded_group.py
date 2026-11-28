"""Run a command in its own process group, owning the group until it is gone.

    bounded_group.py --seconds N --verdict FILE -- COMMAND...

One monotonic deadline covers the command and every process it leaves in its
group. On every exit path (the group finished, the deadline passed, or this
runner was interrupted by SIGINT, SIGTERM or SIGHUP) the group is killed and
observed empty before the runner returns. Then:

- the group finished in time: exit with the leader's status;
- the deadline passed: exit TIMEOUT_EXIT with a "bounded_group: TIMEOUT"
  diagnostic;
- interrupted: die of the same signal.

The verdict file records which ("exit N", "timeout", "interrupted SIGNAME").
Only this runner writes it, so a command that happens to exit TIMEOUT_EXIT
is not taken for a timeout.
"""

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

TIMEOUT_EXIT = 254
# How long a killed group may take to be reaped before the runner fails.
REAP_SECONDS = 10


class Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def interrupt(signum, frame):
    raise Interrupted(signum)


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # macOS answers EPERM for a group whose last members are zombies
        # awaiting their new parent.
        return True
    return True


def wait_for_empty_group(pgid, until):
    while group_present(pgid):
        if time.monotonic() >= until:
            return False
        time.sleep(0.02)
    return True


def end_group(child):
    """Kill the child's group, reap the child, and observe the group empty."""
    pgid = child.pid
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    # The leader stays in its group as a zombie until it is reaped here.
    child.wait()
    if not wait_for_empty_group(pgid, time.monotonic() + REAP_SECONDS):
        raise SystemExit(f"bounded_group: process group {pgid} survived SIGKILL")


def run(seconds, argv):
    """Return the verdict: ("exit", status), ("timeout", None) or ("interrupted", signum)."""
    deadline = time.monotonic() + seconds
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupt)
    child = None
    try:
        child = subprocess.Popen(argv, start_new_session=True)
        try:
            status = child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return ("timeout", None)
        if not wait_for_empty_group(child.pid, deadline):
            return ("timeout", None)
        return ("exit", status if status >= 0 else 128 - status)
    except KeyboardInterrupt:
        return ("interrupted", signal.SIGINT)
    except Interrupted as exc:
        return ("interrupted", exc.signum)
    finally:
        # Interruptions arriving during cleanup wait for it.
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, signal.SIG_IGN)
        if child is not None:
            end_group(child)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seconds", type=float, required=True)
    parser.add_argument("--verdict", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not argv:
        parser.error("a command is required after --")
    kind, value = run(args.seconds, argv)
    if kind == "exit":
        args.verdict.write_text(f"exit {value}\n")
        sys.exit(value)
    if kind == "timeout":
        args.verdict.write_text("timeout\n")
        print(
            f"bounded_group: TIMEOUT after {args.seconds:g} s: {argv[0]}; its process group was killed",
            file=sys.stderr,
        )
        sys.exit(TIMEOUT_EXIT)
    name = signal.Signals(value).name
    args.verdict.write_text(f"interrupted {name}\n")
    print(
        f"bounded_group: interrupted by {name}; its process group was killed",
        file=sys.stderr,
    )
    signal.signal(value, signal.SIG_DFL)
    os.kill(os.getpid(), value)


if __name__ == "__main__":
    main()

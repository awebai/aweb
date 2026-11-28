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
POLL_SECONDS = 0.02
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


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


def end_group(child):
    """Kill the child's group, reap the child, and observe the group empty.

    Once the group is observed empty its number is never used again.
    """
    pgid = child.pid
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    # The leader stays in its group as a zombie until it is reaped here.
    child.wait()
    until = time.monotonic() + REAP_SECONDS
    while group_present(pgid):
        if time.monotonic() >= until:
            raise SystemExit(f"bounded_group: process group {pgid} survived SIGKILL")
        time.sleep(POLL_SECONDS)


def run(seconds, argv):
    """Return the verdict: ("exit", status), ("timeout", None) or ("interrupted", signum).

    The stop signals only record themselves; nothing unwinds asynchronously.
    The loop acts on a recorded stop between steps, so launch, ownership and
    release are never interrupted halfway. A stop at any point, cleanup
    included, makes the verdict "interrupted".
    """
    deadline = time.monotonic() + seconds
    stops = []
    previous = {
        signum: signal.signal(signum, lambda signum, frame: stops.append(signum))
        for signum in STOP_SIGNALS
    }
    try:
        child = subprocess.Popen(argv, start_new_session=True)
        owned = True
        status = None
        verdict = None
        while verdict is None:
            if stops:
                verdict = ("interrupted", stops[0])
                break
            if status is None:
                status = child.poll()
            if status is not None and not group_present(child.pid):
                # Observed empty: the group is released, and its number is
                # never signalled or probed again.
                owned = False
                verdict = ("exit", status if status >= 0 else 128 - status)
                break
            if time.monotonic() >= deadline:
                verdict = ("timeout", None)
                break
            time.sleep(POLL_SECONDS)
        if owned:
            end_group(child)
        if stops and verdict[0] != "interrupted":
            verdict = ("interrupted", stops[0])
        return verdict
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


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

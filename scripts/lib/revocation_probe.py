#!/usr/bin/env python3
"""The OSS journey's revocation probe: after a member's removal, poll its sends
until the healthy server refuses them, inside the revocation window.

    revocation_probe.py --dir D --anchor-ms A --window W --cwd C -- ARGV...

ARGV is the send command; the probe appends each attempt's subject. Times are
milliseconds on the monotonic clock, which every process on the host shares,
and A is the moment the removal succeeded. A refusal counts only when its
attempt completed by A + (W + 5) s. Each attempt runs with the budget that
remains as its timeout, so the runtime ends and reaps an attempt that would
outlive the window. D/verdict ends as refused, late or accepted; the probe
exits 0 only for refused.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import time

PAUSE_SECONDS = 5.0


def monotonic_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def probe(directory, anchor_ms, window, send, *, clock=monotonic_ms, pause=time.sleep):
    """send(n, timeout_seconds) runs attempt n and returns (exit_status, stdout),
    or None when it was ended at its timeout."""
    directory = Path(directory)
    deadline = anchor_ms + (window + 5) * 1000

    def record(verdict, now=None):
        if now is not None:
            (directory / "elapsed-ms").write_text(f"{now - anchor_ms}\n")
        (directory / "verdict").write_text(verdict + "\n")
        return verdict

    n = 0
    while True:
        now = clock()
        if now >= deadline:
            return record("accepted", now)
        n += 1
        result = send(n, (deadline - now) / 1000)
        now = clock()
        if result is None or now > deadline:
            return record("late", now)
        status, output = result
        if status != 0:
            (directory / "refused-subject").write_text(f"after-revocation-{n}\n")
            (directory / "refusal.json").write_bytes(output)
            return record("refused", now)
        pause(min(PAUSE_SECONDS, (deadline - now) / 1000))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--anchor-ms", required=True, type=int)
    parser.add_argument("--window", required=True, type=int)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("command", nargs="+")
    args = parser.parse_args(argv)

    def send(n, timeout):
        try:
            completed = subprocess.run(
                [*args.command, f"after-revocation-{n}"],
                cwd=args.cwd,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return None
        (args.dir / "stderr").write_bytes(completed.stderr)
        return completed.returncode, completed.stdout

    verdict = probe(args.dir, args.anchor_ms, args.window, send)
    print(verdict)
    return 0 if verdict == "refused" else 1


if __name__ == "__main__":
    sys.exit(main())

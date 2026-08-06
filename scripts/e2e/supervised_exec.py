#!/usr/bin/env python3
"""Wait for the supervisor's durable-plan handoff, then exec the runner."""

from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        raise ValueError("usage: supervised_exec.py <gate-fd> -- <command> [args...]")
    gate_fd = int(sys.argv[1])
    try:
        release = os.read(gate_fd, 1)
    finally:
        os.close(gate_fd)
    if release != b"1":
        return 125
    os.execvpe(sys.argv[3], sys.argv[3:], os.environ)
    raise AssertionError("exec returned")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"REFUSE: {error}", file=sys.stderr)
        raise SystemExit(125)

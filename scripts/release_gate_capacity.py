#!/usr/bin/env python3
"""Fixed Docker-filesystem capacity policy for the complete local gate."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# The failed 13d3bce7 run consumed the 2.8 GiB reclaimed from its exact task
# images before row 34 exhausted the daemon filesystem. Twelve GiB retains that
# measured lower bound plus 9.2 GiB for the remaining journeys and fixed margin.
START_REQUIRED_KIB = 12 * 1024 * 1024
BETWEEN_REQUIRED_KIB = 2 * 1024 * 1024


@dataclass(frozen=True)
class Capacity:
    phase: str
    required_kib: int
    available_kib: int

    @property
    def sufficient(self) -> bool:
        return self.available_kib >= self.required_kib

    def message(self) -> str:
        state = "sufficient" if self.sufficient else "insufficient"
        return (
            f"Docker daemon filesystem capacity {state} ({self.phase}): "
            f"required_kib={self.required_kib} available_kib={self.available_kib}"
        )


def available_kib(path: str = "/") -> int:
    stats = os.statvfs(path)
    return stats.f_bavail * stats.f_frsize // 1024


def measure(phase: str) -> Capacity:
    required = {
        "start": START_REQUIRED_KIB,
        "between": BETWEEN_REQUIRED_KIB,
    }.get(phase)
    if required is None:
        raise ValueError(f"unknown capacity phase: {phase}")
    return Capacity(phase, required, available_kib())


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"start", "between"}:
        print("usage: release_gate_capacity.py start|between", file=sys.stderr)
        return 2
    result = measure(sys.argv[1])
    print(result.message(), file=sys.stdout if result.sufficient else sys.stderr)
    return 0 if result.sufficient else 1


if __name__ == "__main__":
    raise SystemExit(main())

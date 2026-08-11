#!/usr/bin/env python3
"""Reject tracked remnants of the deleted comprehensive hosted gate."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Iterable

# Constructed here so the detector does not have to exclude its own source.
# The focused protective test carries each complete literal and mutation-proves it.
FORBIDDEN = (
    "ship" + ".yml",
    "run-" + "ship-suites.sh",
    "ship-" + "env.sh",
    "SHIP" + "_SUITES",
    "ship-" + "suites:",
    "check-" + "ship-invocation:",
    "check-" + "ship-owner:",
    "ship-" + "gate:",
    "ship" + ":",
    "make " + "ship",
    "release-all-" + "check",
)

PRODUCTION_EXCLUSIONS = frozenset(
    {
        "docs/release.md",  # authoritative migration specification
        "docs/runnerless-release.md",  # superseded history, deleted by task .10
        "release-gate/suite-map.tsv",  # temporary old-to-new authority until task .10
        "scripts/e2e/test_release_local_gate_contract.py",  # protective literals
    }
)


def tracked_files(root: Path) -> tuple[str, ...]:
    output = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=root, text=False
    )
    return tuple(item.decode("utf-8") for item in output.split(b"\0") if item)


def find_residue(
    root: Path, excluded: Iterable[str] = PRODUCTION_EXCLUSIONS
) -> list[tuple[str, str]]:
    excluded_set = set(excluded)
    findings: list[tuple[str, str]] = []
    for relative in tracked_files(root):
        if relative in excluded_set:
            continue
        path = root / relative
        if not path.is_file():
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for literal in FORBIDDEN:
            if literal == "ship:" and relative != "Makefile":
                continue
            if literal in body:
                findings.append((relative, literal))
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings = find_residue(root)
    if findings:
        for path, literal in findings:
            print(f"release-gate residue: {path}: {literal}", file=sys.stderr)
        return 1
    print(f"release-gate residue clean ({len(FORBIDDEN)} literals)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

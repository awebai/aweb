#!/usr/bin/env python3
"""Run the fixed local release-gate steps independently with durable logs."""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class MapError(RuntimeError):
    pass


@dataclass(frozen=True)
class Step:
    name: str
    category: str
    target: str
    disposition: str
    old_targets: str


CATEGORIES = {"contract", "unit", "artifact", "journey", "audit", "migration"}
DISPOSITIONS = {"run", "task-6", "task-10-delete", "replaced-wrapper"}


def load_map(path: Path) -> tuple[Step, ...]:
    rows: list[Step] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for number, row in enumerate(
            csv.reader(
                (line for line in handle if not line.startswith("#")), delimiter="\t"
            ),
            1,
        ):
            if not row:
                continue
            if len(row) != 5 or any(not value or value != value.strip() for value in row):
                raise MapError(f"suite-map row {number} must have five trimmed fields")
            step = Step(*row)
            if step.category not in CATEGORIES:
                raise MapError(f"suite-map row {number} has unknown category {step.category}")
            if step.disposition not in DISPOSITIONS:
                raise MapError(
                    f"suite-map row {number} has unknown disposition {step.disposition}"
                )
            if (step.disposition == "run") == (step.category == "migration"):
                raise MapError(
                    f"suite-map row {number} has inconsistent category/disposition"
                )
            old_targets = step.old_targets.split(",")
            if any(not target or target != target.strip() for target in old_targets):
                raise MapError(f"suite-map row {number} has malformed old targets")
            rows.append(step)
    if not rows:
        raise MapError("suite map is empty")
    names = [step.name for step in rows]
    targets = [step.target for step in rows]
    if len(set(names)) != len(names):
        raise MapError("suite map has duplicate step names")
    if len(set(targets)) != len(targets):
        raise MapError("suite map has duplicate make targets")
    old_targets = [
        target
        for step in rows
        for target in step.old_targets.split(",")
        if target != "-"
    ]
    if len(set(old_targets)) != len(old_targets):
        raise MapError("suite map has duplicate old comprehensive-gate targets")
    return tuple(rows)


def write_summary(path: Path, steps: Sequence[Step], states: dict[str, str]) -> None:
    body = "".join(f"{step.name}\t{states[step.name]}\t{step.category}\t{step.target}\n" for step in steps)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(body, encoding="utf-8")
    os.replace(temporary, path)


def run(map_path: Path, log_dir: Path, command_prefix: Sequence[str]) -> int:
    if not command_prefix or any(not item for item in command_prefix):
        raise MapError("make command prefix is empty")
    all_steps = load_map(map_path)
    steps = tuple(step for step in all_steps if step.disposition == "run")
    log_dir.mkdir(parents=True, exist_ok=True)
    states = {step.name: "NOT RUN" for step in steps}
    summary = log_dir / "summary.tsv"
    write_summary(summary, steps, states)
    failed = False
    try:
        for index, step in enumerate(steps, 1):
            print(f"\n=== release gate {index}/{len(steps)}: {step.name} ({step.target}) ===", flush=True)
            log_path = log_dir / f"{index:02d}-{step.name}.log"
            with log_path.open("wb") as log:
                completed = subprocess.run(
                    [*command_prefix, step.target],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
            states[step.name] = "PASSED" if completed.returncode == 0 else "FAILED"
            failed = failed or completed.returncode != 0
            write_summary(summary, steps, states)
            print(f"=== {step.name}: {states[step.name]} (log {log_path}) ===", flush=True)
    finally:
        write_summary(summary, steps, states)
        print("\n=== release gate summary ===")
        for step in steps:
            print(f"  {states[step.name]:7s} {step.name}")
        not_run = sum(state == "NOT RUN" for state in states.values())
        failures = sum(state == "FAILED" for state in states.values())
        print(f"  ----\n  {failures} failed, {not_run} not run, {len(steps) - failures - not_run} passed")
    return 1 if failed or any(state == "NOT RUN" for state in states.values()) else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--make", default="make")
    args = parser.parse_args(argv)
    try:
        return run(args.map, args.log_dir, [args.make])
    except (MapError, OSError) as error:
        print(f"release gate refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

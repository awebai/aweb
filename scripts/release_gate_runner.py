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
from typing import Callable, Sequence

import release_gate_capacity as capacity


class MapError(RuntimeError):
    pass


class InfrastructureError(RuntimeError):
    pass


def verify_checkout(
    expected_root: Path | None = None,
    expected_sha: str | None = None,
) -> None:
    if expected_root is None:
        root_value = os.environ.get("RELEASE_GATE_CHECKOUT_ROOT")
        expected_root = Path(root_value) if root_value else Path.cwd()
    if expected_sha is None:
        expected_sha = os.environ.get("RELEASE_GATE_SOURCE_SHA")
    try:
        expected = expected_root.resolve(strict=True)
        actual = Path.cwd().resolve(strict=True)
        completed = subprocess.run(
            ["git", "-C", str(expected), "rev-parse", "--show-toplevel", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, RuntimeError) as error:
        raise InfrastructureError(f"checkout is unavailable: {error}") from error
    lines = completed.stdout.splitlines()
    if completed.returncode != 0 or len(lines) != 2:
        raise InfrastructureError("checkout git identity is unavailable")
    git_root = Path(lines[0]).resolve(strict=True)
    if actual != expected or git_root != expected:
        raise InfrastructureError(
            f"checkout root changed: expected={expected} cwd={actual} git_root={git_root}"
        )
    if expected_sha and lines[1] != expected_sha:
        raise InfrastructureError(
            f"checkout HEAD changed: expected={expected_sha} actual={lines[1]}"
        )


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


def run(
    map_path: Path,
    log_dir: Path,
    command_prefix: Sequence[str],
    capacity_probe: Callable[[str], capacity.Capacity] = capacity.measure,
    checkout_probe: Callable[[], None] = verify_checkout,
) -> int:
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
        try:
            checkout_probe()
        except InfrastructureError as error:
            print(f"release gate infrastructure refusal: {error}", flush=True)
            return 1
        start_capacity = capacity_probe("start")
        print(start_capacity.message(), flush=True)
        if not start_capacity.sufficient:
            return 1
        for index, step in enumerate(steps, 1):
            if index > 1:
                try:
                    checkout_probe()
                except InfrastructureError as error:
                    print(f"release gate infrastructure refusal: {error}", flush=True)
                    failed = True
                    break
                between_capacity = capacity_probe("between")
                print(between_capacity.message(), flush=True)
                if not between_capacity.sufficient:
                    failed = True
                    break
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

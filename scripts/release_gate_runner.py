#!/usr/bin/env python3
"""Run the fixed local release-gate steps independently with durable logs."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


class MapError(RuntimeError):
    pass


# Conservative policy floors, not measurements of historical gate consumption.
START_REQUIRED_KIB = 6 * 1024 * 1024
BETWEEN_REQUIRED_KIB = 2 * 1024 * 1024


def reclaim_transient_builder_cache(log_path: Path) -> None:
    builder = os.environ.get("BUILDX_BUILDER", "").strip()
    config = os.environ.get("BUILDX_CONFIG", "").strip()
    if not builder:
        raise RuntimeError("cache reclaim refused: BUILDX_BUILDER is empty")
    if not config:
        raise RuntimeError("cache reclaim refused: BUILDX_CONFIG is empty")
    with log_path.open("wb") as log:
        completed = subprocess.run(
            ["docker", "buildx", "prune", "--all", "--force", "--builder", builder],
            stdout=log,
            stderr=subprocess.STDOUT,
            env={**os.environ, "BUILDX_CONFIG": config},
            check=False,
        )
    if completed.returncode:
        raise RuntimeError(f"cache reclaim failed; log: {log_path}")


def infrastructure_refusal(phase: str) -> str | None:
    try:
        expected = Path(os.environ.get("RELEASE_GATE_CHECKOUT_ROOT", Path.cwd())).resolve(strict=True)
        actual = Path.cwd().resolve(strict=True)
        completed = subprocess.run(
            ["git", "-C", str(expected), "rev-parse", "--show-toplevel", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = completed.stdout.splitlines()
        git_root = Path(lines[0]).resolve(strict=True) if len(lines) == 2 else None
    except (OSError, RuntimeError) as error:
        return f"checkout is unavailable: {error}"
    expected_sha = os.environ.get("RELEASE_GATE_SOURCE_SHA")
    if completed.returncode or actual != expected or git_root != expected:
        return f"checkout root changed: expected={expected} cwd={actual} git_root={git_root}"
    if expected_sha and lines[1] != expected_sha:
        return f"checkout HEAD changed: expected={expected_sha} actual={lines[1]}"
    required = START_REQUIRED_KIB if phase == "start" else BETWEEN_REQUIRED_KIB
    stats = os.statvfs("/")
    available = stats.f_bavail * stats.f_frsize // 1024
    if available < required:
        return (
            f"Docker daemon filesystem capacity insufficient ({phase}): "
            f"required_kib={required} available_kib={available}"
        )
    return None


@dataclass(frozen=True)
class Step:
    name: str
    category: str
    target: str


CATEGORIES = {"contract", "unit", "artifact", "journey", "audit"}


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
            if len(row) != 3 or any(not value or value != value.strip() for value in row):
                raise MapError(f"suite-map row {number} must have three trimmed fields")
            step = Step(*row)
            if step.category not in CATEGORIES:
                raise MapError(f"suite-map row {number} has unknown category {step.category}")
            rows.append(step)
    if not rows:
        raise MapError("suite map is empty")
    names = [step.name for step in rows]
    targets = [step.target for step in rows]
    if len(set(names)) != len(names):
        raise MapError("suite map has duplicate step names")
    if len(set(targets)) != len(targets):
        raise MapError("suite map has duplicate make targets")
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
    probe: Callable[[str], str | None] = infrastructure_refusal,
) -> int:
    if not command_prefix or any(not item for item in command_prefix):
        raise MapError("make command prefix is empty")
    steps = load_map(map_path)
    log_dir.mkdir(parents=True, exist_ok=True)
    states = {step.name: "NOT RUN" for step in steps}
    summary = log_dir / "summary.tsv"
    write_summary(summary, steps, states)
    failed = False
    try:
        refusal = probe("start")
        if refusal:
            print(f"release gate infrastructure refusal: {refusal}", flush=True)
            return 1
        for index, step in enumerate(steps, 1):
            if index > 1:
                refusal = probe("between")
                if refusal:
                    print(f"release gate infrastructure refusal: {refusal}", flush=True)
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
            if step.name == "a2a-image":
                try:
                    reclaim_transient_builder_cache(log_dir / "a2a-image-cache-reclaim.log")
                except RuntimeError as error:
                    print(f"release gate infrastructure refusal: {error}", flush=True)
                    failed = True
                    break
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

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release import ARTIFACTS  # noqa: E402  (single authority for artifact keys)


class MapError(RuntimeError):
    pass


ARTIFACT_KEYS = frozenset(artifact.key for artifact in ARTIFACTS)

# Conservative policy floors, not measurements of historical gate consumption.
START_REQUIRED_KIB = 6 * 1024 * 1024
BETWEEN_REQUIRED_KIB = 2 * 1024 * 1024

# The persistent builder keeps its layer cache between gate runs; this bound
# reclaims least-recently-used cache after the largest build instead of
# discarding everything, so disk stays bounded while later runs stay warm.
BUILDER_CACHE_KEEP = "10GB"


def bound_builder_cache(log_path: Path, keep: str = BUILDER_CACHE_KEEP) -> None:
    builder = os.environ.get("BUILDX_BUILDER", "").strip()
    config = os.environ.get("BUILDX_CONFIG", "").strip()
    if not builder:
        raise RuntimeError("cache reclaim refused: BUILDX_BUILDER is empty")
    if not config:
        raise RuntimeError("cache reclaim refused: BUILDX_CONFIG is empty")
    with log_path.open("wb") as log:
        completed = subprocess.run(
            [
                "docker",
                "buildx",
                "prune",
                "--all",
                "--force",
                f"--keep-storage={keep}",
                "--builder",
                builder,
            ],
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
    artifacts: frozenset[str] | None  # None = guards every release ("all")


CATEGORIES = {"contract", "unit", "artifact", "journey", "audit", "acceptance"}


def parse_artifacts(field: str, context: str) -> frozenset[str] | None:
    if field == "all":
        return None
    keys = field.split(",")
    if len(set(keys)) != len(keys):
        raise MapError(f"{context} repeats an artifact key")
    unknown = sorted(set(keys) - ARTIFACT_KEYS)
    if unknown:
        raise MapError(f"{context} names unknown artifact keys: {', '.join(unknown)}")
    return frozenset(keys)


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
            if len(row) != 4 or any(not value or value != value.strip() for value in row):
                raise MapError(f"suite-map row {number} must have four trimmed fields")
            name, category, target, artifacts_field = row
            if category not in CATEGORIES:
                raise MapError(f"suite-map row {number} has unknown category {category}")
            step = Step(
                name,
                category,
                target,
                parse_artifacts(artifacts_field, f"suite-map row {number}"),
            )
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


def selected_steps(
    steps: Sequence[Step], scope: frozenset[str] | None
) -> tuple[Step, ...]:
    """The rows a release with this scope must run, in map order.

    ``scope`` is the set of artifact keys being published this release; ``None``
    means unscoped (run everything). A row runs when it guards every release
    (``all``) or guards any artifact in the scope.
    """
    if scope is None:
        return tuple(steps)
    unknown = sorted(scope - ARTIFACT_KEYS)
    if unknown:
        raise MapError(f"release scope names unknown artifact keys: {', '.join(unknown)}")
    return tuple(
        step for step in steps if step.artifacts is None or step.artifacts & scope
    )


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
    scope: frozenset[str] | None = None,
) -> int:
    if not command_prefix or any(not item for item in command_prefix):
        raise MapError("make command prefix is empty")
    steps = load_map(map_path)
    selected = selected_steps(steps, scope)
    selected_names = {step.name for step in selected}
    map_row = {step.name: number for number, step in enumerate(steps, 1)}
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "release-scope").write_text(
        ("all" if scope is None else ",".join(sorted(scope))) + "\n", encoding="utf-8"
    )
    states = {
        step.name: ("NOT RUN" if step.name in selected_names else "SKIPPED")
        for step in steps
    }
    summary = log_dir / "summary.tsv"
    write_summary(summary, steps, states)
    failed = False
    try:
        refusal = probe("start")
        if refusal:
            print(f"release gate infrastructure refusal: {refusal}", flush=True)
            return 1
        for index, step in enumerate(selected, 1):
            if index > 1:
                refusal = probe("between")
                if refusal:
                    print(f"release gate infrastructure refusal: {refusal}", flush=True)
                    failed = True
                    break
            print(f"\n=== release gate {index}/{len(selected)}: {step.name} ({step.target}) ===", flush=True)
            log_path = log_dir / f"{map_row[step.name]:02d}-{step.name}.log"
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
                    bound_builder_cache(log_dir / "a2a-image-cache-reclaim.log")
                except RuntimeError as error:
                    print(f"release gate infrastructure refusal: {error}", flush=True)
                    failed = True
                    break
    finally:
        write_summary(summary, steps, states)
        print("\n=== release gate summary ===")
        for step in steps:
            print(f"  {states[step.name]:7s} {step.name}")
        counts = Counter(states.values())
        not_run = counts["NOT RUN"]
        failures = counts["FAILED"]
        skipped = counts["SKIPPED"]
        print(
            f"  ----\n  {failures} failed, {not_run} not run, "
            f"{skipped} skipped (outside release scope), {counts['PASSED']} passed"
        )
    return 1 if failed or not_run else 0


def parse_scope(raw: str | None) -> frozenset[str] | None:
    if raw is None:
        return None
    keys = [item for item in raw.split(",") if item]
    if not keys:
        raise MapError("release scope is empty; omit --artifacts to run everything")
    return frozenset(keys)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--make", default="make")
    parser.add_argument(
        "--artifacts",
        default=None,
        help="comma-separated artifact keys being published; omit to run every row",
    )
    args = parser.parse_args(argv)
    try:
        return run(
            args.map,
            args.log_dir,
            [args.make],
            scope=parse_scope(args.artifacts),
        )
    except (MapError, OSError) as error:
        print(f"release gate refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

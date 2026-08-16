#!/usr/bin/env python3
"""Run the fixed local release-gate steps independently with durable logs."""

from __future__ import annotations

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import subprocess
import sys
import threading
import time
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


@dataclass(frozen=True)
class Lane:
    name: str
    steps: tuple[Step, ...]


@dataclass(frozen=True)
class Schedule:
    prerequisites: tuple[Step, ...]
    lanes: tuple[Lane, ...]
    post_join: Step


CATEGORIES = {"contract", "unit", "artifact", "journey", "audit", "acceptance"}

# This is deliberately a fixed schedule, not a dependency graph or a scheduler.
# Each name still gets its category and make target from the canonical map.
PREREQUISITE_NAMES = {
    "docker-boundaries",
    "version-authority",
    "node-dependencies",
    "channel-unit",
    "channel-core-unit",
    "pi-unit",
    "aw-binary",
    "channel-package",
    "pi-package",
    "freshness",
    "channel-process-guard",
}
JOURNEY_NAMES = {
    "oats",
    "oats-proof-helpers",
    "tmux-guard",
    "a2a-gateway-e2e",
    "channel-integration",
    "oss-user",
    "oss-federation",
    "cli-library",
}
UNIT_NAMES = {
    "automatic-release",
    "server-unit",
    "awid-unit",
    "cli-unit",
    "channel-live-name",
    "go-audit-unit",
}
IMAGE_NAMES = {"awid-image", "a2a-image"}
CONTRACT_ARTIFACT_NAMES = {
    "aw-repository-stamp",
    "cli-tidy",
    "cli-vcs-release-matrix",
    "python-locks",
    "sot-inventories",
    "vector-provenance",
    "federation-error-reference",
    "federation-authority-mutations",
    "federation-harness",
    "cli-reference",
    "mcp-reference",
    "channel-version-equality",
    "a2a-copy-contract",
    "cli-version-contract",
    "server-package",
    "awid-package",
    "skills-package-zips",
    "marketplace-pointer",
    "npm-exact-publish",
    "pypi-exact-publish",
    "oci-exact-publish",
}
POST_JOIN_NAME = "release-residue"


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


def fixed_schedule(steps: Sequence[Step]) -> Schedule:
    groups = (
        PREREQUISITE_NAMES,
        JOURNEY_NAMES,
        UNIT_NAMES,
        IMAGE_NAMES,
        CONTRACT_ARTIFACT_NAMES,
        {POST_JOIN_NAME},
    )
    expected: set[str] = set()
    for group in groups:
        overlap = expected & group
        if overlap:
            raise MapError(f"fixed schedule repeats rows: {', '.join(sorted(overlap))}")
        expected.update(group)
    actual = {step.name for step in steps}
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        extra = ", ".join(sorted(actual - expected)) or "none"
        raise MapError(
            f"fixed schedule does not match suite map: missing={missing}; extra={extra}"
        )

    def selected(names: set[str]) -> tuple[Step, ...]:
        return tuple(step for step in steps if step.name in names)

    prerequisites = selected(PREREQUISITE_NAMES)
    journey = selected(JOURNEY_NAMES)
    unit = selected(UNIT_NAMES)
    image = selected(IMAGE_NAMES)
    contract_artifact = selected(CONTRACT_ARTIFACT_NAMES)
    post_join = next(step for step in steps if step.name == POST_JOIN_NAME)
    if any(step.category != "journey" for step in journey):
        raise MapError("fixed journey lane contains a non-journey map row")
    if any(step.category != "unit" for step in unit):
        raise MapError("fixed unit lane contains a non-unit map row")
    if any(step.category != "artifact" for step in image):
        raise MapError("fixed image lane contains a non-artifact map row")
    if any(
        step.category not in {"contract", "artifact"} for step in contract_artifact
    ):
        raise MapError("fixed contract/artifact lane contains another category")
    if post_join.category != "contract":
        raise MapError("release-residue post-join row must remain a contract")
    return Schedule(
        prerequisites=prerequisites,
        lanes=(
            Lane("journey", journey),
            Lane("unit", unit),
            Lane("image", image),
            Lane("contract-artifact", contract_artifact),
        ),
        post_join=post_join,
    )


def write_summary(path: Path, steps: Sequence[Step], states: dict[str, str]) -> None:
    body = "".join(
        f"{step.name}\t{states[step.name]}\t{step.category}\t{step.target}\n"
        for step in steps
    )
    temporary = path.with_suffix(".tmp")
    temporary.write_text(body, encoding="utf-8")
    os.replace(temporary, path)


def write_lane_timings(path: Path, timings: dict[str, float]) -> None:
    order = (
        "preflight",
        "journey",
        "unit",
        "image",
        "contract-artifact",
        "postflight",
        "gate",
    )
    body = "".join(f"{name}\t{timings[name]:.3f}\n" for name in order if name in timings)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(body, encoding="utf-8")
    os.replace(temporary, path)


def run(
    map_path: Path,
    log_dir: Path,
    command_prefix: Sequence[str],
    probe: Callable[[str], str | None] = infrastructure_refusal,
    *,
    serial: bool = False,
) -> int:
    if not command_prefix or any(not item for item in command_prefix):
        raise MapError("make command prefix is empty")
    steps = load_map(map_path)
    schedule = fixed_schedule(steps)
    indexes = {step.name: index for index, step in enumerate(steps, 1)}
    log_dir.mkdir(parents=True, exist_ok=True)
    states = {step.name: "NOT RUN" for step in steps}
    summary = log_dir / "summary.tsv"
    timings_path = log_dir / "lane-timings.tsv"
    timings: dict[str, float] = {}
    state_lock = threading.Lock()
    output_lock = threading.Lock()
    stop = threading.Event()
    flags = {"infrastructure_refusal": False, "crash": False}
    write_summary(summary, steps, states)

    def emit(message: str) -> None:
        with output_lock:
            print(message, flush=True)

    def record_state(step: Step, state: str) -> None:
        with state_lock:
            states[step.name] = state
            write_summary(summary, steps, states)

    def refuse(message: str) -> None:
        with state_lock:
            flags["infrastructure_refusal"] = True
        stop.set()
        emit(f"release gate infrastructure refusal: {message}")

    def mark_crash(scope: str, error: BaseException) -> None:
        with state_lock:
            flags["crash"] = True
        stop.set()
        emit(f"release gate {scope} crashed: {error}")

    def check_infrastructure(phase: str) -> bool:
        refusal = probe(phase)
        if refusal:
            refuse(refusal)
            return False
        return True

    def execute_step(scope: str, step: Step) -> None:
        index = indexes[step.name]
        emit(
            f"\n=== release gate {scope}, map row {index}/{len(steps)}: "
            f"{step.name} ({step.target}) ==="
        )
        log_path = log_dir / f"{index:02d}-{step.name}.log"
        with log_path.open("wb") as log:
            completed = subprocess.run(
                [*command_prefix, step.target],
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
        state = "PASSED" if completed.returncode == 0 else "FAILED"
        record_state(step, state)
        emit(f"=== {step.name}: {state} (log {log_path}) ===")
        if step.name == "a2a-image":
            try:
                reclaim_transient_builder_cache(log_dir / "a2a-image-cache-reclaim.log")
            except RuntimeError as error:
                refuse(str(error))

    def run_phase(
        name: str, phase_steps: Sequence[Step], first_probe: str = "between"
    ) -> None:
        started = time.monotonic()
        try:
            for step in phase_steps:
                if stop.is_set() or not check_infrastructure(first_probe):
                    break
                execute_step(name, step)
        finally:
            with state_lock:
                timings[name] = time.monotonic() - started

    gate_started = time.monotonic()
    try:
        preflight_started = time.monotonic()
        if check_infrastructure("start"):
            try:
                for offset, step in enumerate(schedule.prerequisites):
                    if offset and (
                        stop.is_set() or not check_infrastructure("between")
                    ):
                        break
                    execute_step("preflight", step)
            except Exception as error:
                mark_crash("preflight", error)
        with state_lock:
            timings["preflight"] = time.monotonic() - preflight_started

        if not stop.is_set():
            if serial:
                for lane in schedule.lanes:
                    if stop.is_set():
                        break
                    try:
                        run_phase(lane.name, lane.steps)
                    except Exception as error:
                        mark_crash(f"{lane.name} lane", error)
            else:
                with ThreadPoolExecutor(
                    max_workers=4, thread_name_prefix="release-gate"
                ) as executor:
                    futures = {
                        executor.submit(run_phase, lane.name, lane.steps): lane.name
                        for lane in schedule.lanes
                    }
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as error:
                            mark_crash(f"{futures[future]} lane", error)

        if not stop.is_set() and check_infrastructure("between"):
            postflight_started = time.monotonic()
            try:
                execute_step("postflight", schedule.post_join)
            except Exception as error:
                mark_crash("postflight", error)
            finally:
                with state_lock:
                    timings["postflight"] = time.monotonic() - postflight_started
    finally:
        with state_lock:
            timings["gate"] = time.monotonic() - gate_started
            write_summary(summary, steps, states)
            write_lane_timings(timings_path, timings)
        emit("\n=== release gate summary ===")
        for step in steps:
            emit(f"  {states[step.name]:7s} {step.name}")
        not_run = sum(state == "NOT RUN" for state in states.values())
        failures = sum(state == "FAILED" for state in states.values())
        passed = len(steps) - failures - not_run
        emit(f"  ----\n  {failures} failed, {not_run} not run, {passed} passed")
    return 1 if any(flags.values()) or failures or not_run else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--make", default="make")
    parser.add_argument(
        "--serial",
        action="store_true",
        help="run the fixed lanes one at a time instead of concurrently",
    )
    args = parser.parse_args(argv)
    try:
        return run(args.map, args.log_dir, [args.make], serial=args.serial)
    except (MapError, OSError) as error:
        print(f"release gate refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""The normalizer's orchestration (aben, design sections 6 and 8).

Capture once; compute twice from the captured world and require
byte-identical results (the resolver-nondeterminism stop, alice's named
stop in its ruled within-invocation form); apply allowlisted manifest
patches to the working tree only; recapture and require the second pass
to emit an empty patch (the fixed point); re-observe load-bearing
registry facts and stop under their real names if the world moved; print
the report; exit 0 normal-form, 10 patch-needed, 1 stop. Nothing is
committed, pushed, or persisted anywhere by this code.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Callable, Iterable

import release_normalizer as rn

PATCH_NEEDED = 10
STOP = 1


@dataclasses.dataclass(frozen=True)
class Outcome:
    exit_code: int
    report: str


def _apply_manifest_patch(path: Path, from_version: str, to_version: str) -> None:
    text = path.read_text()
    if path.name == "package.json":
        pattern = f'"version": "{from_version}"'
        replacement = f'"version": "{to_version}"'
    else:
        pattern = f'version = "{from_version}"'
        replacement = f'version = "{to_version}"'
    if text.count(pattern) != 1:
        raise RuntimeError(
            f"{path}: expected exactly one {pattern!r}, found {text.count(pattern)}"
        )
    path.write_text(text.replace(pattern, replacement, 1))


def run_normalizer(
    *,
    capture: Callable[[], rn.CapturedWorld],
    manifest_paths: dict[str, Path],
    reobserve: Callable[[rn.NormalizerResult], Iterable[rn.Stop]],
    normalize: Callable[[rn.CapturedWorld], rn.NormalizerResult] = rn.normalize,
    recapture: Callable[[], rn.CapturedWorld] | None = None,
) -> Outcome:
    world = capture()
    first = normalize(world)
    second = normalize(world)
    if first.serialize() != second.serialize():
        return Outcome(
            STOP,
            "STOP normalizer-nondeterminism: two computations from identical "
            "captured inputs differ; refusing to trust either",
        )

    if first.outcome == "stop":
        lines = [
            f"STOP {stop.code}"
            + (f" ({stop.artifact})" if stop.artifact else "")
            for stop in first.stops
        ]
        return Outcome(STOP, "\n".join(lines))

    if first.outcome == "patch-needed":
        # Equality-group members share physical manifests (both AWID
        # rows own awid/pyproject.toml): the edit is applied once per
        # FILE, and rows disagreeing about that file's edit are an
        # engine inconsistency stopped by name, never a blind second
        # application.
        edits_by_path: dict[Path, tuple[str, str]] = {}
        for name, from_version, to_version in first.patches:
            path = manifest_paths[name]
            edit = (from_version, to_version)
            if edits_by_path.setdefault(path, edit) != edit:
                return Outcome(
                    STOP,
                    f"STOP divergent-manifest-patch: {path} wanted both "
                    f"{edits_by_path[path]} and {edit}",
                )
        for path, (from_version, to_version) in edits_by_path.items():
            _apply_manifest_patch(path, from_version, to_version)
        followup = normalize((recapture or capture)())
        if followup.outcome == "patch-needed":
            return Outcome(
                STOP,
                "STOP non-convergent-normalization: the patched tree still "
                f"wants {followup.patches}",
            )
        if followup.outcome == "stop":
            lines = [f"STOP {stop.code}" for stop in followup.stops]
            return Outcome(STOP, "\n".join(lines))
        moved = list(reobserve(first))
        if moved:
            return Outcome(
                STOP, "\n".join(f"STOP {stop.code}" for stop in moved)
            )
        lines = ["PATCH NEEDED - allowlisted working-tree edits applied:"]
        lines += [
            f"  {name}: {from_version} -> {to_version}"
            for name, from_version, to_version in first.patches
        ]
        lines.append(
            "Normal review, commit, and integration are required before the "
            "next release-prepare; nothing was committed or stored."
        )
        return Outcome(PATCH_NEEDED, "\n".join(lines))

    moved = list(reobserve(first))
    if moved:
        return Outcome(STOP, "\n".join(f"STOP {stop.code}" for stop in moved))
    return Outcome(0, "normal form: world and repositories agree; proceeding")

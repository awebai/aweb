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
    # The computed projection, carried so the SAME in-memory result the
    # orchestration validated is what prepare builds the card from
    # (aben amendment A5); None on stops.
    result: rn.NormalizerResult | None = None


def _apply_floor_patch(path: Path, from_version: str, to_version: str) -> None:
    text = path.read_text()
    pattern = f"awid-service>={from_version}"
    if text.count(pattern) != 1:
        raise RuntimeError(
            f"{path}: expected exactly one {pattern!r}, found {text.count(pattern)}"
        )
    path.write_text(text.replace(pattern, f"awid-service>={to_version}", 1))


def _apply_manifest_patch(path: Path, from_version: str, to_version: str) -> None:
    text = path.read_text()
    # Chosen by SUFFIX, not by the exact filename: the version mirrors
    # are .claude-plugin/plugin.json, which is JSON and was falling to
    # the TOML form because it is not literally named package.json.
    if path.suffix == ".json":
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


def render_stops(stops) -> str:
    """THE rendering of a stop line. The runner reached this text from
    four places and three of them dropped the artifact, so whether a
    refusal was actionable depended on which path raised it - one fact,
    several derivations, the family this epic exists to remove. A stop
    names its subject or it is not a refusal an operator can act on."""

    return "\n".join(
        f"STOP {stop.code}"
        + (f" ({stop.artifact})" if stop.artifact else "")
        + (f": {stop.detail}" if stop.detail else "")
        for stop in stops
    )


def run_normalizer(
    *,
    capture: Callable[[], rn.CapturedWorld],
    manifest_paths: dict[str, Path],
    version_mirrors: dict[str, tuple[Path, ...]] | None = None,
    reobserve: Callable[..., Iterable[rn.Stop]],
    normalize: Callable[[rn.CapturedWorld], rn.NormalizerResult] = rn.normalize,
    recapture: Callable[[], rn.CapturedWorld] | None = None,
    lock_paths: dict[str, tuple[Path, ...]] | None = None,
    regenerate_lock: Callable[[Path], None] | None = None,
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
        return Outcome(STOP, render_stops(first.stops))

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
        # A version that is MIRRORED in other committed files moves in
        # all of them or the tree contradicts itself. The live prepare
        # patched skills' package.json, left its .claude-plugin mirror
        # behind, and was refused by the equality guard - correctly, but
        # the patch should never have produced that tree.
        for name, _from, _to in first.patches:
            for mirror in (version_mirrors or {}).get(name, ()):
                _apply_manifest_patch(mirror, _from, _to)
        for owner, floor_from, floor_to in first.floor_patches:
            _apply_floor_patch(manifest_paths[owner], floor_from, floor_to)
        # The owned locks of every patched manifest (the floor owner's
        # included) regenerate now, so the patch the operator reviews is
        # the complete allowlisted edit, never a stale-lock ship.
        patched = {name for name, _f, _t in first.patches} | {
            owner for owner, _f, _t in first.floor_patches
        }
        lock_targets: list[Path] = []
        for name in sorted(patched):
            for lock in (lock_paths or {}).get(name, ()):
                if lock not in lock_targets:
                    lock_targets.append(lock)
        if lock_targets and regenerate_lock is not None:
            for lock in lock_targets:
                try:
                    regenerate_lock(lock)
                except Exception as error:  # noqa: BLE001 - named stop
                    return Outcome(
                        STOP, f"STOP lock-regeneration-failed: {lock}: {error}"
                    )
        followup = normalize((recapture or capture)())
        if followup.outcome == "patch-needed":
            return Outcome(
                STOP,
                "STOP non-convergent-normalization: the patched tree still "
                f"wants {followup.patches}",
            )
        if followup.outcome == "stop":
            return Outcome(STOP, render_stops(followup.stops))
        moved = list(reobserve(first, world))
        if moved:
            return Outcome(STOP, render_stops(moved))
        lines = ["PATCH NEEDED - allowlisted working-tree edits applied:"]
        lines += [
            f"  {name}: {from_version} -> {to_version}"
            for name, from_version, to_version in first.patches
        ]
        lines += [
            f"  {owner} floor: awid-service>={floor_from} -> >={floor_to}"
            for owner, floor_from, floor_to in first.floor_patches
        ]
        lines.append(
            "Normal review, commit, and integration are required before the "
            "next release-prepare; nothing was committed or stored."
        )
        return Outcome(PATCH_NEEDED, "\n".join(lines), result=first)

    moved = list(reobserve(first, world))
    if moved:
        return Outcome(STOP, render_stops(moved))
    return Outcome(
        0, "normal form: world and repositories agree; proceeding", result=first
    )

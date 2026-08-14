#!/usr/bin/env python3
"""Predecessor-row gate assembly (aben, design section 8).

rows_for_artifacts composes the per-fact builders over the named card
artifacts' declared outputs at their card versions, routing each unit
target by spelling. The gates consume these rows: an ordering obligation
is enforced by every predecessor row being observed-present, never by a
primary poll or a monitor conclusion.
"""

from __future__ import annotations

import release_status_builders as builders
from release_status import Row

_DEFAULT_BASES = {
    "pypi": "https://pypi.org/pypi",
    "npm": "https://registry.npmjs.org",
    "ghcr": "https://ghcr.io",
}


def rows_for_artifacts(card, names, *, bases=None, timeout: float) -> list[Row]:
    import release_train as rt

    resolved = {**_DEFAULT_BASES, **(bases or {})}
    rows: list[Row] = []
    for item in card.artifacts:
        if item.name not in names:
            continue
        artifact = rt._artifact(item.name)
        for target in artifact.occupancy_unit or artifact.targets[:1]:
            if target.startswith("pypi:"):
                rows += builders.pypi_rows(
                    target.removeprefix("pypi:"),
                    item.version,
                    anchor=f"{artifact.anchor.value}{item.version}"
                    if artifact.anchor
                    else "unanchored",
                    base=resolved["pypi"],
                    timeout=timeout,
                )
            elif target.startswith("npm:"):
                rows.append(
                    builders.npm_tarball_row(
                        target.removeprefix("npm:"),
                        item.version,
                        base=resolved["npm"],
                        timeout=timeout,
                    )
                )
            elif target.startswith("ghcr.io/"):
                rows += builders.image_rows(
                    target.removeprefix("ghcr.io/"),
                    item.version,
                    expected_revision="",
                    required_platforms=artifact.platforms,
                    check_latest=False,
                    base=resolved["ghcr"],
                    token="",
                    timeout=timeout,
                )
            else:
                rows.append(
                    Row(
                        fact=f"{target} {item.version}",
                        state="unavailable",
                        evidence="no row builder routes this target kind yet",
                    )
                )
    return rows

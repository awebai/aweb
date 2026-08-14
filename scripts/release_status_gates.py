#!/usr/bin/env python3
"""Row assembly over card artifacts (aben, design section 8).

rows_for_artifacts composes the per-fact builders over the named card
artifacts' declared outputs at their card versions, routing EVERY unit
target by spelling - pypi file contracts, npm integrity, image indexes
with real bearer auth and real expected revisions, GitHub releases with
their required asset sets - plus each artifact's observed source
anchor. The predecessor gates and the terminal DONE sweep both consume
these rows; an ordering obligation is enforced by every predecessor row
being observed-present, never by a primary poll or a monitor
conclusion.
"""

from __future__ import annotations

import release_status_builders as builders
from release_status import Row

_DEFAULT_BASES = {
    "pypi": "https://pypi.org/pypi",
    "npm": "https://registry.npmjs.org",
    "ghcr": "https://ghcr.io",
    "github": "https://api.github.com",
}

# Images whose publisher promises a mutable latest equal to the version
# digest; the AC image publishes :VERSION and :SHA instead, no latest.
_LATEST_PROMISED = {"awid-image", "a2a-gateway-image"}


def rows_for_artifacts(
    card,
    names,
    *,
    bases=None,
    expected_sources=None,
    tokens=None,
    repo_roots=None,
    timeout: float,
) -> list[Row]:
    import release_train as rt

    resolved = {**_DEFAULT_BASES, **(bases or {})}
    expected_sources = expected_sources or {}
    tokens = tokens or {}
    rows: list[Row] = []
    for item in card.artifacts:
        if item.name not in names:
            continue
        artifact = rt._artifact(item.name)
        expected = _expected_identity(item, expected_sources)
        for target in artifact.occupancy_unit or artifact.targets[:1]:
            if target.startswith("pypi:"):
                rows += builders.pypi_rows(
                    target.removeprefix("pypi:"),
                    item.version,
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
                    expected_revision=expected or "",
                    required_platforms=artifact.platforms,
                    check_latest=item.name in _LATEST_PROMISED,
                    base=resolved["ghcr"],
                    token=tokens.get("ghcr", ""),
                    timeout=timeout,
                )
            elif target.startswith("github:"):
                _, repository, _channel = target.split(":", 2)
                prefix = (
                    f"{artifact.anchor.value}" if artifact.anchor else "v"
                )
                tag = (
                    f"{prefix}{item.version}"
                    if artifact.anchor and artifact.anchor.kind == "tag_pattern"
                    else f"v{item.version}"
                )
                required = tuple(
                    name.format(version=item.version)
                    for name in artifact.required_current_outputs
                )
                rows += builders.github_release_rows(
                    repository,
                    tag if item.name == "skills" else f"v{item.version}",
                    required_assets=required,
                    base=resolved["github"],
                    token=tokens.get("github", ""),
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
        if (
            repo_roots is not None
            and artifact.anchor is not None
            and artifact.anchor.kind == "tag_pattern"
            and expected
        ):
            rows.append(
                builders.source_tag_row(
                    repo_roots[artifact.repository],
                    f"{artifact.anchor.value}{item.version}",
                    expected_identity=expected,
                )
            )
    return rows


def _expected_identity(item, expected_sources) -> str | None:
    """The identity this artifact's outputs must bind to: for moving and
    recovery rows the card's named completion source; for unmoved rows
    the card's own previous-complete anchor identity."""

    if item.disposition == "unmoved":
        anchor = item.previous_complete_anchor
        return anchor.source_identity if anchor is not None else None
    return expected_sources.get(item.name)

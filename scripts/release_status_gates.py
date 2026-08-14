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
    "pypi": "https://pypi.org",
    "npm": "https://registry.npmjs.org",
    "ghcr": "https://ghcr.io",
    "github": "https://api.github.com",
}




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
                image = target.removeprefix("ghcr.io/")
                rows += builders.image_rows(
                    image,
                    item.version,
                    expected_revision=expected or "",
                    required_platforms=artifact.platforms,
                    check_latest=artifact.promises_latest,
                    base=resolved["ghcr"],
                    token=tokens.get("ghcr", ""),
                    timeout=timeout,
                )
                if item.name == "ac-image" and expected:
                    # The AC publisher's contract is :VERSION and :SHA,
                    # no latest; the alias row proves both names serve
                    # one digest.
                    rows.append(
                        builders.image_alias_row(
                            image,
                            item.version,
                            expected,
                            base=resolved["ghcr"],
                            token=tokens.get("ghcr", ""),
                            timeout=timeout,
                        )
                    )
            elif target.startswith("github:"):
                _, repository, _channel = target.split(":", 2)
                # release-review's A7 point: the tag choice keys on
                # DATA, not on an artifact's name. A release in the
                # artifact's own source repository is tagged with its
                # canonical anchor prefix (skills-v{V} on awebai/aweb);
                # an external product repository (awebai/aw) tags v{V}.
                own_repository = repository == f"awebai/{artifact.repository}"
                tag = (
                    f"{artifact.anchor.value}{item.version}"
                    if own_repository
                    and artifact.anchor is not None
                    and artifact.anchor.kind == "tag_pattern"
                    else f"v{item.version}"
                )
                required = tuple(
                    name.format(version=item.version)
                    for name in artifact.required_current_outputs
                )
                rows += builders.github_release_rows(
                    repository,
                    tag,
                    required_assets=required,
                    base=resolved["github"],
                    token=tokens.get("github", ""),
                    timeout=timeout,
                )
                if not own_repository and expected:
                    # The external product repository (awebai/aw): its
                    # own tag and the sync-stamp tree binding to the
                    # exact aweb source the card names.
                    rows += builders.external_release_binding_rows(
                        repository,
                        tag,
                        expected_source_sha=expected,
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


def expected_fact_keys(
    card, names, *, include_source_tags: bool, expected_sources=None
) -> set[str]:
    """The EXACT registry-row fact domain the assembly must produce for
    the named card artifacts, derived from canonical metadata alone -
    so a routed builder silently omitting a fact is detectable by set
    equality in both directions, not only an unrouted target (C2, the
    omission control the verdict demanded)."""

    import release_train as rt

    expected_sources = expected_sources or {}
    keys: set[str] = set()
    for item in card.artifacts:
        if item.name not in names:
            continue
        artifact = rt._artifact(item.name)
        expected = _expected_identity(item, expected_sources)
        for target in artifact.occupancy_unit or artifact.targets[:1]:
            if target.startswith("pypi:"):
                package = target.removeprefix("pypi:")
                normalized = package.replace("-", "_")
                keys |= {
                    f"pypi:{package} sdist {normalized}-{item.version}.tar.gz",
                    f"pypi:{package} wheel",
                    f"pypi:{package} filename set",
                }
            elif target.startswith("npm:"):
                package = target.removeprefix("npm:")
                keys.add(f"npm:{package} tarball integrity")
            elif target.startswith("ghcr.io/"):
                image = target.removeprefix("ghcr.io/")
                keys.add(f"ghcr:{image} {item.version} index digest")
                for platform in artifact.platforms:
                    keys.add(
                        f"ghcr:{image} {item.version} {platform} revision label"
                    )
                if artifact.promises_latest:
                    keys.add(f"ghcr:{image} latest == {item.version}")
                if item.name == "ac-image" and expected:
                    keys.add(
                        f"ghcr:{image} {expected} digest == {item.version} digest"
                    )
            elif target.startswith("github:"):
                _, repository, _channel = target.split(":", 2)
                own_repository = repository == f"awebai/{artifact.repository}"
                tag = (
                    f"{artifact.anchor.value}{item.version}"
                    if own_repository
                    and artifact.anchor is not None
                    and artifact.anchor.kind == "tag_pattern"
                    else f"v{item.version}"
                )
                keys.add(f"github:{repository} release {tag}")
                for name in artifact.required_current_outputs:
                    keys.add(
                        f"github:{repository} {tag} asset "
                        f"{name.format(version=item.version)}"
                    )
                if not own_repository and expected:
                    keys |= {
                        f"github:{repository} external tag {tag}",
                        f"github:{repository} {tag} tree binding",
                    }
        if (
            include_source_tags
            and artifact.anchor is not None
            and artifact.anchor.kind == "tag_pattern"
            and expected
        ):
            keys.add(f"source tag {artifact.anchor.value}{item.version}")
    return keys

"""The release normalizer's pure derivations (aben, docs/aben-design.md).

This module holds the side-effect-free algorithms: the version grammar,
the movement/version table (design section 3), and - as the module grows
through R3 - anchor reconciliation classification and the equality-group
shared-candidate algorithm. Orchestration (observation capture, patch
application, the prepare phase wiring) lives separately; these functions
take plain values and return decisions, which is what makes the fixtures
in scripts/e2e exact.
"""

from __future__ import annotations

import dataclasses
import re

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def parse_version(text: str) -> tuple[int, int, int] | None:
    """Strict numeric MAJOR.MINOR.PATCH (optional leading v); no
    prerelease, no build metadata. Ordering on the returned tuple is
    numeric by construction."""
    match = _VERSION_RE.match(text)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def format_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def next_patch(version: tuple[int, int, int]) -> tuple[int, int, int]:
    return (version[0], version[1], version[2] + 1)


@dataclasses.dataclass(frozen=True)
class MovementDecision:
    """kind is "unmoved", "moving", or "stop". For moving, version is the
    intended version and patch is (from, to) when the normalizer must
    emit a manifest edit, None when the manifest already says it. For
    stop, stop carries the stable code."""

    kind: str
    version: str | None = None
    patch: tuple[str, str] | None = None
    stop: str | None = None


def movement_decision(
    *,
    content_changed: bool,
    manifest_version: str,
    reconciled_p: str,
    occupied_versions: frozenset[str],
    compatibility: str,
    derivation: str,
) -> MovementDecision:
    """The five-case movement/version table, plus the CLI tag-history
    exception (design section 3).

    reconciled_p is the anchor reconciler's single complete published
    version; occupied_versions is every version any unit member occupies
    (always including reconciled_p). derivation is "manifest" or
    "tag-history"; the latter re-derives mechanically over occupancy
    instead of stopping, which is the existing CLI rule and the B2
    fixture's expected outcome.
    """

    manifest = parse_version(manifest_version)
    published = parse_version(reconciled_p)
    if manifest is None or published is None:
        return MovementDecision(kind="stop", stop="malformed-version-candidate")
    occupied = {
        parsed for v in occupied_versions if (parsed := parse_version(v)) is not None
    }
    greatest_occupied = max(occupied) if occupied else published

    if not content_changed:
        if manifest == published:
            return MovementDecision(kind="unmoved", version=reconciled_p)
        if manifest > published:
            return MovementDecision(
                kind="stop", stop="contentless-or-predeclared-version"
            )
        return MovementDecision(kind="stop", stop="manifest-version-behind-public")

    if derivation == "tag-history":
        candidate = next_patch(published)
        while candidate in occupied:
            candidate = next_patch(candidate)
        return MovementDecision(
            kind="moving",
            version=format_version(candidate),
            patch=None,
        )

    if manifest > published:
        if manifest in occupied or manifest <= greatest_occupied:
            return MovementDecision(kind="stop", stop="version-occupied")
        return MovementDecision(kind="moving", version=manifest_version, patch=None)

    # content changed, manifest at or behind the published version: the
    # deterministic next patch, minted only under compatibility "none".
    if compatibility != "none":
        return MovementDecision(kind="stop", stop="compat-version-decision-needed")
    candidate = next_patch(published)
    if candidate in occupied or candidate <= greatest_occupied:
        return MovementDecision(kind="stop", stop="version-occupied")
    return MovementDecision(
        kind="moving",
        version=format_version(candidate),
        patch=(manifest_version, format_version(candidate)),
    )

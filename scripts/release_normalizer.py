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


@dataclasses.dataclass(frozen=True)
class UnitMember:
    """One publication-unit member's discovered occupancy: version ->
    observable source identity, or None where the member kind carries no
    source identity (pypi/npm listings)."""

    name: str
    occupied: dict[str, str | None]


@dataclasses.dataclass(frozen=True)
class Reconciliation:
    """state: reconciled | recoverable-partial | conflicting-partial | stop.

    p is the previous COMPLETE anchored version (the content-diff anchor);
    for reconciled it equals the candidate. candidate is the version under
    consideration when partial. provisional marks recoverability resting on
    identityless occupancy alone (decided by the staged-byte check at
    publication). stop carries the stable code for terminal states.
    """

    state: str
    p: str | None = None
    candidate: str | None = None
    source_identity: str | None = None
    provisional: bool = False
    stop: str | None = None


def reconcile_unit(
    *,
    members: list[UnitMember],
    anchor_versions: dict[str, str],
    manifest_intent: str,
) -> Reconciliation:
    """The four-state anchor reconciliation (design section 2), with the
    recoverable-versus-conflicting fork.

    anchor_versions maps each anchored version to its source identity.
    History below the candidate never stops; every terminal condition
    carries a stable code.
    """

    for m in members:
        for version in m.occupied:
            if parse_version(version) is None:
                return Reconciliation(
                    state="stop", stop="malformed-version-candidate"
                )
    for version in anchor_versions:
        if parse_version(version) is None:
            return Reconciliation(state="stop", stop="malformed-version-candidate")

    all_versions = {v for m in members for v in m.occupied} | set(anchor_versions)
    if not all_versions:
        # Nothing published anywhere: trivially reconciled at no version;
        # movement derivation treats absent P via its own rules.
        return Reconciliation(state="reconciled", p=None)

    candidate = format_version(
        max(parsed for v in all_versions if (parsed := parse_version(v)) is not None)
    )

    occupied_members = [m for m in members if candidate in m.occupied]
    missing_members = [m for m in members if candidate not in m.occupied]
    anchor_identity = anchor_versions.get(candidate)

    def complete_at(version: str) -> bool:
        return version in anchor_versions and all(
            version in m.occupied for m in members
        )

    previous_complete = None
    lower = sorted(
        (
            parsed
            for v in all_versions
            if v != candidate and (parsed := parse_version(v)) is not None
        ),
        reverse=True,
    )
    for parsed in lower:
        text = format_version(parsed)
        if complete_at(text):
            previous_complete = text
            break

    # Identity coherence: occupied members that carry identity must agree
    # with each other and with the anchor. Provisionality is separate -
    # it is about the occupied bytes' provenance, so the anchor's own
    # identity never converts identityless occupancy into proven state.
    member_identities = {
        identity
        for m in occupied_members
        for v, identity in m.occupied.items()
        if v == candidate and identity is not None
    }
    identities = set(member_identities)
    if anchor_identity is not None:
        identities.add(anchor_identity)
    if len(identities) > 1:
        return Reconciliation(state="conflicting-partial", candidate=candidate)

    if not missing_members:
        if anchor_identity is None:
            return Reconciliation(state="stop", stop="anchorless-version")
        return Reconciliation(
            state="reconciled",
            p=candidate,
            candidate=candidate,
            source_identity=anchor_identity,
        )

    # Partial: fork on evidence.
    if manifest_intent != candidate:
        return Reconciliation(state="conflicting-partial", candidate=candidate)
    if previous_complete is None:
        return Reconciliation(state="conflicting-partial", candidate=candidate)
    provisional = bool(occupied_members) and not member_identities
    return Reconciliation(
        state="recoverable-partial",
        p=previous_complete,
        candidate=candidate,
        source_identity=next(iter(identities)) if identities else None,
        provisional=provisional,
    )

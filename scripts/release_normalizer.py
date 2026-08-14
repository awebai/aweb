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
from collections.abc import Iterable

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


def numeric_prefix(text: str) -> tuple[int, ...] | None:
    """The numeric runs of a near-version candidate, so a malformed one
    can be placed against the versions in play: "0.3" -> (0, 3),
    "0.7.15rc1" -> (0, 7, 15, 1), "v2" -> (2,). None when the candidate
    is not digit-led at all."""

    body = text[1:] if text.startswith("v") else text
    parts: list[int] = []
    for chunk in re.split(r"[^0-9]+", body):
        if not chunk:
            break
        parts.append(int(chunk))
    return tuple(parts) or None


def malformed_is_history(prefix: tuple[int, ...] | None, candidate) -> bool:
    """Is a malformed candidate provably BELOW the candidate in play?

    Component-wise until the FIRST difference decides it. Only a first
    difference proving the malformed spelling lower makes it history.
    Equal-but-incomplete ("0.7" against 0.7.15) and equal-with-suffix
    ("0.7.15rc1" against 0.7.15) are ambiguous, not lower - they could
    bear on the decision, so they stop. So does a candidate with no
    numeric prefix at all. (plan-critic's binding conditions on the
    narrowing; padding an incomplete spelling into history is exactly
    the move they forbid.)
    """

    if prefix is None:
        return False
    for mine, theirs in zip(prefix, candidate):
        if mine != theirs:
            return mine < theirs
    return False


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

    seen = {v for m in members for v in m.occupied} | set(anchor_versions)
    parsed_versions = {
        v: parsed for v in seen if (parsed := parse_version(v)) is not None
    }
    # unit_candidate below derives the same top from the same inputs; it
    # exists so capture can resolve identity for exactly this version
    # without a second implementation of which version that is.
    malformed = sorted(seen - set(parsed_versions))
    if not parsed_versions:
        # Only near-versions, or nothing at all. With no conforming
        # version there is no candidate to place them against, so a
        # malformed one cannot be shown to be history and stops.
        if malformed:
            return Reconciliation(
                state="stop", stop="malformed-version-candidate"
            )
        # Nothing published anywhere: trivially reconciled at no version;
        # movement derivation treats absent P via its own rules.
        return Reconciliation(state="reconciled", p=None)

    candidate_text = unit_candidate(seen, ())
    top = parse_version(candidate_text or "")
    # A malformed candidate stops only when it could BEAR on the
    # decision - its numeric prefix sorting at or above the candidate in
    # play. Anything strictly below is history, logged like latest and
    # sha-* and never a halt (design section 2): the registry keeps old
    # shapes forever and we do not mutate the world to quiet a checker.
    for version in malformed:
        if not malformed_is_history(numeric_prefix(version), top):
            return Reconciliation(
                state="stop", stop="malformed-version-candidate"
            )

    all_versions = set(parsed_versions)
    candidate = candidate_text or ""
    assert top is not None  # parsed_versions non-empty implies a candidate

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
            if manifest_intent == candidate and member_identities:
                # Occupied at the intended version by bytes whose source
                # cannot be bound to any anchor: the conflicting fork,
                # not a flat anchorless stop - the equality group's mint
                # path consumes this (design section 3, the
                # lagging-conflicting control).
                return Reconciliation(
                    state="conflicting-partial",
                    candidate=candidate,
                    source_identity=next(iter(member_identities)),
                )
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


def unit_candidate(
    occupied_versions: Iterable[str], anchor_versions: Iterable[str]
) -> str | None:
    """The one version whose source identity the reconciler compares.

    reconcile_unit derives its candidate as the greatest conforming
    version across the unit's occupancy and its anchors, and reads
    member identity ONLY at that version (`if v == candidate`). Capture
    calls this to resolve identity for exactly that version instead of
    walking every tag in the namespace, so the expensive read is bound
    to the fact that consumes it rather than to registry history.

    Returns None when no conforming version exists, where there is no
    candidate to place anything against.
    """

    parsed = [
        version
        for text in {*occupied_versions, *anchor_versions}
        if (version := parse_version(text)) is not None
    ]
    return format_version(max(parsed)) if parsed else None


@dataclasses.dataclass(frozen=True)
class GroupMember:
    """One equality-group member: its own unit reconciliation and whether
    its content scope moved since its anchor."""

    name: str
    reconciliation: Reconciliation
    content_changed: bool


@dataclasses.dataclass(frozen=True)
class GroupDecision:
    """kind: unmoved | shared-candidate | stop. For shared-candidate,
    version is the group's one version; patch lists (member, from, to)
    manifest edits (None when manifests already carry the version);
    recovering names members walking recovery at the version; driver
    labels the member whose state forced any mint."""

    kind: str
    version: str | None = None
    patch: tuple[tuple[str, str, str], ...] | None = None
    recovering: tuple[str, ...] = ()
    driver: str | None = None
    stop: str | None = None


def group_decision(
    *,
    members: list[GroupMember],
    manifest_versions: dict[str, str],
    compatibility: str,
) -> GroupDecision:
    """The shared-candidate algorithm (design section 3): validate
    manifest equality; reuse M when every lagging member can publish or
    recover at it; mint one shared next patch only when M cannot serve,
    compat-gated, driver-labeled."""

    versions = {manifest_versions[m.name] for m in members}
    if len(versions) != 1:
        return GroupDecision(kind="stop", stop="equality-invariant-violated")
    m_text = next(iter(versions))
    m_parsed = parse_version(m_text)
    if m_parsed is None:
        return GroupDecision(kind="stop", stop="malformed-version-candidate")

    for member in members:
        if member.reconciliation.state == "stop":
            return GroupDecision(
                kind="stop", stop=member.reconciliation.stop or "member-stop"
            )

    complete_at_m = [
        m for m in members
        if m.reconciliation.state == "reconciled" and m.reconciliation.p == m_text
    ]
    recoverable_at_m = [
        m for m in members
        if m.reconciliation.state == "recoverable-partial"
        and m.reconciliation.candidate == m_text
    ]
    conflicting = [
        m for m in members if m.reconciliation.state == "conflicting-partial"
    ]
    # A member complete at a LOWER version whose unit therefore does not
    # occupy M can publish or recover AT M (design section 3 step 3) -
    # minting for it would burn a number because one member lagged, the
    # phantom-release direction. Only p > M (non-monotonic) joins the
    # mint path.
    movable_at_m = [
        m for m in members
        if m.reconciliation.state == "reconciled"
        and m.reconciliation.p is not None
        and (p := parse_version(m.reconciliation.p)) is not None
        and p < m_parsed
    ]
    lagging_complete = [
        m for m in members
        if m.reconciliation.state == "reconciled"
        and m.reconciliation.p != m_text
        and m not in movable_at_m
    ]

    if not conflicting and not lagging_complete:
        if len(complete_at_m) == len(members):
            changed = [m for m in members if m.content_changed]
            if not changed:
                return GroupDecision(kind="unmoved", version=m_text)
            # Content moved on some side while every unit is complete at
            # M: the group needs the next version, driver-labeled.
            if compatibility != "none":
                return GroupDecision(
                    kind="stop", stop="compat-version-decision-needed"
                )
            minted = format_version(next_patch(m_parsed))
            return GroupDecision(
                kind="shared-candidate",
                version=minted,
                patch=tuple(
                    (m.name, m_text, minted) for m in sorted(members, key=lambda g: g.name)
                ),
                driver=changed[0].name,
            )
        # Everyone is complete at M, recoverable at M, or movable to M:
        # reuse M; lagging members walk recovery there.
        return GroupDecision(
            kind="shared-candidate",
            version=m_text,
            patch=None,
            recovering=tuple(
                sorted(m.name for m in (*recoverable_at_m, *movable_at_m))
            ),
        )

    # M cannot serve: a member conflicts at it, or a complete member sits
    # at a different version while manifests claim M. One shared next
    # patch over the group's greatest complete/occupied version.
    if compatibility != "none":
        return GroupDecision(kind="stop", stop="compat-version-decision-needed")
    greatest = m_parsed
    for member in members:
        for text in (member.reconciliation.p, member.reconciliation.candidate):
            if text and (parsed := parse_version(text)) and parsed > greatest:
                greatest = parsed
    minted = format_version(next_patch(greatest))
    driver = (conflicting or lagging_complete)[0].name
    return GroupDecision(
        kind="shared-candidate",
        version=minted,
        patch=tuple(
            (m.name, manifest_versions[m.name], minted)
            for m in sorted(members, key=lambda g: g.name)
        ),
        driver=driver,
    )


@dataclasses.dataclass
class CapturedArtifact:
    """One artifact's captured world: repository facts (manifest version,
    content-changed against its anchor, derivation kind) plus registry
    observations (unit member occupancy, anchor versions). Capture is
    I/O; everything after is pure."""

    manifest_version: str
    content_changed: bool
    derivation: str
    members: list[UnitMember]
    anchor_versions: dict[str, str]


@dataclasses.dataclass
class CapturedWorld:
    artifacts: dict[str, CapturedArtifact]
    equality_groups: tuple[tuple[str, ...], ...]
    compatibility: str
    # The same-cycle consumer floor (design section 4, R1): the awid
    # floor literal read from server's manifest. None = not captured
    # (direct-built fixture worlds; the policy is out of scope), "" =
    # captured but the literal was not found (a named stop when awid
    # moves), otherwise the literal version.
    server_awid_floor: str | None = None


@dataclasses.dataclass(frozen=True)
class ArtifactResult:
    disposition: str  # moving | unmoved | moving-with-recovery
    version: str | None
    previous_complete_anchor: tuple[str, str | None] | None = None
    # For recovery rows: the observable identity of the candidate's
    # occupied members, so continue can bind a partial to the card's
    # source (C3); None where the member kinds expose no identity.
    candidate_source_identity: str | None = None


@dataclasses.dataclass(frozen=True)
class Stop:
    code: str
    artifact: str | None = None
    # What the refusal knows beyond its name: the failing command's
    # output, the conflicting value. A stop the operator cannot act on
    # is a stop that sends them to re-run the thing by hand.
    detail: str | None = None


@dataclasses.dataclass(frozen=True)
class NormalizerResult:
    outcome: str  # normal-form | patch-needed | stop
    artifacts: dict[str, ArtifactResult]
    patches: tuple[tuple[str, str, str], ...]
    stops: tuple[Stop, ...]
    # (owner artifact, from, to) consumer-floor edits - the R1 policy's
    # patch half; the owner's manifest file carries the literal.
    floor_patches: tuple[tuple[str, str, str], ...] = ()

    def serialize(self) -> bytes:
        import json

        return json.dumps(
            {
                "outcome": self.outcome,
                "artifacts": {
                    name: dataclasses.asdict(result)
                    for name, result in sorted(self.artifacts.items())
                },
                "patches": self.patches,
                "floor_patches": self.floor_patches,
                "stops": [dataclasses.asdict(s) for s in self.stops],
            },
            sort_keys=True,
        ).encode()


def _artifact_result(
    name: str,
    captured: CapturedArtifact,
    reconciliation: Reconciliation,
    compatibility: str,
) -> tuple[ArtifactResult | None, tuple[str, str, str] | None, Stop | None]:
    if reconciliation.state == "stop":
        return None, None, Stop(reconciliation.stop or "member-stop", name)
    if reconciliation.state == "conflicting-partial":
        return None, None, Stop("conflicting-partial", name)
    if reconciliation.state == "recoverable-partial":
        return (
            ArtifactResult(
                disposition="moving-with-recovery",
                version=reconciliation.candidate,
                previous_complete_anchor=(
                    reconciliation.p or "",
                    captured.anchor_versions.get(reconciliation.p or ""),
                ),
                candidate_source_identity=reconciliation.source_identity,
            ),
            None,
            None,
        )
    # reconciled (p may be None when nothing was ever published)
    p = reconciliation.p or "0.0.0"
    occupied = frozenset(
        v for m in captured.members for v in m.occupied
    ) | set(captured.anchor_versions) | {p}
    decision = movement_decision(
        content_changed=captured.content_changed,
        manifest_version=captured.manifest_version,
        reconciled_p=p,
        occupied_versions=frozenset(occupied),
        compatibility=compatibility,
        derivation=captured.derivation,
    )
    if decision.kind == "stop":
        return None, None, Stop(decision.stop or "movement-stop", name)
    if decision.kind == "unmoved":
        return (
            ArtifactResult(
                disposition="unmoved",
                version=decision.version,
                previous_complete_anchor=(
                    p,
                    captured.anchor_versions.get(p),
                ),
            ),
            None,
            None,
        )
    patch = None
    if decision.patch is not None:
        patch = (name, decision.patch[0], decision.patch[1])
    return ArtifactResult(disposition="moving", version=decision.version), patch, None


def normalize(world: CapturedWorld) -> NormalizerResult:
    """Compose reconciliation, equality groups, the movement table, and
    the same-cycle consumer-floor policy into the complete result. Pure
    over the captured world.

    The R1 floor edge runs as a closure: if awid-service moves to M and
    the captured floor literal differs, the floor edit changes server's
    shipped content, so the whole computation reruns with aweb-server's
    content flipped - the induced server (and by equality gateway)
    movement comes out of THIS pass, which is what lets the fixed-point
    pass on the patched tree come back empty.
    """

    result = _normalize_once(world)
    floor = world.server_awid_floor
    if floor is None:
        return result
    awid = result.artifacts.get("awid-service")
    moving = awid is not None and awid.disposition in (
        "moving",
        "moving-with-recovery",
    )
    if not moving or awid.version is None or floor == awid.version:
        return result
    if not floor:
        stops = tuple(
            sorted(
                [*result.stops, Stop("floor-literal-missing", "aweb-server")],
                key=lambda s: (s.code, s.artifact or ""),
            )
        )
        return dataclasses.replace(result, outcome="stop", stops=stops)
    flipped = dataclasses.replace(
        world,
        artifacts={
            **world.artifacts,
            "aweb-server": dataclasses.replace(
                world.artifacts["aweb-server"], content_changed=True
            ),
        },
    )
    induced = _normalize_once(flipped)
    # The flip touches exactly one field of one artifact, and today's
    # equality groups are disjoint - but that invariance is relied on,
    # so it is checked: an awid row that changed across the two passes
    # means a coupling this closure does not model.
    for name in ("awid-service", "awid-image"):
        if induced.artifacts.get(name) != result.artifacts.get(name):
            return dataclasses.replace(
                result,
                outcome="stop",
                stops=tuple(
                    sorted(
                        [*result.stops, Stop("floor-closure-coupling", name)],
                        key=lambda s: (s.code, s.artifact or ""),
                    )
                ),
            )
    floor_patch = ("aweb-server", floor, awid.version)
    outcome = "stop" if induced.stops else "patch-needed"
    return dataclasses.replace(
        induced, outcome=outcome, floor_patches=(floor_patch,)
    )


def _normalize_once(world: CapturedWorld) -> NormalizerResult:
    """Reconciliation, equality groups, and the movement table alone."""

    grouped = {name for group in world.equality_groups for name in group}
    artifacts: dict[str, ArtifactResult] = {}
    patches: list[tuple[str, str, str]] = []
    stops: list[Stop] = []

    reconciliations = {
        name: reconcile_unit(
            members=captured.members,
            anchor_versions=captured.anchor_versions,
            manifest_intent=captured.manifest_version,
        )
        for name, captured in world.artifacts.items()
    }

    for name, captured in world.artifacts.items():
        if name in grouped:
            continue
        result, patch, stop = _artifact_result(
            name, captured, reconciliations[name], world.compatibility
        )
        if stop is not None:
            stops.append(stop)
        if result is not None:
            artifacts[name] = result
        if patch is not None:
            patches.append(patch)

    for group in world.equality_groups:
        decision = group_decision(
            members=[
                GroupMember(
                    name=name,
                    reconciliation=reconciliations[name],
                    content_changed=world.artifacts[name].content_changed,
                )
                for name in group
            ],
            manifest_versions={
                name: world.artifacts[name].manifest_version for name in group
            },
            compatibility=world.compatibility,
        )
        if decision.kind == "stop":
            stops.append(Stop(decision.stop or "group-stop", "+".join(group)))
            continue
        for name in group:
            recon = reconciliations[name]
            if name in decision.recovering:
                artifacts[name] = ArtifactResult(
                    disposition="moving-with-recovery",
                    version=decision.version,
                    previous_complete_anchor=(
                        recon.p or "",
                        world.artifacts[name].anchor_versions.get(recon.p or ""),
                    ),
                    candidate_source_identity=recon.source_identity,
                )
            elif recon.state == "reconciled" and recon.p == decision.version:
                # A member already COMPLETE at the group's candidate is
                # not moving: the candidate is not a version it is about
                # to take, and when the candidate is M its occupancy is
                # the precondition for sharing M (design section 3 step
                # 3 marks only the LAGGING members). Labelling it moving
                # made the exit re-observation read the member's own
                # existing release as a collision. This subsumes the
                # whole-group unmoved decision, where every member is
                # complete at M by construction.
                artifacts[name] = ArtifactResult(
                    disposition="unmoved",
                    version=decision.version,
                    previous_complete_anchor=(
                        recon.p or "",
                        world.artifacts[name].anchor_versions.get(recon.p or ""),
                    ),
                )
            else:
                artifacts[name] = ArtifactResult(
                    disposition="moving", version=decision.version
                )
        if decision.patch:
            patches.extend(decision.patch)

    patches.sort()
    if stops:
        outcome = "stop"
    elif patches:
        outcome = "patch-needed"
    else:
        outcome = "normal-form"
    return NormalizerResult(
        outcome=outcome,
        artifacts=artifacts,
        patches=tuple(patches),
        stops=tuple(sorted(stops, key=lambda s: (s.code, s.artifact or ""))),
    )

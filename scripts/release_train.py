#!/usr/bin/env python3
"""Fixed release inventory and transient-card primitives.

This module deliberately contains no operator command and performs no outward
release action.  It is the literal, testable foundation shared later by the two
approved release commands: one fixed inventory, ten fixed edges, one git-local
card, and narrow subprocess/HTTP observation boundaries.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence


class ReleaseTrainError(RuntimeError):
    """Base error for the fixed release train foundation."""


class ValidationError(ReleaseTrainError):
    """Material release input is not in its strict accepted form."""


class CardError(ReleaseTrainError):
    """Base error for transient release-card failures."""


class CardUnavailable(CardError):
    """The fixed card is missing or has already been consumed."""


class CardFormatError(CardError):
    """The fixed card cannot be parsed without guessing."""


class MaterialMismatch(CardError):
    """Observed material differs from the approved card."""


class CommandUnavailable(ReleaseTrainError):
    """A bounded local command could not be observed."""


class CommandFailed(ReleaseTrainError):
    """A bounded local command completed unsuccessfully."""


class ObservationUnavailable(ReleaseTrainError):
    """A registry observation was transiently unavailable."""


class ObservationMalformed(ReleaseTrainError):
    """A registry returned evidence whose meaning is not exact."""


@dataclasses.dataclass(frozen=True)
class Anchor:
    """Source anchor for one artifact's published versions.

    kind is "tag_pattern" (value: the tag prefix the publisher emits) or
    "oci_revision_label" (value: the label name stamped into the image
    config and read back from the registry).
    """

    kind: str
    value: str


@dataclasses.dataclass(frozen=True)
class OwnedLock:
    """A lockfile whose content follows its artifact's manifest, with the
    offline regeneration method that keeps it coherent pre-publication."""

    path: str
    method: str


@dataclasses.dataclass(frozen=True)
class Artifact:
    key: str
    repository: str
    name: str
    targets: tuple[str, ...]
    version_source: str | None
    outputs: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    bundled_inputs: tuple[str, ...] = ()
    external_repository: str | None = None
    # aben canonical metadata (docs/aben-design.md section 1). content_scope
    # names the paths whose change constitutes movement, excluding the
    # artifact's own version manifest and owned locks so normalization has
    # a fixed point. occupancy_unit lists the same-version targets that
    # must reconcile to one published version. required_current_outputs is
    # the within-member completeness set the read-back verifies.
    content_scope: tuple[str, ...] = ()
    anchor: Anchor | None = None
    occupancy_unit: tuple[str, ...] = ()
    required_current_outputs: tuple[str, ...] = ()
    owned_locks: tuple[OwnedLock, ...] = ()


@dataclasses.dataclass(frozen=True)
class ReleaseEdge:
    number: int
    kind: str
    nodes: tuple[str, ...]
    rule: str
    # aben typed obligations (docs/aben-design.md sections 1 and 4): each
    # entry is (obligation_type, reference) where the reference names the
    # rule-table row or the enforcing invariant. Domain equality per type
    # is contract-tested; an edge may carry several obligations and the
    # sites edge deliberately carries none.
    obligations: tuple[tuple[str, str], ...] = ()


AW_NPM_PACKAGES = (
    "@awebai/aw",
    "@awebai/aw-linux-x64",
    "@awebai/aw-linux-arm64",
    "@awebai/aw-darwin-x64",
    "@awebai/aw-darwin-arm64",
    "@awebai/aw-windows-x64",
    "@awebai/aw-windows-arm64",
)
AW_BINARIES = ("aw", "aweb-a2a-gw")
AW_RELEASE_ASSETS = (
    "aw_{version}_linux_amd64.tar.gz",
    "aw_{version}_linux_arm64.tar.gz",
    "aw_{version}_darwin_amd64.tar.gz",
    "aw_{version}_darwin_arm64.tar.gz",
    "aw_{version}_windows_amd64.zip",
    "aw_{version}_windows_arm64.zip",
    "checksums.txt",
)
SKILL_SOURCES = (
    "aweb-coordination",
    "aweb-messaging",
    "aweb-team-membership",
    "aweb-bootstrap",
    "aweb-identity",
)
SKILL_ZIPS = tuple(f"{name}.zip" for name in SKILL_SOURCES)
OCI_PLATFORMS = ("linux/amd64", "linux/arm64")
CARD_GIT_PATH = "aweb-release-card.json"


ARTIFACTS = (
    Artifact(
        "aweb-server",
        "aweb",
        "aweb server",
        ("pypi:aweb",),
        "server/pyproject.toml",
        content_scope=("server/",),
        anchor=Anchor("tag_pattern", "server-v"),
        occupancy_unit=("pypi:aweb",),
        owned_locks=(OwnedLock("server/uv.lock", "uv-lock-offline"),),
    ),
    Artifact(
        "awid-service",
        "aweb",
        "AWID service",
        ("pypi:awid-service",),
        "awid/pyproject.toml",
        content_scope=("awid/",),
        anchor=Anchor("tag_pattern", "awid-service-v"),
        occupancy_unit=("pypi:awid-service",),
        owned_locks=(OwnedLock("awid/uv.lock", "uv-lock-offline"),),
    ),
    Artifact(
        "awid-image",
        "aweb",
        "AWID image",
        ("ghcr.io/awebai/awid",),
        "awid/pyproject.toml",
        platforms=OCI_PLATFORMS,
        bundled_inputs=("server-source",),
        content_scope=("awid/", "server/"),
        anchor=Anchor("tag_pattern", "awid-v"),
        occupancy_unit=("ghcr.io/awebai/awid",),
        required_current_outputs=OCI_PLATFORMS,
    ),
    Artifact(
        "aw-cli",
        "aweb",
        "aw CLI",
        ("github:awebai/aw:release",)
        + tuple(f"npm:{package}" for package in AW_NPM_PACKAGES),
        "tag-history:aw-v*",
        outputs=AW_BINARIES,
        external_repository="awebai/aw",
        content_scope=("cli/go/",),
        anchor=Anchor("tag_pattern", "aw-v"),
        occupancy_unit=("github:awebai/aw:release",)
        + tuple(f"npm:{package}" for package in AW_NPM_PACKAGES),
        required_current_outputs=AW_RELEASE_ASSETS,
    ),
    Artifact(
        "channel-plugin",
        "aweb",
        "channel plugin",
        ("npm:@awebai/claude-channel",),
        "channel/package.json",
        bundled_inputs=("channel-core",),
        content_scope=("channel/", "channel-core/"),
        anchor=Anchor("tag_pattern", "channel-v"),
        occupancy_unit=("npm:@awebai/claude-channel",),
    ),
    Artifact(
        "pi-extension",
        "aweb",
        "Pi extension",
        ("npm:@awebai/pi",),
        "pi-extension/package.json",
        bundled_inputs=("channel-core",) + SKILL_SOURCES,
        content_scope=("pi-extension/", "channel-core/", "skills/"),
        anchor=Anchor("tag_pattern", "pi-v"),
        occupancy_unit=("npm:@awebai/pi",),
    ),
    Artifact(
        "skills",
        "aweb",
        "skills",
        (
            "npm:@awebai/claude-skills",
            "github:awebai/aweb:skills-release-zips",
        ),
        "packages/claude-skills/package.json",
        outputs=SKILL_ZIPS,
        bundled_inputs=SKILL_SOURCES,
        content_scope=("packages/claude-skills/", "skills/"),
        anchor=Anchor("tag_pattern", "skills-v"),
        occupancy_unit=(
            "npm:@awebai/claude-skills",
            "github:awebai/aweb:skills-release-zips",
        ),
        required_current_outputs=SKILL_ZIPS,
    ),
    Artifact(
        "a2a-gateway-image",
        "aweb",
        "a2a-gateway image",
        ("ghcr.io/awebai/a2a-gateway",),
        "equals:server/pyproject.toml",
        platforms=OCI_PLATFORMS,
        content_scope=("cli/go/",),
        anchor=Anchor("tag_pattern", "a2a-gw-v"),
        occupancy_unit=("ghcr.io/awebai/a2a-gateway",),
        required_current_outputs=OCI_PLATFORMS,
    ),
    Artifact(
        "awid-site",
        "aweb",
        "awid.ai site",
        ("render-static:deploy-awid-landing",),
        None,
    ),
    Artifact(
        "ac-image",
        "ac",
        "product image",
        ("ghcr.io/awebai/ac",),
        "backend/pyproject.toml",
        platforms=OCI_PLATFORMS,
        content_scope=("backend/", "frontend/", "Dockerfile.release"),
        anchor=Anchor("oci_revision_label", "org.opencontainers.image.revision"),
        occupancy_unit=("ghcr.io/awebai/ac",),
        required_current_outputs=OCI_PLATFORMS,
        owned_locks=(OwnedLock("backend/uv.lock", "uv-lock-offline"),),
    ),
    Artifact(
        "ac-production",
        "ac",
        "production deploy",
        ("render:aweb-cloud:image-digest",),
        "image:ghcr.io/awebai/ac@digest",
    ),
    Artifact(
        "aweb-site",
        "ac",
        "aweb.ai site",
        ("render-static:deploy-landing",),
        None,
    ),
)

DAG_EDGES = (
    ReleaseEdge(
        1,
        "ordering",
        ("awid-service", "aweb-server"),
        "public PyPI AWID dependency floor before aweb",
        obligations=(
            ("publication-order", "pypi-release needs:awid_service + floor-served check"),
            ("consumer-version-policy", "R1"),
        ),
    ),
    ReleaseEdge(
        2,
        "ordering",
        ("aw-cli-npm-set", "pi-extension"),
        "all seven aw npm packages served before Pi when its floor moves",
        obligations=(
            ("conditional-publication-order", "npm-release pi lane floor check (iff floor moves)"),
            ("consumer-no-mutation-decision", "R4"),
        ),
    ),
    ReleaseEdge(
        3,
        "ordering",
        ("channel-plugin", "skills", "marketplace-pointer"),
        "channel and skills served before marketplace advance",
        obligations=(("publication-order", "predecessor-rows gate before pointer apply"),),
    ),
    ReleaseEdge(
        4,
        "ordering",
        ("intended-aweb-awid-public", "ac-dependency-commit", "ac-gate"),
        "public packages before derived AC dependency commit and gate",
        obligations=(
            ("publication-order", "predecessor-rows gate before AC derivation"),
            ("post-publication-consumer-derivation", "R2"),
            ("post-publication-consumer-derivation", "R3"),
        ),
    ),
    ReleaseEdge(
        5,
        "ordering",
        ("ac-image", "ac-production", "digest-health-verification"),
        "AC image before deploy before digest and health verification",
        obligations=(("deploy-order", "digest observation is the deploy edge input"),),
    ),
    ReleaseEdge(
        6,
        "same-commit",
        ("channel-core", "channel-plugin", "pi-extension"),
        "one channel-core input in channel and Pi",
        obligations=(("same-commit-content", "content_scope: channel-plugin, pi-extension"),),
    ),
    ReleaseEdge(
        7,
        "same-commit",
        ("skill-source-set", "pi-extension", "skills", "skills-zips"),
        "the same five skill sources in every output",
        obligations=(("same-commit-content", "content_scope: pi-extension, skills"),),
    ),
    ReleaseEdge(
        8,
        "same-commit",
        ("server-source", "awid-image"),
        "server source in the same-commit AWID image",
        obligations=(
            ("same-commit-content", "content_scope: awid-image"),
            ("version-equality", "card invariant: awid-service == awid-image"),
        ),
    ),
    ReleaseEdge(
        9,
        "equality",
        ("a2a-gateway-image", "aweb-server"),
        "a2a-gateway version equals server version",
        obligations=(
            ("same-commit-content", "content_scope: a2a-gateway-image"),
            ("version-equality", "train invariant: a2a-gateway == aweb-server"),
        ),
    ),
    ReleaseEdge(
        10,
        "independent",
        ("awid-site", "aweb-site"),
        "both site branch pushes are independent of the artifact train",
    ),
)

# The AC dependency floors track exactly these PyPI artifacts; when neither
# moves on a card, the derived dependency-only commit is empty by definition
# and the final AC commit is the card's base.
AC_FLOOR_ARTIFACTS = ("awid-service", "aweb-server")

CARD_ARTIFACT_ORDER = (
    "awid-service",
    "aweb-server",
    "awid-image",
    "aw-cli",
    "channel-plugin",
    "pi-extension",
    "skills",
    "a2a-gateway-image",
    "ac-image",
)


_SHA_RE = re.compile(r"[0-9a-f]{40}")
_SEMVER_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:"
    r"(?:0|[1-9][0-9]*)|(?:[A-Za-z-][0-9A-Za-z-]*)"
    r")(?:\.(?:(?:0|[1-9][0-9]*)|(?:[A-Za-z-][0-9A-Za-z-]*)))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def validate_sha(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value) or value == "0" * 40:
        raise ValidationError(f"{name} must be a nonzero lowercase full 40-hex SHA")
    return value


def validate_version(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SEMVER_RE.fullmatch(value):
        raise ValidationError(f"{name} must be a strict semantic version")
    return value


def validate_line(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\n" in value
        or "\r" in value
    ):
        raise ValidationError(f"{name} must be one nonempty, trimmed line")
    return value


def validate_compatibility(value: object) -> str:
    line = validate_line(value, "compatibility")
    if line.lower() == "none" and line != "none":
        raise ValidationError("compatibility uses the exact literal 'none'")
    return line


def _validate_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise ValidationError(f"{name} must be a boolean")
    return value


_DISPOSITIONS = ("moving", "unmoved", "moving-with-recovery")
_ANCHOR_KINDS = ("tag", "oci-revision-label")


@dataclasses.dataclass(frozen=True)
class PreviousCompleteAnchor:
    """The prior complete anchored version and its source identity - the
    card-time fact continuation cannot re-derive (aben design section 7).
    An exact tagged variant: kind is "tag" or "oci-revision-label"."""

    version: str
    kind: str
    source_identity: str

    def __post_init__(self) -> None:
        validate_version(self.version, "previous complete anchor version")
        if self.kind not in _ANCHOR_KINDS:
            raise ValidationError(
                f"previous complete anchor kind must be one of {_ANCHOR_KINDS}"
            )
        validate_sha(self.source_identity, "previous complete anchor identity")


@dataclasses.dataclass(frozen=True)
class ArtifactSelection:
    name: str
    version: str
    moves: bool
    # aben design section 7: the disposition enum strictly extends moves,
    # and the anchor is REQUIRED for unmoved and moving-with-recovery
    # rows, FORBIDDEN for moving rows. disposition defaults from moves so
    # existing moving constructors stay valid; unmoved rows must supply
    # their anchor from card generation.
    disposition: str | None = None
    previous_complete_anchor: PreviousCompleteAnchor | None = None

    def __post_init__(self) -> None:
        validate_line(self.name, "artifact name")
        validate_version(self.version, self.name)
        _validate_bool(self.moves, f"{self.name} moves")
        if self.disposition is None:
            object.__setattr__(
                self, "disposition", "moving" if self.moves else "unmoved"
            )
        if self.disposition not in _DISPOSITIONS:
            raise ValidationError(
                f"{self.name} disposition must be one of {_DISPOSITIONS}"
            )
        expected_moves = self.disposition != "unmoved"
        if self.moves != expected_moves:
            raise ValidationError(
                f"{self.name}: moves={self.moves} contradicts disposition "
                f"{self.disposition}"
            )
        needs_anchor = self.disposition in ("unmoved", "moving-with-recovery")
        if needs_anchor and self.previous_complete_anchor is None:
            raise ValidationError(
                f"{self.name}: disposition {self.disposition} requires "
                "previous_complete_anchor"
            )
        if not needs_anchor and self.previous_complete_anchor is not None:
            raise ValidationError(
                f"{self.name}: disposition moving forbids "
                "previous_complete_anchor"
            )


@dataclasses.dataclass(frozen=True)
class GateEvidence:
    name: str
    sha: str
    result: str
    reference: str
    suites: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_line(self.name, "gate name")
        validate_sha(self.sha, f"{self.name} SHA")
        if self.result not in {"passed", "not-relevant"}:
            raise ValidationError(
                f"{self.name} result must be 'passed' or 'not-relevant'"
            )
        validate_line(self.reference, f"{self.name} reference")
        if not isinstance(self.suites, tuple) or not self.suites:
            raise ValidationError(f"{self.name} must name observed suites")
        for suite in self.suites:
            validate_line(suite, f"{self.name} suite")
        if len(set(self.suites)) != len(self.suites):
            raise ValidationError(f"{self.name} suites must be unique")


@dataclasses.dataclass(frozen=True)
class DeploymentSet:
    production: bool
    awid_site: bool
    aweb_site: bool

    def __post_init__(self) -> None:
        _validate_bool(self.production, "production deployment")
        _validate_bool(self.awid_site, "awid.ai deployment")
        _validate_bool(self.aweb_site, "aweb.ai deployment")


_CARD_FIELDS = {
    "aweb_sha",
    "ac_base_sha",
    "artifacts",
    "compatibility",
    "gates",
    "purpose",
    "deployments",
    "final_ac_sha",
    "first_release_correction_pending",
}
_ARTIFACT_FIELDS = {
    "name",
    "version",
    "moves",
    "disposition",
    "previous_complete_anchor",
}
_GATE_FIELDS = {"name", "sha", "result", "reference", "suites"}
_DEPLOYMENT_FIELDS = {"production", "awid_site", "aweb_site"}


@dataclasses.dataclass(frozen=True)
class ReleaseCard:
    aweb_sha: str
    ac_base_sha: str
    artifacts: tuple[ArtifactSelection, ...]
    compatibility: str
    gates: tuple[GateEvidence, ...]
    purpose: str
    deployments: DeploymentSet
    final_ac_sha: None
    first_release_correction_pending: bool

    def __post_init__(self) -> None:
        validate_sha(self.aweb_sha, "aweb SHA")
        validate_sha(self.ac_base_sha, "AC base SHA")
        if not isinstance(self.artifacts, tuple):
            raise ValidationError("artifacts must be an ordered tuple")
        names = tuple(item.name for item in self.artifacts)
        if names != CARD_ARTIFACT_ORDER:
            raise ValidationError(
                "artifact order/set must equal the fixed DAG-ordered version set"
            )
        versions = {item.name: item.version for item in self.artifacts}
        if versions["a2a-gateway-image"] != versions["aweb-server"]:
            raise ValidationError("a2a-gateway version must equal server version")
        if versions["awid-service"] != versions["awid-image"]:
            raise ValidationError("AWID service version must equal AWID image version")
        validate_compatibility(self.compatibility)
        if not isinstance(self.gates, tuple) or not self.gates:
            raise ValidationError("gate evidence must be a nonempty ordered tuple")
        if len({gate.name for gate in self.gates}) != len(self.gates):
            raise ValidationError("gate evidence names must be unique")
        if any(gate.sha != self.aweb_sha for gate in self.gates):
            raise ValidationError("every gate evidence SHA must equal the aweb SHA")
        validate_line(self.purpose, "purpose")
        if not isinstance(self.deployments, DeploymentSet):
            raise ValidationError("deployments must be a DeploymentSet")
        ac_moves = next(
            item.moves for item in self.artifacts if item.name == "ac-image"
        )
        if self.deployments.production != ac_moves:
            raise ValidationError(
                "production deployment must be inferred exactly from AC image movement"
            )
        _validate_bool(
            self.first_release_correction_pending,
            "first release correction pending",
        )
        if self.first_release_correction_pending and not ac_moves:
            raise ValidationError(
                "first release correction cannot be pending without production deployment"
            )
        if self.final_ac_sha is not None:
            raise ValidationError("final AC SHA must remain pending on the release card")

    @classmethod
    def create(cls, **values: object) -> "ReleaseCard":
        return cls(**values)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, Any]:
        return {
            "aweb_sha": self.aweb_sha,
            "ac_base_sha": self.ac_base_sha,
            "artifacts": [dataclasses.asdict(item) for item in self.artifacts],
            "compatibility": self.compatibility,
            "gates": [dataclasses.asdict(gate) for gate in self.gates],
            "purpose": self.purpose,
            "deployments": dataclasses.asdict(self.deployments),
            "final_ac_sha": self.final_ac_sha,
            "first_release_correction_pending": self.first_release_correction_pending,
        }

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, document: object) -> "ReleaseCard":
        card = _require_mapping(document, "card")
        _require_keys(card, _CARD_FIELDS, "card")

        raw_artifacts = card["artifacts"]
        if not isinstance(raw_artifacts, list):
            raise CardFormatError("card artifacts must be a list")
        artifacts: list[ArtifactSelection] = []
        for index, raw in enumerate(raw_artifacts):
            item = _require_mapping(raw, f"artifact {index}")
            _require_keys(item, _ARTIFACT_FIELDS, f"artifact {index}")
            raw_anchor = item["previous_complete_anchor"]
            anchor = None
            if raw_anchor is not None:
                anchor_map = _require_mapping(raw_anchor, f"artifact {index} anchor")
                _require_keys(
                    anchor_map,
                    {"version", "kind", "source_identity"},
                    f"artifact {index} anchor",
                )
                try:
                    anchor = PreviousCompleteAnchor(
                        anchor_map["version"],
                        anchor_map["kind"],
                        anchor_map["source_identity"],
                    )
                except ValidationError as error:
                    raise CardFormatError(str(error)) from error
            try:
                artifacts.append(
                    ArtifactSelection(
                        item["name"],
                        item["version"],
                        item["moves"],
                        disposition=item["disposition"],
                        previous_complete_anchor=anchor,
                    )
                )
            except ValidationError as error:
                raise CardFormatError(str(error)) from error

        raw_gates = card["gates"]
        if not isinstance(raw_gates, list):
            raise CardFormatError("card gates must be a list")
        gates: list[GateEvidence] = []
        for index, raw in enumerate(raw_gates):
            item = _require_mapping(raw, f"gate {index}")
            _require_keys(item, _GATE_FIELDS, f"gate {index}")
            suites = item["suites"]
            if not isinstance(suites, list):
                raise CardFormatError(f"gate {index} suites must be a list")
            try:
                gates.append(
                    GateEvidence(
                        item["name"],
                        item["sha"],
                        item["result"],
                        item["reference"],
                        tuple(suites),
                    )
                )
            except ValidationError as error:
                raise CardFormatError(str(error)) from error

        raw_deployments = _require_mapping(card["deployments"], "deployments")
        _require_keys(raw_deployments, _DEPLOYMENT_FIELDS, "deployments")
        try:
            deployments = DeploymentSet(
                raw_deployments["production"],
                raw_deployments["awid_site"],
                raw_deployments["aweb_site"],
            )
            return cls(
                card["aweb_sha"],
                card["ac_base_sha"],
                tuple(artifacts),
                card["compatibility"],
                tuple(gates),
                card["purpose"],
                deployments,
                card["final_ac_sha"],
                card["first_release_correction_pending"],
            )
        except ValidationError as error:
            raise CardFormatError(str(error)) from error


def _require_mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CardFormatError(f"{name} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise CardFormatError(f"{name} field names must be strings")
    return value


def _require_keys(
    value: Mapping[str, Any], expected: set[str], name: str
) -> None:
    actual = set(value)
    unknown = sorted(actual - expected)
    if unknown:
        raise CardFormatError(f"{name} has unknown fields: {', '.join(unknown)}")
    missing = sorted(expected - actual)
    if missing:
        raise CardFormatError(f"{name} is missing fields: {', '.join(missing)}")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CardFormatError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _parse_json_bytes(body: bytes, name: str) -> object:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CardFormatError(f"{name} is not UTF-8") from error
    try:
        return json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except CardFormatError:
        raise
    except (json.JSONDecodeError, ValueError) as error:
        raise CardFormatError(f"{name} is malformed JSON") from error


@dataclasses.dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    stdout: str
    stderr: str


# Work commands - gate suites, publish workflows, deploys - run for hours;
# a registry or HTTP observation that takes that long is a hang, not work.
# Observations keep the tight default bound.
WORK_TIMEOUT = 6 * 3600.0


def _bounded_timeout(timeout: object, *, limit: float = 600.0) -> float:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
        or timeout > limit
    ):
        raise ValidationError(
            f"timeout must be greater than zero and at most {limit:g} seconds"
        )
    return float(timeout)


def run_command(
    args: Sequence[str], *, cwd: Path, timeout: float
) -> CommandResult:
    """Run one explicit argv with a bounded timeout; never invoke a shell."""

    if not args or any(not isinstance(arg, str) or not arg for arg in args):
        raise ValidationError("command argv must contain nonempty strings")
    bounded = _bounded_timeout(timeout, limit=86400.0)
    try:
        completed = subprocess.run(
            list(args),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=bounded,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise CommandUnavailable(
            f"command timed out after {bounded:g}s: {args[0]}"
        ) from error
    except FileNotFoundError as error:
        raise CommandUnavailable(f"command is not available: {args[0]}") from error
    except OSError as error:
        raise CommandUnavailable(f"command could not start: {args[0]}: {error}") from error
    if completed.returncode != 0:
        raise CommandFailed(
            f"command exited with exit {completed.returncode}: {args[0]}: "
            f"{completed.stderr.strip()}"
        )
    return CommandResult(tuple(args), completed.stdout, completed.stderr)


def card_path(repository: Path) -> Path:
    repository = Path(repository).resolve()
    result = run_command(
        ["git", "rev-parse", "--git-path", CARD_GIT_PATH],
        cwd=repository,
        timeout=10,
    )
    raw_path = result.stdout.strip()
    if not raw_path or "\n" in raw_path or "\r" in raw_path:
        raise CardError("git returned an invalid card path")
    path = Path(raw_path)
    if not path.is_absolute():
        path = repository / path
    return path.resolve()


def read_card(repository: Path) -> ReleaseCard:
    path = card_path(repository)
    try:
        body = path.read_bytes()
    except FileNotFoundError as error:
        raise CardUnavailable(
            f"release card is missing or consumed: {path}"
        ) from error
    except OSError as error:
        raise CardError(f"cannot read release card {path}: {error}") from error
    return ReleaseCard.from_dict(_parse_json_bytes(body, "release card"))


def assert_material_matches(expected: ReleaseCard, observed: ReleaseCard) -> None:
    expected_document = expected.to_dict()
    observed_document = observed.to_dict()
    changed = sorted(
        key
        for key in _CARD_FIELDS
        if expected_document[key] != observed_document[key]
    )
    if changed:
        raise MaterialMismatch(
            "release card material changed: " + ", ".join(changed)
        )


def write_card(repository: Path, card: ReleaseCard) -> Path:
    path = card_path(repository)
    if path.exists():
        existing = read_card(repository)
        if (
            existing.aweb_sha == card.aweb_sha
            and existing.ac_base_sha == card.ac_base_sha
        ):
            assert_material_matches(card, existing)
            return path
        # The incoming card carries the freshly observed origin mains.
        # Liveness of the stored card is continue's own predicate
        # (_dependency_only_derived_child, shared with continue_environment):
        # a card whose AC main sits at its derived child is mid-continue and
        # must be finished, not destroyed.
        if existing.aweb_sha == card.aweb_sha and _dependency_only_derived_child(
            (Path(repository).resolve().parent / "ac").resolve(),
            existing.ac_base_sha,
            card.ac_base_sha,
        ):
            raise MaterialMismatch(
                "the stored card is still executable: AC main is its derived "
                "dependency-only child; rerun release-continue to finish it"
            )
        # Otherwise the mains have moved past the stored card, continue could
        # never execute it, and prepare overwrites it atomically below rather
        # than depending on an operator to delete a file.
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            os.chmod(temporary.name, 0o600)
            temporary.write(card.canonical_bytes())
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    except OSError as error:
        raise CardError(f"cannot write release card {path}: {error}") from error
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    return path


def consume_card(repository: Path, expected: ReleaseCard) -> None:
    path = card_path(repository)
    observed = read_card(repository)
    assert_material_matches(expected, observed)
    try:
        path.unlink()
    except FileNotFoundError as error:
        raise CardUnavailable(
            f"release card is missing or consumed: {path}"
        ) from error
    except OSError as error:
        raise CardError(f"cannot consume release card {path}: {error}") from error


class RegistryOutcome(enum.Enum):
    ABSENT = "absent"
    EXACT = "exact"
    CONFLICT = "conflict"


def _validate_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValidationError(f"{name} must be a lowercase sha256 digest")
    return value


def observe_registry(
    url: str,
    expected_version: str,
    expected_digest: str,
    *,
    timeout: float,
) -> RegistryOutcome:
    """Observe one exact registry item without turning outages into absence."""

    validate_line(url, "registry URL")
    validate_version(expected_version, "expected registry version")
    _validate_digest(expected_digest, "expected registry digest")
    bounded = _bounded_timeout(timeout)
    request = urllib.request.Request(
        url, headers={"Accept": "application/json"}, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=bounded) as response:
            if response.status != 200:
                raise ObservationUnavailable(
                    f"registry observation returned HTTP {response.status}"
                )
            body = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        if code == 404:
            return RegistryOutcome.ABSENT
        raise ObservationUnavailable(
            f"registry observation returned HTTP {code}"
        ) from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ObservationUnavailable(f"registry observation unavailable: {error}") from error
    if len(body) > 1024 * 1024:
        raise ObservationMalformed("registry evidence exceeds 1 MiB")
    try:
        document = _parse_json_bytes(body, "registry evidence")
    except CardFormatError as error:
        raise ObservationMalformed(str(error)) from error
    evidence = _require_registry_mapping(document)
    state = evidence.get("state")
    if state != "present":
        raise ObservationMalformed(
            "registry evidence state must be present; absence requires HTTP 404"
        )
    if set(evidence) != {"state", "version", "digest"}:
        raise ObservationMalformed(
            "present registry evidence requires exactly state, version, and digest"
        )
    try:
        observed_version = validate_version(evidence["version"], "registry version")
        observed_digest = _validate_digest(evidence["digest"], "registry digest")
    except ValidationError as error:
        raise ObservationMalformed(str(error)) from error
    if (
        observed_version == expected_version
        and observed_digest == expected_digest
    ):
        return RegistryOutcome.EXACT
    return RegistryOutcome.CONFLICT


def _require_registry_mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ObservationMalformed("registry evidence must be a JSON object")
    return value


# --- release-prepare -------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class PreparedEnvironment:
    aweb_root: Path
    ac_root: Path
    aweb_sha: str
    ac_sha: str
    purpose: str
    compatibility: str


def _git(repository: Path, *args: str, timeout: float = 120) -> CommandResult:
    return run_command(["git", *args], cwd=repository, timeout=timeout)


def _require_origin(repository: Path, name: str) -> None:
    url = _git(repository, "remote", "get-url", "origin").stdout.strip().rstrip("/")
    if not (url.endswith(f"awebai/{name}") or url.endswith(f"awebai/{name}.git")):
        raise ValidationError(
            f"the {name} origin must be the canonical awebai/{name} remote; found "
            f"{url or '<none>'}. Fix: run release-prepare from checkouts cloned "
            f"from the canonical remotes"
        )


def _require_clean(repository: Path, label: str) -> None:
    status = _git(repository, "status", "--porcelain").stdout
    if status.strip():
        raise ValidationError(
            f"the {label} working tree is not clean:\n{status}"
            f"Fix: commit and push, or remove the listed paths, then rerun "
            f"release-prepare"
        )


def _select_tip(repository: Path, label: str, override: str | None) -> str:
    _git(repository, "fetch", "origin")
    remote_main = _git(repository, "rev-parse", "refs/remotes/origin/main").stdout.strip()
    if override is None:
        return validate_sha(remote_main, f"{label} origin/main tip")
    sha = validate_sha(override, f"{label} override")
    try:
        _git(repository, "merge-base", "--is-ancestor", sha, remote_main)
    except CommandFailed as error:
        raise ValidationError(
            f"the {label} override {sha} is not reachable from origin/main. "
            f"Fix: land it on main and push before naming it"
        ) from error
    return sha


def prepare_environment(
    repo_root: Path, environment: Mapping[str, str]
) -> PreparedEnvironment:
    repo_root = Path(repo_root).resolve()
    toplevel = Path(
        _git(repo_root, "rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()
    if toplevel != repo_root:
        raise ValidationError(
            f"release-prepare runs only from the canonical aweb repository root: "
            f"{toplevel}. Fix: cd {toplevel} and rerun"
        )
    _require_origin(repo_root, "aweb")
    ac_root = (repo_root.parent / "ac").resolve()
    if not (ac_root / ".git").exists():
        raise ValidationError(
            f"the sibling ../ac checkout is missing at {ac_root}. Fix: clone "
            f"the canonical awebai/ac remote next to this repository"
        )
    _require_origin(ac_root, "ac")
    purpose = validate_line(environment.get("PURPOSE"), "PURPOSE")
    compatibility = validate_compatibility(environment.get("COMPAT_BREAK"))
    for repository, label in ((repo_root, "aweb"), (ac_root, "ac")):
        _require_clean(repository, label)
    aweb_sha = _select_tip(repo_root, "aweb", environment.get("AWEB_SHA"))
    ac_sha = _select_tip(ac_root, "ac", environment.get("AC_SHA"))
    return PreparedEnvironment(
        aweb_root=repo_root,
        ac_root=ac_root,
        aweb_sha=aweb_sha,
        ac_sha=ac_sha,
        purpose=purpose,
        compatibility=compatibility,
    )


SITE_DEPLOYMENTS = {
    "awid-site": ("aweb", "deploy-awid-landing", ("awid/site",)),
    "aweb-site": ("ac", "deploy-landing", ("site",)),
}


def _artifact(key: str) -> Artifact:
    for item in ARTIFACTS:
        if item.key == key:
            return item
    raise ValidationError(f"unknown artifact: {key}")


def _read_manifest_version(prepared: PreparedEnvironment, artifact: Artifact) -> str:
    source = artifact.version_source
    repository = prepared.aweb_root if artifact.repository == "aweb" else prepared.ac_root
    sha = prepared.aweb_sha if artifact.repository == "aweb" else prepared.ac_sha
    if source is None:
        raise ValidationError(f"{artifact.key} has no manifest version source")
    if source.startswith("equals:"):
        return _read_manifest_version(prepared, _artifact("aweb-server"))
    if source.startswith("tag-history:"):
        pattern = source.split(":", 1)[1]
        listed = _git(repository, "tag", "--list", pattern).stdout.split()
        versions = []
        for tag in listed:
            candidate = tag.removeprefix("aw-v")
            if _SEMVER_RE.fullmatch(candidate):
                versions.append(tuple(int(part) for part in candidate.split("-")[0].split(".")))
        if not versions:
            raise ObservationUnavailable(
                f"{artifact.key} has no {pattern} tag history to derive the next version"
            )
        newest = max(versions)
        newest_tag = f"aw-v{newest[0]}.{newest[1]}.{newest[2]}"
        # The next patch exists only if the synced cli/go tree changed since
        # the newest tag; otherwise the intended version IS the newest tag's,
        # already published, and the artifact does not move. Deriving
        # newest+1 unconditionally would mint a contentless aw release on
        # every train run after the first (observed at 0.7.14 prepare:
        # derived 1.34.5 with zero cli-scope changes since aw-v1.34.4).
        try:
            _git(repository, "diff", "--quiet", newest_tag, sha, "--", "cli/go")
        except CommandFailed:
            return f"{newest[0]}.{newest[1]}.{newest[2] + 1}"
        return f"{newest[0]}.{newest[1]}.{newest[2]}"
    body = _git(repository, "show", f"{sha}:{source}").stdout
    if source.endswith("pyproject.toml"):
        document = tomllib.loads(body)
        return validate_version(
            document.get("project", {}).get("version"), f"{artifact.key} version"
        )
    if source.endswith("package.json"):
        document = _parse_json_bytes(body.encode(), f"{artifact.key} manifest")
        if not isinstance(document, dict):
            raise ObservationMalformed(f"{artifact.key} manifest must be an object")
        return validate_version(document.get("version"), f"{artifact.key} version")
    raise ValidationError(f"{artifact.key} version source is not recognized: {source}")


def observe_registry_presence(url: str, expected_version: str, *, timeout: float) -> bool:
    """True when the registry serves exactly this version; False on HTTP 404."""

    validate_line(url, "registry URL")
    validate_version(expected_version, "expected registry version")
    bounded = _bounded_timeout(timeout)
    request = urllib.request.Request(
        url, headers={"Accept": "application/json"}, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=bounded) as response:
            if response.status != 200:
                raise ObservationUnavailable(
                    f"registry observation returned HTTP {response.status}"
                )
            body = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        if code == 404:
            return False
        raise ObservationUnavailable(
            f"registry observation returned HTTP {code}"
        ) from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ObservationUnavailable(f"registry observation unavailable: {error}") from error
    if len(body) > 1024 * 1024:
        raise ObservationMalformed("registry evidence exceeds 1 MiB")
    evidence = _require_registry_mapping(_parse_json_bytes(body, "registry evidence"))
    if evidence.get("state") != "present":
        raise ObservationMalformed(
            "registry evidence state must be present; absence requires HTTP 404"
        )
    observed = validate_version(evidence.get("version"), "registry version")
    if observed != expected_version:
        raise ObservationMalformed(
            f"registry serves version {observed} where {expected_version} was "
            f"queried; same-version conflict"
        )
    return True


def _resolve_anchor_identity(
    prepared: PreparedEnvironment, artifact: Artifact, version: str, *, timeout: float
) -> PreviousCompleteAnchor:
    """The unmoved row's anchor: its published version's source identity,
    read from where the anchor actually lives (aben design section 7).

    Tag anchors resolve on the artifact's repository origin with annotated
    tags peeled - the same direct/peeled semantics as the shared shell
    helper. The OCI revision label resolves from the registry through the
    adoption reader's contract; unavailability raises rather than
    guessing, because an unmoved row without a provable anchor is not an
    unmoved row.
    """

    if artifact.anchor is None:
        raise ValidationError(f"{artifact.key} has no canonical anchor")
    if artifact.anchor.kind == "tag_pattern":
        repository = (
            prepared.aweb_root if artifact.repository == "aweb" else prepared.ac_root
        )
        tag = f"{artifact.anchor.value}{version}"
        lines = _git(
            repository, "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"
        ).stdout.splitlines()
        direct = peeled = None
        for line in lines:
            sha, ref = line.split(None, 1)
            if ref.endswith("^{}"):
                peeled = sha
            else:
                direct = sha
        identity = peeled or direct
        if identity is None:
            raise ObservationUnavailable(
                f"{artifact.key}: anchor tag {tag} absent while the registry "
                "serves the version - anchorless unmoved row"
            )
        return PreviousCompleteAnchor(version, "tag", identity)
    # oci_revision_label: the image config's revision label, read from
    # the registry (aben R5 - the reader that made R4's refusal here
    # unnecessary rather than tolerated).
    import release_normalizer_capture as _cap

    image = artifact.targets[0].removeprefix("ghcr.io/")
    try:
        identity = _cap.read_oci_revision(
            image,
            version,
            token=os.environ.get("AWEB_GHCR_READ_TOKEN", ""),
            timeout=timeout,
        )
    except _cap.DiscoveryUnavailable as error:
        raise ObservationUnavailable(str(error)) from error
    return PreviousCompleteAnchor(version, "oci-revision-label", identity)


_ANCHOR_KIND_BY_METADATA = {
    "tag_pattern": "tag",
    "oci_revision_label": "oci-revision-label",
}


def selections_from_projection(result) -> tuple[ArtifactSelection, ...]:
    """Card rows from the normalizer's projection (aben amendment A5,
    shipment finding 2): every disposition shape the reconciler can
    produce - moving, unmoved, moving-with-recovery - reaches the card,
    with anchors carried from the projection under the canonical
    entry's anchor kind. A row whose disposition requires an anchor
    fails closed when the projection cannot supply an identityful one;
    a projection missing a canonical artifact fails closed by name.
    """

    if result.outcome == "stop":
        raise ValidationError(
            "the normalizer projection carries stops; a card is never built "
            "past a refusal: "
            + ", ".join(
                f"{s.code}({s.artifact})" if s.artifact else s.code
                for s in result.stops
            )
        )
    selections = []
    for name in CARD_ARTIFACT_ORDER:
        row = result.artifacts.get(name)
        if row is None or row.version is None:
            raise ValidationError(
                f"the normalizer projection carries no {name} row; a card "
                "cannot be built from a partial projection"
            )
        anchor = None
        if row.disposition in ("unmoved", "moving-with-recovery"):
            pca = row.previous_complete_anchor
            if pca is None or not pca[0] or pca[1] is None:
                raise ValidationError(
                    f"{name} is {row.disposition} but the projection's "
                    "previous complete anchor is missing or identityless"
                )
            anchor = PreviousCompleteAnchor(
                version=pca[0],
                kind=_ANCHOR_KIND_BY_METADATA[_artifact_entry(name).anchor.kind],
                source_identity=pca[1],
            )
        selections.append(
            ArtifactSelection(
                name=name,
                version=row.version,
                moves=row.disposition != "unmoved",
                disposition=row.disposition,
                previous_complete_anchor=anchor,
            )
        )
    return tuple(selections)


def _artifact_entry(key: str):
    for entry in ARTIFACTS:
        if entry.key == key:
            return entry
    raise ValidationError(f"unknown canonical artifact {key!r}")


def check_plugin_equality(prepared: PreparedEnvironment) -> None:
    pairs = (
        ("channel-plugin", "channel/.claude-plugin/plugin.json", "channel/package.json"),
        ("skills", "packages/claude-skills/.claude-plugin/plugin.json", "packages/claude-skills/package.json"),
    )
    for name, plugin_path, package_path in pairs:
        try:
            plugin_body = _git(
                prepared.aweb_root, "show", f"{prepared.aweb_sha}:{plugin_path}"
            ).stdout
        except CommandFailed:
            continue
        package_body = _git(
            prepared.aweb_root, "show", f"{prepared.aweb_sha}:{package_path}"
        ).stdout
        plugin = _parse_json_bytes(plugin_body.encode(), f"{name} plugin manifest")
        package = _parse_json_bytes(package_body.encode(), f"{name} package manifest")
        if not isinstance(plugin, dict) or not isinstance(package, dict):
            raise ObservationMalformed(f"{name} manifests must be objects")
        if plugin.get("version") != package.get("version"):
            raise ValidationError(
                f"{name} committed plugin.json version {plugin.get('version')!r} "
                f"must equal package.json version {package.get('version')!r}"
            )


def _site_moves(prepared: PreparedEnvironment, name: str) -> bool:
    repository_name, branch, paths = SITE_DEPLOYMENTS[name]
    repository = (
        prepared.aweb_root if repository_name == "aweb" else prepared.ac_root
    )
    sha = prepared.aweb_sha if repository_name == "aweb" else prepared.ac_sha
    listed = _git(repository, "ls-remote", "origin", f"refs/heads/{branch}").stdout.strip()
    if not listed:
        # U3: the deployment branch does not exist (live for aweb-site).
        # The source set has never deployed, so the site moves; the deploy
        # target stays pending until the branch shape is verified (U3).
        return True
    deployed = listed.split()[0]
    try:
        _git(repository, "diff", "--quiet", deployed, sha, "--", *paths)
    except CommandFailed:
        return True
    return False


COMPAT_PAIR = ("aw-cli", "aweb-server")


def select_compat_pairing(
    selections: Sequence[ArtifactSelection],
) -> tuple[str, str] | None:
    """The one deterministically relevant last/new pairing: the cli-server
    pair, only when exactly one side moves this release."""

    moves = {item.name: item.moves for item in selections}
    cli, server = COMPAT_PAIR
    if moves[cli] == moves[server]:
        return None
    return (
        f"{cli}@{'new' if moves[cli] else 'last'}",
        f"{server}@{'new' if moves[server] else 'last'}",
    )


def run_gate_once(
    prepared: PreparedEnvironment, gate_command: tuple[str, ...], *, work_timeout: float
) -> GateEvidence:
    if not gate_command or not all(isinstance(item, str) and item for item in gate_command):
        raise ValidationError("gate command must be a nonempty tuple of arguments")
    result = run_command(list(gate_command), cwd=prepared.aweb_root, timeout=work_timeout)
    document = _parse_json_bytes(result.stdout.encode(), "gate evidence")
    if not isinstance(document, dict):
        raise ObservationMalformed("gate evidence must be a JSON object")
    suites = document.get("suites")
    reference = document.get("reference")
    if not isinstance(suites, list) or not suites:
        raise ObservationMalformed("gate evidence must name its suites")
    return GateEvidence(
        name="aweb-clean-gate",
        sha=prepared.aweb_sha,
        result="passed",
        reference=validate_line(reference, "gate log reference"),
        suites=tuple(validate_line(item, "gate suite") for item in suites),
    )


def prepare(
    repo_root: Path,
    environment: Mapping[str, str],
    *,
    projection,
    gate_command: tuple[str, ...],
    timeout: float = 600,
    work_timeout: float = WORK_TIMEOUT,
) -> ReleaseCard:
    """The card is constructed from the normalizer's projection - the
    production entry computes that projection with the SAME phase that
    validated it, in this one command (aben A5, shipment finding 2)."""

    prepared = prepare_environment(repo_root, environment)
    selections = selections_from_projection(projection)
    versions = {item.name: item.version for item in selections}
    if versions["a2a-gateway-image"] != versions["aweb-server"]:
        raise ValidationError(
            "a2a-gateway version must equal the server version at set computation"
        )
    check_plugin_equality(prepared)
    gate = run_gate_once(prepared, gate_command, work_timeout=work_timeout)
    gates = [gate]
    pairing = select_compat_pairing(selections)
    if pairing is not None:
        compat_result = run_command(
            [*gate_command, "compat-pairing", *pairing],
            cwd=prepared.aweb_root,
            timeout=work_timeout,
        )
        compat_document = _parse_json_bytes(
            compat_result.stdout.encode(), "compat gate evidence"
        )
        if not isinstance(compat_document, dict) or not compat_document.get("suites"):
            raise ObservationMalformed("compat gate evidence must name its suites")
        gates.append(
            GateEvidence(
                name="compat-pairing",
                sha=prepared.aweb_sha,
                result="passed",
                reference=validate_line(
                    compat_document.get("reference"), "compat gate log reference"
                ),
                suites=tuple(
                    validate_line(item, "compat gate suite")
                    for item in compat_document["suites"]
                ),
            )
        )
    moves = {item.name: item.moves for item in selections}
    deployments = DeploymentSet(
        production=moves["ac-image"],
        awid_site=_site_moves(prepared, "awid-site"),
        aweb_site=_site_moves(prepared, "aweb-site"),
    )
    card = ReleaseCard(
        aweb_sha=prepared.aweb_sha,
        ac_base_sha=prepared.ac_sha,
        artifacts=selections,
        compatibility=prepared.compatibility,
        gates=tuple(gates),
        purpose=prepared.purpose,
        deployments=deployments,
        final_ac_sha=None,
        # Pending exactly when this card deploys production - the card's
        # own validator forbids a pending correction without a deploy,
        # and a world at rest must still be cardable.
        first_release_correction_pending=deployments.production,
    )
    write_card(prepared.aweb_root, card)
    return card


# --- public registry read adapters ----------------------------------------

PUBLIC_READ_BASES = {
    "pypi": "https://pypi.org",
    "npm": "https://registry.npmjs.org",
    "ghcr": "https://ghcr.io",
    "github": "https://api.github.com",
}
_GITHUB_RELEASE_TAGS = {
    "github:awebai/aw:release": "v{version}",
    "github:awebai/aweb:skills-release-zips": "skills-v{version}",
}


def _bounded_get(
    url: str, *, timeout: float, headers: Mapping[str, str] | None = None
) -> object | None:
    """GET one public read endpoint: 404 is the only absence (None), any
    other non-200 is unavailable, and evidence beyond 1 MiB is malformed."""

    bounded = _bounded_timeout(timeout)
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", **(headers or {})}, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=bounded) as response:
            if response.status != 200:
                raise ObservationUnavailable(
                    f"public read returned HTTP {response.status}: {url}"
                )
            body = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        if code == 404:
            return None
        raise ObservationUnavailable(
            f"public read returned HTTP {code}: {url}"
        ) from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ObservationUnavailable(f"public read unavailable: {url}: {error}") from error
    if len(body) > 1024 * 1024:
        raise ObservationMalformed(f"public read evidence exceeds 1 MiB: {url}")
    return _parse_json_bytes(body, "public read evidence")


def observe_public_target(
    target: str,
    version: str,
    *,
    bases: Mapping[str, str] | None = None,
    timeout: float,
) -> bool:
    """Read-only presence of one artifact target at exactly one version.

    Speaks each registry's real read API behind the fixed semantics: HTTP 404
    is the only absence, any other failure is unavailable rather than absence,
    and served evidence must name exactly the queried version.
    """

    validate_line(target, "artifact target")
    validate_version(version, "target version")
    resolved = {**PUBLIC_READ_BASES, **(bases or {})}
    if target.startswith("pypi:"):
        name = target.split(":", 1)[1]
        document = _bounded_get(
            f"{resolved['pypi']}/pypi/{name}/{version}/json", timeout=timeout
        )
        if document is None:
            return False
        served = document.get("info", {}).get("version") if isinstance(document, dict) else None
        if served != version:
            raise ObservationMalformed(
                f"PyPI serves version {served!r} where {version} was queried: {name}"
            )
        return True
    if target.startswith("npm:"):
        package = urllib.parse.quote(target.split(":", 1)[1], safe="@")
        document = _bounded_get(
            f"{resolved['npm']}/{package}/{version}", timeout=timeout
        )
        if document is None:
            return False
        served = document.get("version") if isinstance(document, dict) else None
        if served != version:
            raise ObservationMalformed(
                f"npm serves version {served!r} where {version} was queried: {target}"
            )
        return True
    if target.startswith("ghcr.io/"):
        repository = target.removeprefix("ghcr.io/")
        exchange_headers: dict[str, str] = {}
        read_token = os.environ.get("AWEB_GHCR_READ_TOKEN", "").strip()
        if read_token:
            import base64

            exchange_headers["Authorization"] = "Basic " + base64.b64encode(
                f"token:{read_token}".encode()
            ).decode()
        token_document = _bounded_get(
            f"{resolved['ghcr']}/token?scope=repository:{repository}:pull&service=ghcr.io",
            timeout=timeout,
            headers=exchange_headers,
        )
        token = token_document.get("token") if isinstance(token_document, dict) else None
        if not token:
            raise ObservationUnavailable(
                f"GHCR token exchange returned no token for {repository}"
            )
        manifest = _bounded_get(
            f"{resolved['ghcr']}/v2/{repository}/manifests/{version}",
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": (
                    "application/vnd.oci.image.index.v1+json, "
                    "application/vnd.docker.distribution.manifest.list.v2+json"
                ),
            },
        )
        return manifest is not None
    if target in _GITHUB_RELEASE_TAGS:
        repository = target.split(":")[1]
        tag = _GITHUB_RELEASE_TAGS[target].format(version=version)
        document = _bounded_get(
            f"{resolved['github']}/repos/{repository}/releases/tags/{tag}",
            timeout=timeout,
        )
        return document is not None
    raise ValidationError(
        f"target has no public read adapter (sites deploy by branch, not "
        f"registry): {target}"
    )


# --- release-continue ------------------------------------------------------


AC_DERIVED_ALLOWLIST = ("backend/pyproject.toml", "backend/uv.lock")


@dataclasses.dataclass(frozen=True)
class ContinueEnvironment:
    aweb_root: Path
    ac_root: Path
    card: ReleaseCard
    ac_derived_sha: str | None


def _dependency_only_derived_child(
    ac_root: Path, base_sha: str, observed_sha: str
) -> bool:
    """Continue's adoption predicate: observed AC main is a child of the
    recorded base whose diff stays inside the derived-commit allowlist."""

    try:
        parent = _git(ac_root, "rev-parse", f"{observed_sha}^").stdout.strip()
    except CommandFailed:
        return False
    if parent != base_sha:
        return False
    changed = _git(
        ac_root, "diff", "--name-only", f"{base_sha}..{observed_sha}"
    ).stdout.split()
    return set(changed) <= set(AC_DERIVED_ALLOWLIST)


def continue_environment(repo_root: Path) -> ContinueEnvironment:
    """Read the fixed unconsumed card and re-observe its material commits.

    Continue takes no arguments; any material drift invalidates the card and
    requires a fresh prepare and go. One prior partial state is adoptable:
    AC main already at a dependency-only child of the recorded base whose
    diff stays inside the declared allowlist.
    """

    repo_root = Path(repo_root).resolve()
    card = read_card(repo_root)
    _require_origin(repo_root, "aweb")
    ac_root = (repo_root.parent / "ac").resolve()
    if not (ac_root / ".git").exists():
        raise ValidationError(
            f"the sibling ../ac checkout is missing at {ac_root}. Fix: clone "
            f"the canonical awebai/ac remote next to this repository"
        )
    _require_origin(ac_root, "ac")
    _git(repo_root, "fetch", "origin")
    aweb_main = _git(repo_root, "rev-parse", "refs/remotes/origin/main").stdout.strip()
    if aweb_main != card.aweb_sha:
        raise MaterialMismatch(
            f"aweb origin/main moved from the card's {card.aweb_sha} to "
            f"{aweb_main}; the card is invalid - run a fresh prepare and "
            f"obtain a fresh go"
        )
    _git(ac_root, "fetch", "origin")
    ac_main = _git(ac_root, "rev-parse", "refs/remotes/origin/main").stdout.strip()
    ac_derived_sha: str | None = None
    if ac_main != card.ac_base_sha:
        if _dependency_only_derived_child(ac_root, card.ac_base_sha, ac_main):
            ac_derived_sha = ac_main
        else:
            raise MaterialMismatch(
                f"ac origin/main moved from the card's {card.ac_base_sha} to "
                f"{ac_main} and is not the dependency-only derived commit; "
                f"the card is invalid - run a fresh prepare and obtain a "
                f"fresh go"
            )
    return ContinueEnvironment(
        aweb_root=repo_root,
        ac_root=ac_root,
        card=card,
        ac_derived_sha=ac_derived_sha,
    )


def fast_forward_release(
    repository: Path, branch: str, target_sha: str
) -> None:
    """Advance a publication pointer fast-forward-only, adopting exact matches."""

    validate_sha(target_sha, f"{branch} target")
    listed = _git(
        repository, "ls-remote", "origin", f"refs/heads/{branch}"
    ).stdout.strip()
    if listed:
        current = listed.split()[0]
        if current == target_sha:
            return
        try:
            _git(repository, "merge-base", "--is-ancestor", current, target_sha)
        except CommandFailed as error:
            raise ValidationError(
                f"refusing non-fast-forward move of {branch}: {current} is "
                f"not an ancestor of {target_sha}; a failed candidate leaves "
                f"the pointer put"
            ) from error
    _git(repository, "push", "origin", f"{target_sha}:refs/heads/{branch}")


# Long-wait polling: back off toward the cap so an hours-long digest wait
# makes dozens of registry requests, not tens of thousands, and survive
# transient unavailability (a 429 or 5xx inside the window must not stop the
# train - that is the failure the wait exists to prevent). A served-version
# mismatch (ObservationMalformed) stays fatal: it is a defect, not weather.
POLL_INITIAL_INTERVAL_SECONDS = 1.0
POLL_MAX_INTERVAL_SECONDS = 30.0


def _poll_public_target(
    target: str,
    version: str,
    *,
    bases: Mapping[str, str] | None,
    timeout: float,
    wait_seconds: float = 10.0,
) -> None:
    """Poll until the registry serves the version, bounded by wait_seconds.

    The default bound stays short for targets whose publisher was already
    monitored to completion; the digest edge passes its work bound instead,
    because the AC release-branch push starts a build this wait must outlast
    (first release: the digest observation raced the image build and stopped
    the train for a full rerun).
    """

    import time as _time

    started = _time.monotonic()
    deadline = started + wait_seconds
    interval = POLL_INITIAL_INTERVAL_SECONDS
    last_unavailable: ObservationUnavailable | None = None
    attempt = 0
    while True:
        attempt += 1
        try:
            if observe_public_target(target, version, bases=bases, timeout=timeout):
                return
            last_unavailable = None
        except ObservationUnavailable as error:
            last_unavailable = error
        now = _time.monotonic()
        if now >= deadline:
            break
        if attempt == 1 or attempt % 10 == 0:
            print(
                f"still waiting: {target} does not yet serve {version} "
                f"({int(now - started)}s elapsed)",
                file=sys.stderr,
            )
        _time.sleep(min(interval, max(0.0, deadline - now)))
        interval = min(interval * 1.5, POLL_MAX_INTERVAL_SECONDS)
    suffix = f"; last observation error: {last_unavailable}" if last_unavailable else ""
    raise ObservationUnavailable(
        f"still waiting: {target} does not yet serve {version}; rerun "
        f"release-continue once the registry catches up{suffix}"
    )


def _default_rederive(environment) -> list:
    """The real continue-start re-derivation: capture over the checkouts
    at the card SHAs with fresh registry observations, normalize, and
    compare to the card's projection. Lazy imports break the module
    cycle with the entry-point module."""

    import release_continue_check as rcc
    import release_normalizer as rn
    import release_normalizer_capture as cap
    import release_normalizer_main as rmain

    specs = cap.derive_capture_specs(ARTIFACTS)
    world = cap.assemble_captured_world(
        specs=specs,
        repo_roots={
            "aweb": environment.aweb_root,
            "ac": environment.ac_root,
        },
        discover_target=lambda target: rmain.route_discovery(
            target,
            timeout=30,
            ghcr_token=os.environ.get("AWEB_GHCR_READ_TOKEN", ""),
            gh_token=os.environ.get("GH_TOKEN", ""),
        ),
        equality_groups=rmain.EQUALITY_GROUPS,
        compatibility=environment.card.compatibility,
    )
    result = rn.normalize(world)
    rows = [
        rcc.CardRow(
            name=item.name,
            version=item.version,
            disposition=item.disposition,
            previous_complete_anchor=(
                (
                    item.previous_complete_anchor.version,
                    item.previous_complete_anchor.source_identity,
                )
                if item.previous_complete_anchor is not None
                else None
            ),
        )
        for item in environment.card.artifacts
    ]
    return rcc.verify_card_against_world(rows, result)


def _gate_rows_not_present(rows) -> list:
    return [row.fact for row in rows if not row.present()]


def _default_marketplace_gate(card, bases, timeout) -> list:
    """Complete channel+skills rows before the pointer mutation."""

    import release_status_gates as gates

    return _gate_rows_not_present(
        gates.rows_for_artifacts(card, ("channel-plugin", "skills"), bases=bases, timeout=timeout)
    )


def _default_ac_predecessor_gate(card, bases, timeout) -> list:
    """Every intended aweb/AWID output present before AC derivation."""

    import release_status_gates as gates

    names = tuple(
        item.name
        for item in card.artifacts
        if _artifact(item.name).repository == "aweb"
    )
    return _gate_rows_not_present(
        gates.rows_for_artifacts(card, names, bases=bases, timeout=timeout)
    )


def continue_train(
    repo_root: Path,
    *,
    bases: Mapping[str, str] | None = None,
    workflow_command: tuple[str, ...],
    derive_command: tuple[str, ...],
    ac_gate_command: tuple[str, ...],
    migrate_command: tuple[str, ...],
    deploy_command: tuple[str, ...],
    verify_command: tuple[str, ...],
    digest_command: tuple[str, ...],
    marketplace_command: tuple[str, ...] | None = None,
    timeout: float = 600,
    work_timeout: float = WORK_TIMEOUT,
    rederive=None,
    marketplace_gate=None,
    ac_predecessor_gate=None,
) -> dict[str, str]:
    """Execute the ten edges literally, idempotently, stopping named."""

    environment = continue_environment(repo_root)
    card = environment.card
    # aben design section 7: before the first irreversible edge (this
    # fast-forward triggers every publisher at once), the same normalizer
    # re-derives the world and the card is exact-compared under the
    # progress allowlist. rederive is injectable for fixture runs; the
    # default runs the real capture and comparator.
    drift = (rederive or _default_rederive)(environment)
    if drift:
        names = ", ".join(
            f"{stop.code}({stop.artifact})" if stop.artifact else stop.code
            for stop in drift
        )
        raise ValidationError(
            f"continue re-derivation refuses before the release move: {names}"
        )
    fast_forward_release(environment.aweb_root, "release", card.aweb_sha)
    versions = {item.name: item.version for item in card.artifacts}
    for selection in card.artifacts:
        artifact = _artifact(selection.name)
        if artifact.repository != "aweb":
            continue
        primary = artifact.targets[0]
        if not selection.moves:
            _poll_public_target(
                primary, selection.version, bases=bases, timeout=timeout
            )
            continue
        if not observe_public_target(
            primary, selection.version, bases=bases, timeout=timeout
        ):
            run_command(
                [*workflow_command, selection.name, selection.version],
                cwd=environment.aweb_root,
                timeout=work_timeout,
            )
        _poll_public_target(primary, selection.version, bases=bases, timeout=timeout)
    if marketplace_command is not None:
        # aben design section 8: marketplace mutation is gated on the
        # COMPLETE channel+skills output rows, not on monitored adoption
        # alone. The gate returns the non-present rows; any -> refusal.
        blocking = list((marketplace_gate or _default_marketplace_gate)(card, bases, timeout))
        if blocking:
            raise ValidationError(
                "marketplace mutation refused: predecessor rows not present: "
                + "; ".join(blocking)
            )
        run_command(
            list(marketplace_command), cwd=environment.aweb_root, timeout=work_timeout
        )
    ac_derived = environment.ac_derived_sha
    if ac_derived is None and not any(
        selection.moves
        for selection in card.artifacts
        if selection.name in AC_FLOOR_ARTIFACTS
    ):
        ac_derived = card.ac_base_sha
    if ac_derived is None:
        # aben design section 8: all intended aweb/AWID outputs must be
        # PRESENT (complete per-output rows) immediately before the AC
        # derivation - primary polls are not the enforcement.
        blocking = list((ac_predecessor_gate or _default_ac_predecessor_gate)(card, bases, timeout))
        if blocking:
            raise ValidationError(
                "AC derivation refused: predecessor rows not present: "
                + "; ".join(blocking)
            )
        run_command(list(derive_command), cwd=environment.ac_root, timeout=work_timeout)
        changed = _git(environment.ac_root, "status", "--porcelain").stdout.split()
        names = {line for line in changed if not line.startswith(("M", "A", "?"))} or {
            item.split()[-1] for item in _git(
                environment.ac_root, "status", "--porcelain"
            ).stdout.splitlines()
        }
        if not names:
            raise ValidationError(
                "derivation changed nothing; the dependency floors were "
                "expected to move"
            )
        if not names <= set(AC_DERIVED_ALLOWLIST):
            raise ValidationError(
                f"derivation touched files outside the declared allowlist "
                f"{AC_DERIVED_ALLOWLIST}: {sorted(names)}; the train stops "
                f"and the card is invalid"
            )
        _git(environment.ac_root, "add", *AC_DERIVED_ALLOWLIST)
        _git(
            environment.ac_root,
            "commit",
            "-m",
            "release: derive public dependency floors and lock",
        )
        ac_derived = _git(environment.ac_root, "rev-parse", "HEAD").stdout.strip()
        _git(
            environment.ac_root,
            "push",
            "origin",
            f"HEAD:refs/heads/main",
            f"--force-with-lease=refs/heads/main:{card.ac_base_sha}",
        )
    run_command(list(ac_gate_command), cwd=environment.ac_root, timeout=work_timeout)
    fast_forward_release(environment.ac_root, "release", ac_derived)
    _poll_public_target(
        _artifact("ac-image").targets[0],
        versions["ac-image"],
        bases=bases,
        timeout=timeout,
        wait_seconds=work_timeout,
    )
    digest_result = run_command(
        list(digest_command), cwd=environment.ac_root, timeout=work_timeout
    )
    digest = digest_result.stdout.strip()
    if not _DIGEST_RE.fullmatch(digest):
        raise ObservationMalformed(
            f"AC image digest observation is not an exact digest: {digest!r}"
        )
    if card.deployments.production:
        run_command(list(migrate_command), cwd=environment.ac_root, timeout=work_timeout)
        run_command(
            [*deploy_command, digest], cwd=environment.ac_root, timeout=work_timeout
        )
        run_command(
            [*verify_command, digest], cwd=environment.ac_root, timeout=work_timeout
        )
    if card.deployments.awid_site:
        fast_forward_release(
            environment.aweb_root, "deploy-awid-landing", card.aweb_sha
        )
    if card.deployments.aweb_site:
        fast_forward_release(environment.ac_root, "deploy-landing", ac_derived)
    consume_card(environment.aweb_root, card)
    summary = {
        "status": "DONE",
        "aweb_sha": card.aweb_sha,
        "final_ac_sha": ac_derived,
        "ac_image_digest": digest,
        **{f"version:{name}": version for name, version in versions.items()},
    }
    print(
        "release-continue DONE: "
        + " ".join(f"{key}={value}" for key, value in sorted(summary.items()))
    )
    return summary


_CONTINUE_COMMAND_ENVS = (
    "AWEB_RELEASE_WORKFLOW_COMMAND",
    "AWEB_RELEASE_DERIVE_COMMAND",
    "AWEB_RELEASE_AC_GATE_COMMAND",
    "AWEB_RELEASE_MIGRATE_COMMAND",
    "AWEB_RELEASE_DEPLOY_COMMAND",
    "AWEB_RELEASE_VERIFY_COMMAND",
    "AWEB_RELEASE_DIGEST_COMMAND",
)


def _continue_main() -> int:
    missing = [name for name in _CONTINUE_COMMAND_ENVS if not os.environ.get(name, "").strip()]
    if missing:
        print(
            "release-continue refused: the boundary commands are not named: "
            + ", ".join(missing)
            + ". The epic ends at non-production readiness; nothing here "
            "guesses real workflow, provider, or migration entry points.",
            file=sys.stderr,
        )
        return 2
    commands = {
        name: tuple(shlex.split(os.environ[name]))
        for name in _CONTINUE_COMMAND_ENVS
    }
    marketplace_raw = os.environ.get("AWEB_RELEASE_MARKETPLACE_COMMAND", "").strip()
    try:
        summary = continue_train(
            Path.cwd(),
            workflow_command=commands["AWEB_RELEASE_WORKFLOW_COMMAND"],
            derive_command=commands["AWEB_RELEASE_DERIVE_COMMAND"],
            ac_gate_command=commands["AWEB_RELEASE_AC_GATE_COMMAND"],
            migrate_command=commands["AWEB_RELEASE_MIGRATE_COMMAND"],
            deploy_command=commands["AWEB_RELEASE_DEPLOY_COMMAND"],
            verify_command=commands["AWEB_RELEASE_VERIFY_COMMAND"],
            digest_command=commands["AWEB_RELEASE_DIGEST_COMMAND"],
            marketplace_command=(
                tuple(shlex.split(marketplace_raw)) if marketplace_raw else None
            ),
        )
    except ReleaseTrainError as error:
        print(f"release-continue stopped: {error}", file=sys.stderr)
        return 1
    del summary
    return 0


def _main(argv: Sequence[str]) -> int:
    if list(argv) == ["continue"]:
        return _continue_main()
    if list(argv) != ["prepare"]:
        print("usage: release_train.py prepare|continue", file=sys.stderr)
        return 2
    gate_raw = os.environ.get("AWEB_RELEASE_GATE_COMMAND", "").strip()
    if not gate_raw:
        print(
            "release-prepare refused: AWEB_RELEASE_GATE_COMMAND must name the "
            "gate entry (the Make target supplies the real wrapper).",
            file=sys.stderr,
        )
        return 2
    # The normalizer phase runs in THIS command and its in-memory
    # projection is what the card is built from (aben A5); a stop or a
    # patch ends the run before any test, exactly as the phase reports.
    import release_normalizer_main as normalizer_entry

    phase_code, phase_report, projection, normalizer_root = (
        normalizer_entry.run_phase()
    )
    print(phase_report)
    if phase_code != 0:
        return phase_code
    if normalizer_root != Path.cwd().resolve():
        print(
            "release-prepare refused: the normalizer ran over "
            f"{normalizer_root} but prepare runs from {Path.cwd().resolve()}; "
            "one world per command",
            file=sys.stderr,
        )
        return 2
    try:
        card = prepare(
            Path.cwd(),
            os.environ,
            projection=projection,
            gate_command=tuple(shlex.split(gate_raw)),
        )
    except ReleaseTrainError as error:
        print(f"release-prepare failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(dataclasses.asdict(card), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))

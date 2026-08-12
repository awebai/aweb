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


@dataclasses.dataclass(frozen=True)
class ReleaseEdge:
    number: int
    kind: str
    nodes: tuple[str, ...]
    rule: str


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
    ),
    Artifact(
        "awid-service",
        "aweb",
        "AWID service",
        ("pypi:awid-service",),
        "awid/pyproject.toml",
    ),
    Artifact(
        "awid-image",
        "aweb",
        "AWID image",
        ("ghcr.io/awebai/awid",),
        "awid/pyproject.toml",
        platforms=OCI_PLATFORMS,
        bundled_inputs=("server-source",),
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
    ),
    Artifact(
        "channel-plugin",
        "aweb",
        "channel plugin",
        ("npm:@awebai/claude-channel",),
        "channel/package.json",
        bundled_inputs=("channel-core",),
    ),
    Artifact(
        "pi-extension",
        "aweb",
        "Pi extension",
        ("npm:@awebai/pi",),
        "pi-extension/package.json",
        bundled_inputs=("channel-core",) + SKILL_SOURCES,
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
    ),
    Artifact(
        "a2a-gateway-image",
        "aweb",
        "a2a-gateway image",
        ("ghcr.io/awebai/a2a-gateway",),
        "equals:server/pyproject.toml",
        platforms=OCI_PLATFORMS,
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
    ),
    ReleaseEdge(
        2,
        "ordering",
        ("aw-cli-npm-set", "pi-extension"),
        "all seven aw npm packages served before Pi when its floor moves",
    ),
    ReleaseEdge(
        3,
        "ordering",
        ("channel-plugin", "skills", "marketplace-pointer"),
        "channel and skills served before marketplace advance",
    ),
    ReleaseEdge(
        4,
        "ordering",
        ("intended-aweb-awid-public", "ac-dependency-commit", "ac-gate"),
        "public packages before derived AC dependency commit and gate",
    ),
    ReleaseEdge(
        5,
        "ordering",
        ("ac-image", "ac-production", "digest-health-verification"),
        "AC image before deploy before digest and health verification",
    ),
    ReleaseEdge(
        6,
        "same-commit",
        ("channel-core", "channel-plugin", "pi-extension"),
        "one channel-core input in channel and Pi",
    ),
    ReleaseEdge(
        7,
        "same-commit",
        ("skill-source-set", "pi-extension", "skills", "skills-zips"),
        "the same five skill sources in every output",
    ),
    ReleaseEdge(
        8,
        "same-commit",
        ("server-source", "awid-image"),
        "server source in the same-commit AWID image",
    ),
    ReleaseEdge(
        9,
        "equality",
        ("a2a-gateway-image", "aweb-server"),
        "a2a-gateway version equals server version",
    ),
    ReleaseEdge(
        10,
        "independent",
        ("awid-site", "aweb-site"),
        "both site branch pushes are independent of the artifact train",
    ),
)

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


@dataclasses.dataclass(frozen=True)
class ArtifactSelection:
    name: str
    version: str
    moves: bool

    def __post_init__(self) -> None:
        validate_line(self.name, "artifact name")
        validate_version(self.version, self.name)
        _validate_bool(self.moves, f"{self.name} moves")


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
_ARTIFACT_FIELDS = {"name", "version", "moves"}
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
            try:
                artifacts.append(
                    ArtifactSelection(item["name"], item["version"], item["moves"])
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


def _bounded_timeout(timeout: object) -> float:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
        or timeout > 600
    ):
        raise ValidationError("timeout must be greater than zero and at most 600 seconds")
    return float(timeout)


def run_command(
    args: Sequence[str], *, cwd: Path, timeout: float
) -> CommandResult:
    """Run one explicit argv with a bounded timeout; never invoke a shell."""

    if not args or any(not isinstance(arg, str) or not arg for arg in args):
        raise ValidationError("command argv must contain nonempty strings")
    bounded = _bounded_timeout(timeout)
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
        assert_material_matches(card, read_card(repository))
        return path
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
        return f"{newest[0]}.{newest[1]}.{newest[2] + 1}"
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


def select_artifacts(
    prepared: PreparedEnvironment, *, registry_base: str, timeout: float
) -> tuple[ArtifactSelection, ...]:
    validate_line(registry_base, "registry base")
    selections = []
    versions: dict[str, str] = {}
    for name in CARD_ARTIFACT_ORDER:
        artifact = _artifact(name)
        version = _read_manifest_version(prepared, artifact)
        versions[name] = version
        reference = artifact.targets[0]
        url = f"{registry_base}/{urllib.parse.quote(reference, safe='')}/{version}"
        present = observe_registry_presence(url, version, timeout=timeout)
        selections.append(ArtifactSelection(name=name, version=version, moves=not present))
    if versions["a2a-gateway-image"] != versions["aweb-server"]:
        raise ValidationError(
            "a2a-gateway version must equal the server version at set computation"
        )
    return tuple(selections)


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


def run_gate_once(
    prepared: PreparedEnvironment, gate_command: tuple[str, ...], *, timeout: float
) -> GateEvidence:
    if not gate_command or not all(isinstance(item, str) and item for item in gate_command):
        raise ValidationError("gate command must be a nonempty tuple of arguments")
    result = run_command(list(gate_command), cwd=prepared.aweb_root, timeout=timeout)
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
    registry_base: str,
    gate_command: tuple[str, ...],
    timeout: float = 600,
) -> ReleaseCard:
    prepared = prepare_environment(repo_root, environment)
    selections = select_artifacts(
        prepared, registry_base=registry_base, timeout=timeout
    )
    check_plugin_equality(prepared)
    gate = run_gate_once(prepared, gate_command, timeout=timeout)
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
        gates=(gate,),
        purpose=prepared.purpose,
        deployments=deployments,
        final_ac_sha=None,
        first_release_correction_pending=True,
    )
    try:
        existing = read_card(prepared.aweb_root)
    except CardUnavailable:
        existing = None
    if existing is not None:
        assert_material_matches(existing, card)
    write_card(prepared.aweb_root, card)
    return card


def _main(argv: Sequence[str]) -> int:
    if list(argv) != ["prepare"]:
        print("usage: release_train.py prepare", file=sys.stderr)
        return 2
    registry_base = os.environ.get("AWEB_RELEASE_REGISTRY_BASE", "").strip()
    gate_raw = os.environ.get("AWEB_RELEASE_GATE_COMMAND", "").strip()
    if not registry_base or not gate_raw:
        print(
            "release-prepare refused: AWEB_RELEASE_REGISTRY_BASE and "
            "AWEB_RELEASE_GATE_COMMAND must name the observation endpoint and "
            "gate entry. The epic ends at non-production readiness; the "
            "real-registry adapters are first-release work and nothing here "
            "guesses them.",
            file=sys.stderr,
        )
        return 2
    try:
        card = prepare(
            Path.cwd(),
            os.environ,
            registry_base=registry_base,
            gate_command=tuple(shlex.split(gate_raw)),
        )
    except ReleaseTrainError as error:
        print(f"release-prepare failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(dataclasses.asdict(card), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))

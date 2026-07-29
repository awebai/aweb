#!/usr/bin/env python3
"""Fail-closed Render production operations for Library.

All production mutations require --apply and an exact service-ID confirmation.
The API key is loaded from a mode-0600 env file and is never printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.client import HTTPException, IncompleteRead
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

SCRIPT_PATH = Path(__file__).resolve()
REPOSITORY_ROOT = SCRIPT_PATH.parents[1]
SCRIPT_RELATIVE_PATH = SCRIPT_PATH.relative_to(REPOSITORY_ROOT)
API_BASE = "https://api.render.com/v1"
IN_PROGRESS_STATUSES = {
    "created",
    "build_in_progress",
    "update_in_progress",
    "pre_deploy_in_progress",
}
FAILURE_STATUSES = {"build_failed", "update_failed", "pre_deploy_failed", "canceled"}
TERMINAL_STATUSES = {"live", "deactivated", *FAILURE_STATUSES}
KNOWN_STATUSES = {*IN_PROGRESS_STATUSES, *TERMINAL_STATUSES}
ROLLBACK_ARTIFACT_STATUSES = {"live", "deactivated"}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DEPLOY_RE = re.compile(r"^dep-[a-z0-9]+$")
SERVICE_RE = re.compile(r"^srv-[a-z0-9]+$")
HEALTH_READINESS_TIMEOUT_SECONDS = 90.0
HEALTH_RETRY_INTERVAL_SECONDS = 5.0
HEALTH_REQUEST_TIMEOUT_SECONDS = 20.0
HEALTH_USER_AGENT = "aweb-library-deploy-gate/1.0"
BLOCKED_BASELINE_USER_AGENT = "Python-urllib/3.12"
HEALTH_BODY_CAPTURE_LIMIT = 16_384
HEALTH_BODY_PREVIEW_LIMIT = 16_384
HEALTH_HEADER_CAPTURE_LIMIT = 16_384
HEALTH_DIAGNOSTIC_HEADERS = {
    "cf-cache-status",
    "cf-mitigated",
    "cf-ray",
    "content-length",
    "content-type",
    "location",
    "retry-after",
    "server",
}
RETRYABLE_HEALTH_HTTP_STATUSES = {404, 408, 425, 429, 500, 502, 503, 504}

# Stable child predicates evaluated by the Render half of `make prod-verify`.
# AATK validates exact set equality between these source-owned IDs, its static
# manifest, and terminal release receipts; adding or removing a predicate here
# cannot silently disappear from the release proof.
POSTDEPLOY_PREDICATES = frozenset(
    {
        "verifier.source-clean",
        "verifier.evidence-private-no-replace",
        "render.topology.exact",
        "render.deploy.sole-live-id",
        "render.deploy.exact-commit",
        "health.origin.exact-url-no-redirect",
        "health.origin.user-agent",
        "health.origin.http-200",
        "health.origin.evidence-complete",
        "health.origin.payload-contract",
        "health.origin.build-sha",
        "health.public.exact-url-no-redirect",
        "health.public.user-agent",
        "health.public.http-200",
        "health.public.evidence-complete",
        "health.public.payload-contract",
        "health.public.build-sha",
        "health.surfaces.payload-equal",
        "health.readiness.bounded",
    }
)
CANDIDATE_ONLY_POSTDEPLOY_PREDICATES = frozenset(
    {
        "health.origin.build-sha",
        "health.public.build-sha",
    }
)


AATK_CAPABILITY_OBLIGATIONS = (
    "runtime.path-fidelity",
    "safety.boundary-invocation",
    "controls.executed-same-path",
)
AATK_PREDICATE_COVERAGE = {
    "health.origin.build-sha": ("release-infrastructure", "deferred"),
    "health.origin.evidence-complete": ("release-infrastructure", "deferred"),
    "health.origin.exact-url-no-redirect": ("release-infrastructure", "deferred"),
    "health.origin.http-200": ("release-infrastructure", "instrumented-capability"),
    "health.origin.payload-contract": ("release-infrastructure", "instrumented-capability"),
    "health.origin.user-agent": ("release-infrastructure", "deferred"),
    "health.public.build-sha": ("release-infrastructure", "deferred"),
    "health.public.evidence-complete": ("release-infrastructure", "deferred"),
    "health.public.exact-url-no-redirect": ("release-infrastructure", "deferred"),
    "health.public.http-200": ("release-infrastructure", "instrumented-capability"),
    "health.public.payload-contract": ("release-infrastructure", "instrumented-capability"),
    "health.public.user-agent": ("release-infrastructure", "deferred"),
    "health.readiness.bounded": ("release-infrastructure", "deferred"),
    "health.surfaces.payload-equal": ("release-infrastructure", "deferred"),
    "render.deploy.exact-commit": ("release-infrastructure", "deferred"),
    "render.deploy.sole-live-id": ("release-infrastructure", "deferred"),
    "render.topology.exact": ("release-infrastructure", "deferred"),
    "verifier.evidence-private-no-replace": ("release-infrastructure", "deferred"),
    "verifier.source-clean": ("release-infrastructure", "deferred"),
}


def postdeploy_predicate_inventory() -> list[str]:
    """Return stable child IDs emitted by the postdeploy executor."""
    return sorted(POSTDEPLOY_PREDICATES)


def aatk_predicate_coverage() -> list[dict[str, Any]]:
    """Return source-owned per-obligation capability coverage for this executor."""
    return [
        {
            "domain": "candidate-postdeploy",
            "id": predicate_id,
            "owner": owner,
            "candidate_mapping": {"state": "self"},
            "obligations": {obligation: state for obligation in AATK_CAPABILITY_OBLIGATIONS},
        }
        for predicate_id, (owner, state) in sorted(AATK_PREDICATE_COVERAGE.items())
    ]


class OpsError(RuntimeError):
    """A safe-to-print operational failure."""


class TransientHealthError(OpsError):
    """A health failure that may be caused by a live-transition readiness window."""


class PermanentHealthHTTPError(OpsError):
    """A nonretryable health HTTP response with a preserved status."""

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


def _open_directory_nofollow(path: Path) -> list[tuple[int, str, tuple[int, int]]]:
    """Retain a no-follow descriptor chain for an existing absolute directory."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    root_stat = os.fstat(descriptor)
    chain = [(descriptor, "", (root_stat.st_dev, root_stat.st_ino))]
    try:
        for component in path.parts[1:]:
            descriptor = os.open(component, flags, dir_fd=chain[-1][0])
            component_stat = os.fstat(descriptor)
            chain.append(
                (descriptor, component, (component_stat.st_dev, component_stat.st_ino))
            )
        return chain
    except OSError:
        for opened, _, _ in reversed(chain):
            os.close(opened)
        raise


class HealthEvidenceRun:
    """Descriptor-anchored, mode-private evidence for unauthenticated health probes."""

    def __init__(
        self, path: Path, *, label: str, metadata: dict[str, Any] | None = None
    ) -> None:
        if not path.is_absolute():
            raise OpsError("health evidence directory must be absolute")
        normalized = Path(os.path.normpath(str(path)))
        if normalized != path:
            raise OpsError("health evidence directory must not contain traversal components")
        if path == REPOSITORY_ROOT or REPOSITORY_ROOT in path.parents:
            raise OpsError("health evidence directory must be outside the repository")
        self.path = path
        self.label = label
        self.metadata = {"run_id": str(uuid.uuid4()), **(metadata or {})}
        self.sequence = 0
        self._closed = False
        try:
            self._parent_chain = _open_directory_nofollow(path.parent)
            self._parent_fd = self._parent_chain[-1][0]
        except OSError as exc:
            raise OpsError(
                "health evidence parent must be an existing path without symlink components"
            ) from exc
        self._leaf = path.name
        try:
            self._validate_parent_chain()
            parent_stat = os.fstat(self._parent_fd)
            if (
                stat.S_IMODE(parent_stat.st_mode) != 0o700
                or parent_stat.st_uid != os.geteuid()
            ):
                raise OpsError(
                    "health evidence parent must be operator-owned with exact mode 0700"
                )
            previous_umask = os.umask(0)
            try:
                os.mkdir(self._leaf, 0o700, dir_fd=self._parent_fd)
            finally:
                os.umask(previous_umask)
            created_stat = os.stat(self._leaf, dir_fd=self._parent_fd, follow_symlinks=False)
            self._directory_fd = os.open(
                self._leaf,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._parent_fd,
            )
            os.fchmod(self._directory_fd, 0o700)
            directory_stat = os.fstat(self._directory_fd)
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or stat.S_IMODE(directory_stat.st_mode) != 0o700
                or (created_stat.st_dev, created_stat.st_ino)
                != (directory_stat.st_dev, directory_stat.st_ino)
            ):
                raise OpsError("health evidence directory changed during creation")
            self._directory_identity = (directory_stat.st_dev, directory_stat.st_ino)
            self.record({"probe_kind": "run-manifest", "outcome": "started"})
        except FileExistsError as exc:
            for descriptor, _, _ in reversed(self._parent_chain):
                os.close(descriptor)
            self._closed = True
            raise OpsError("health evidence directory must not already exist") from exc
        except Exception:
            self.close()
            raise

    def _validate_parent_chain(self) -> None:
        for index in range(1, len(self._parent_chain)):
            parent_fd = self._parent_chain[index - 1][0]
            descriptor, component, identity = self._parent_chain[index]
            descriptor_stat = os.fstat(descriptor)
            try:
                component_stat = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                raise OpsError("health evidence parent path changed") from exc
            if (
                not stat.S_ISDIR(component_stat.st_mode)
                or (descriptor_stat.st_dev, descriptor_stat.st_ino) != identity
                or (component_stat.st_dev, component_stat.st_ino) != identity
            ):
                raise OpsError("health evidence parent path changed")

    def _validate_anchor(self) -> None:
        if self._closed:
            raise OpsError("health evidence run is closed")
        self._validate_parent_chain()
        directory_stat = os.fstat(self._directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or stat.S_IMODE(directory_stat.st_mode) != 0o700
            or (directory_stat.st_dev, directory_stat.st_ino) != self._directory_identity
        ):
            raise OpsError("health evidence directory identity or mode changed")
        try:
            path_stat = os.stat(self._leaf, dir_fd=self._parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise OpsError("health evidence directory path changed") from exc
        if (
            not stat.S_ISDIR(path_stat.st_mode)
            or (path_stat.st_dev, path_stat.st_ino) != self._directory_identity
        ):
            raise OpsError("health evidence directory path changed")

    def record(self, event: dict[str, Any]) -> None:
        self._validate_anchor()
        self.sequence += 1
        payload = {
            "schema": "library.health-evidence.v1",
            "run_label": self.label,
            "run_metadata": self.metadata,
            "sequence": self.sequence,
            **event,
        }
        encoded = (json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n").encode()
        destination = f"{self.sequence:03d}.json"
        temporary = f".{destination}.{uuid.uuid4().hex}.tmp"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=self._directory_fd,
            )
            os.fchmod(descriptor, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            try:
                os.link(
                    temporary,
                    destination,
                    src_dir_fd=self._directory_fd,
                    dst_dir_fd=self._directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise OpsError("health evidence artifact must not already exist") from exc
            os.fsync(self._directory_fd)
            self._validate_anchor()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self._directory_fd)
            except FileNotFoundError:
                pass

    def finish(self, event: dict[str, Any]) -> None:
        try:
            self.record(event)
        finally:
            self.close()

    def close(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        directory_descriptor = getattr(self, "_directory_fd", None)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        for descriptor, _, _ in reversed(getattr(self, "_parent_chain", [])):
            os.close(descriptor)

    def __del__(self) -> None:
        self.close()


CAPABILITY_FIXTURE_PREDICATES = frozenset(
    {
        "health.origin.http-200",
        "health.origin.payload-contract",
        "health.public.http-200",
        "health.public.payload-contract",
    }
)
CAPABILITY_COMPONENT_COMMAND = "render-ops.command-verify"
CAPABILITY_COMPONENT_SURFACES = "render-ops.verify-health-surfaces"
CAPABILITY_COMPONENT_ORIGIN = "render-ops.verify-health.origin"
CAPABILITY_COMPONENT_PUBLIC = "render-ops.verify-health.public"


class CapabilityFixtureRecorder:
    """Emit an untrusted, isolated child-capability transcript.

    This recorder establishes only which checked-in Python components and assertions a
    contract fixture observed.  It is deliberately unsigned and cannot satisfy any
    lifecycle receipt.
    """

    def __init__(
        self,
        path: Path,
        *,
        config: ProductionConfig,
        deploy_id: str,
        commit: str,
        correlation_id: str,
        mutation_id: str,
    ) -> None:
        if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", correlation_id):
            raise OpsError("capability correlation ID must be a stable opaque ID")
        if mutation_id and not re.fullmatch(
            r"[a-z0-9]+(?:[.-][a-z0-9]+)*", mutation_id
        ):
            raise OpsError("capability mutation ID must be empty or stable")
        source_identity = _verifier_identity()
        self._evidence = HealthEvidenceRun(
            path,
            label="aatk-capability-fixture",
            metadata={
                "transcript_class": "capability-fixture",
                "driver": "render_ops.command_verify",
                "correlation_id": correlation_id,
                "mutation_id": mutation_id,
                "verifier_source_sha": source_identity["verifier_source_sha"],
                "verifier_script_sha256": source_identity["verifier_script_sha256"],
                "config_sha256": config.source_sha256,
            },
        )
        self._metadata = {
            "schema": "library.aatk-capability-transcript.v1",
            "transcript_class": "capability-fixture",
            "driver": "render_ops.command_verify",
            "correlation_id": correlation_id,
            "mutation_id": mutation_id,
            "source": source_identity,
            "config_sha256": config.source_sha256,
            "normalized_arguments": {
                "commit": commit,
                "deploy_id": deploy_id,
                "service_id": config.service_id,
            },
            "substitutions": [
                {
                    "boundary_id": "render.api.fixture",
                    "position": "render-ops.command-verify.render-api",
                },
                {
                    "boundary_id": "http.origin.fixture",
                    "position": "render-ops.verify-health.origin.http",
                },
                {
                    "boundary_id": "http.public.fixture",
                    "position": "render-ops.verify-health.public.http",
                },
            ],
        }
        self.components: list[str] = []
        self.children: list[dict[str, Any]] = []
        self._terminal = False

    def enter(self, component_id: str) -> None:
        if self._terminal:
            raise OpsError("capability transcript is already terminal")
        if component_id in self.components:
            raise OpsError(f"capability-duplicate-component: {component_id}")
        self.components.append(component_id)

    def _expected_path(self, predicate_id: str) -> list[str]:
        base = [CAPABILITY_COMPONENT_COMMAND, CAPABILITY_COMPONENT_SURFACES]
        if predicate_id.startswith("health.origin."):
            return [*base, CAPABILITY_COMPONENT_ORIGIN]
        return [*base, CAPABILITY_COMPONENT_ORIGIN, CAPABILITY_COMPONENT_PUBLIC]

    def terminal_child(
        self,
        predicate_id: str,
        *,
        outcome: str,
        assertion_code: str,
        subject_sha256: str,
    ) -> None:
        if predicate_id not in CAPABILITY_FIXTURE_PREDICATES:
            raise OpsError(f"capability-unknown-predicate: {predicate_id}")
        if any(child["predicate_id"] == predicate_id for child in self.children):
            raise OpsError(f"capability-duplicate-terminal: {predicate_id}")
        expected = self._expected_path(predicate_id)
        if self.components != expected:
            missing = next(
                (item for item in expected if item not in self.components),
                "component-order",
            )
            raise OpsError(f"capability-path-mismatch: {predicate_id}: {missing}")
        if outcome not in {"passed", "expected-failure"}:
            raise OpsError("capability terminal outcome is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", subject_sha256):
            raise OpsError("capability subject digest must be sha256")
        self.children.append(
            {
                "predicate_id": predicate_id,
                "observed_subject_path": list(self.components),
                "terminal": {
                    "outcome": outcome,
                    "assertion_code": assertion_code,
                    "count": 1,
                },
                "subject_artifact_sha256": subject_sha256,
            }
        )

    def finish(self, *, outcome: str, error_code: str = "") -> None:
        if self._terminal:
            return
        missing_error = ""
        if outcome == "passed":
            observed = {child["predicate_id"] for child in self.children}
            missing = sorted(CAPABILITY_FIXTURE_PREDICATES - observed)
            unexpected = sorted(observed - CAPABILITY_FIXTURE_PREDICATES)
            nonpassing = sorted(
                child["predicate_id"]
                for child in self.children
                if child["terminal"]["outcome"] != "passed"
            )
            if missing or unexpected or nonpassing:
                missing_error = (
                    "capability-incomplete: "
                    f"missing={missing} unexpected={unexpected} nonpassing={nonpassing}"
                )
                outcome = "failed"
                error_code = missing_error
        self._terminal = True
        transcript = {
            **self._metadata,
            "observed_components": list(self.components),
            "children": list(self.children),
            "terminal": {"outcome": outcome, "error_code": error_code, "count": 1},
        }
        encoded = json.dumps(transcript, ensure_ascii=True, sort_keys=True).encode()
        if len(encoded) > 65_536:
            self._evidence.close()
            raise OpsError("capability transcript exceeded evidence bound")
        self._evidence.finish(
            {"probe_kind": "aatk-capability-transcript", "transcript": transcript}
        )
        if missing_error:
            raise OpsError(missing_error)


class NoHealthRedirects(HTTPRedirectHandler):
    """Reject health redirects before requesting their Location target."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def open_health_url(url: str, *, timeout: float, user_agent: str = HEALTH_USER_AGENT):
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": user_agent},
    )
    return build_opener(NoHealthRedirects()).open(request, timeout=timeout)


def _control_safe(value: str) -> str:
    return "".join(
        char if ord(char) >= 32 and ord(char) != 127 else "�" for char in value
    )


def _header_evidence_size(
    captured: dict[str, list[str]], omitted_names: list[str], omitted_count: int
) -> int:
    return len(
        json.dumps(
            {
                "response_headers": captured,
                "omitted_response_header_names": omitted_names,
                "omitted_response_header_count": omitted_count,
                "response_headers_complete": False,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


def _health_headers(
    headers: Any,
) -> tuple[dict[str, list[str]], list[str], int, bool]:
    captured: dict[str, list[str]] = {}
    omitted_names: list[str] = []
    omitted_seen: set[str] = set()
    omitted_count = 0
    complete = True
    if headers is None:
        return captured, omitted_names, omitted_count, complete
    for raw_name, raw_value in headers.items():
        name = _control_safe(str(raw_name).lower())
        if name not in HEALTH_DIAGNOSTIC_HEADERS:
            omitted_count += 1
            if name in omitted_seen:
                continue
            candidate_names = sorted([*omitted_names, name])
            if (
                _header_evidence_size(captured, candidate_names, omitted_count)
                <= HEALTH_HEADER_CAPTURE_LIMIT
            ):
                omitted_names = candidate_names
                omitted_seen.add(name)
            else:
                complete = False
            continue
        value = _control_safe(str(raw_value))
        if name == "location":
            try:
                parts = urlsplit(value)
                host = parts.hostname or ""
                if parts.port is not None:
                    host = f"{host}:{parts.port}"
                value = urlunsplit((parts.scheme, host, parts.path, "", ""))
            except ValueError:
                value = "[invalid-location]"
        candidate = {key: list(values) for key, values in captured.items()}
        candidate.setdefault(name, []).append(value)
        if (
            _header_evidence_size(candidate, omitted_names, omitted_count)
            <= HEALTH_HEADER_CAPTURE_LIMIT
        ):
            captured = candidate
        else:
            omitted_count += 1
            complete = False
            if name not in omitted_seen:
                candidate_names = sorted([*omitted_names, name])
                if (
                    _header_evidence_size(captured, candidate_names, omitted_count)
                    <= HEALTH_HEADER_CAPTURE_LIMIT
                ):
                    omitted_names = candidate_names
                    omitted_seen.add(name)
    while (
        _header_evidence_size(captured, omitted_names, omitted_count)
        > HEALTH_HEADER_CAPTURE_LIMIT
        and omitted_names
    ):
        omitted_names.pop()
        complete = False
    return dict(sorted(captured.items())), omitted_names, omitted_count, complete


def _body_preview(body: bytes) -> tuple[str, bool]:
    tokens: list[str] = []
    remaining = HEALTH_BODY_PREVIEW_LIMIT - 2  # JSON string quotes
    complete = True
    for byte in body:
        token = chr(byte) if 32 <= byte <= 126 else f"\\x{byte:02x}"
        serialized_length = len(json.dumps(token, ensure_ascii=True).encode()) - 2
        if serialized_length > remaining:
            complete = False
            break
        tokens.append(token)
        remaining -= serialized_length
    return "".join(tokens), complete


def _health_event(
    *,
    url: str,
    user_agent: str,
    started_wall: str,
    started_mono: float,
    status: int | None,
    headers: Any,
    body: bytes,
    body_complete: bool,
    phase: str,
    error_class: str | None = None,
) -> dict[str, Any]:
    allowed_headers, omitted_headers, omitted_count, headers_complete = _health_headers(headers)
    body_preview, preview_complete = _body_preview(body)
    return {
        "probe_kind": "unauthenticated-health",
        "phase": phase,
        "method": "GET",
        "url": url,
        "request_headers": {"accept": "application/json", "user-agent": user_agent},
        "started_at": started_wall,
        "finished_at": datetime.now(UTC).isoformat(),
        "duration_seconds": round(time.monotonic() - started_mono, 6),
        "status": status,
        "response_headers": allowed_headers,
        "response_headers_complete": headers_complete,
        "omitted_response_header_names": omitted_headers,
        "omitted_response_header_count": omitted_count,
        "body_preview_encoding": "control-safe-ascii-with-hex-byte-escapes",
        "body_preview": body_preview,
        "body_preview_complete": preview_complete,
        "captured_body_bytes": len(body),
        "captured_body_sha256": hashlib.sha256(body).hexdigest(),
        "body_complete": body_complete,
        "error_class": error_class,
    }


@dataclass(frozen=True)
class ProductionConfig:
    service_id: str
    service_name: str
    region: str
    repo: str
    branch: str
    origin_url: str
    public_url: str
    health_path: str
    source_sha256: str = field(default="", compare=False, repr=False)

    @classmethod
    def load(cls, path: Path) -> ProductionConfig:
        try:
            snapshot = path.read_bytes()
            raw = json.loads(snapshot.decode("utf-8"))
            if not isinstance(raw, dict) or "source_sha256" in raw:
                raise TypeError("invalid config object")
            config = cls(**raw, source_sha256=hashlib.sha256(snapshot).hexdigest())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise OpsError(f"invalid production config: {path}") from exc
        if not SERVICE_RE.fullmatch(config.service_id):
            raise OpsError("production config has an invalid Render service ID")
        if not config.origin_url.startswith("https://") or not config.public_url.startswith(
            "https://"
        ):
            raise OpsError("production URLs must use https")
        if not config.health_path.startswith("/"):
            raise OpsError("health_path must be absolute")
        return config


def load_api_key(path: Path) -> str:
    try:
        if path.is_symlink():
            raise OpsError("Render env file must not be a symlink")
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError as exc:
        raise OpsError(f"Render env file not found: {path}") from exc
    if mode & 0o077:
        raise OpsError(f"Render env file must not be group/world accessible (mode {mode:03o})")
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OpsError(f"Render env file cannot be read: {path}") from exc
    values: list[str] = []
    for raw in contents.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if line.startswith("RENDER_API_KEY="):
            value = line.split("=", 1)[1].strip().strip("'\"")
            values.append(value)
    if len(values) != 1 or not values[0]:
        raise OpsError("Render env file must contain exactly one nonempty RENDER_API_KEY")
    return values[0]


class RenderClient:
    def __init__(self, api_key: str, *, base_url: str = API_BASE, timeout: float = 30.0) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self._base_url}{path}",
            method=method,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise OpsError(f"Render API {method} {path} failed with HTTP {exc.code}") from exc
        except (URLError, TimeoutError) as exc:
            raise OpsError(f"Render API {method} {path} failed: {type(exc).__name__}") from exc

    def service(self, service_id: str) -> dict[str, Any]:
        return _unwrap(self.request("GET", f"/services/{service_id}"), "service")

    def deploys(self, service_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        response = self.request("GET", f"/services/{service_id}/deploys?limit={limit}")
        return [_unwrap(item, "deploy") for item in response]

    def deploy(self, service_id: str, commit: str) -> dict[str, Any]:
        return _unwrap(
            self.request(
                "POST",
                f"/services/{service_id}/deploys",
                {"clearCache": "clear", "commitId": commit},
            ),
            "deploy",
        )

    def rollback(self, service_id: str, deploy_id: str) -> dict[str, Any]:
        return _unwrap(
            self.request("POST", f"/services/{service_id}/rollback", {"deployId": deploy_id}),
            "deploy",
        )

    def deploy_by_id(self, service_id: str, deploy_id: str) -> dict[str, Any]:
        return _unwrap(self.request("GET", f"/services/{service_id}/deploys/{deploy_id}"), "deploy")


def _unwrap(value: Any, key: str) -> Any:
    if isinstance(value, dict) and key in value:
        return value[key]
    return value


def deploy_commit(deploy: dict[str, Any]) -> str:
    commit = deploy.get("commit") or {}
    return str(commit.get("id") or deploy.get("commitId") or "")


def safe_deploy(deploy: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": deploy.get("id"),
        "status": deploy.get("status"),
        "commit": deploy_commit(deploy),
        "created_at": deploy.get("createdAt"),
        "finished_at": deploy.get("finishedAt"),
    }


def validate_service(service: dict[str, Any], config: ProductionConfig) -> None:
    details = service.get("serviceDetails") or {}
    observed = {
        "id": service.get("id"),
        "name": service.get("name"),
        "region": details.get("region"),
        "repo": service.get("repo"),
        "branch": service.get("branch"),
        "url": details.get("url"),
        "suspended": service.get("suspended"),
        "autoDeploy": service.get("autoDeploy"),
    }
    expected = {
        "id": config.service_id,
        "name": config.service_name,
        "region": config.region,
        "repo": config.repo,
        "branch": config.branch,
        "url": config.origin_url,
        "suspended": "not_suspended",
        "autoDeploy": "no",
    }
    mismatches = [key for key in expected if observed[key] != expected[key]]
    if mismatches:
        raise OpsError(f"Render service does not match production config: {', '.join(mismatches)}")


def require_commit(value: str, field: str = "commit") -> str:
    if not COMMIT_RE.fullmatch(value):
        raise OpsError(f"{field} must be a full lowercase 40-character Git SHA")
    return value


def require_deploy_id(value: str, field: str = "deploy ID") -> str:
    if not DEPLOY_RE.fullmatch(value):
        raise OpsError(f"{field} is invalid")
    return value


def canonical_git_repo(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("git@github.com:"):
        normalized = f"github.com/{normalized.removeprefix('git@github.com:')}"
    elif normalized.startswith("https://") or normalized.startswith("ssh://"):
        normalized = normalized.split("://", 1)[1]
    return normalized.removesuffix(".git").rstrip("/")


def verify_git_target(
    repo_root: Path, commit: str, *, expected_repo: str, expected_branch: str
) -> None:
    require_commit(commit)
    remote_ref = f"origin/{expected_branch}"
    try:
        origin_url = subprocess.run(
            ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        remote_commit = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", remote_ref],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-e", f"{commit}^{{commit}}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise OpsError("failed to verify local Git target") from exc
    if canonical_git_repo(origin_url) != canonical_git_repo(expected_repo):
        raise OpsError("local origin remote is not the configured production repository")
    if remote_commit != commit:
        raise OpsError(f"{remote_ref} is {remote_commit}, not the approved target {commit}")


def current_live(deploys: list[dict[str, Any]]) -> dict[str, Any]:
    unknown = [deploy for deploy in deploys if deploy.get("status") not in KNOWN_STATUSES]
    if unknown:
        raise OpsError(
            f"refusing unknown Render deploy state {unknown[0].get('status')!r}: "
            f"{unknown[0].get('id')}"
        )
    active = [deploy for deploy in deploys if deploy.get("status") in IN_PROGRESS_STATUSES]
    if active:
        raise OpsError(f"another deploy is active: {active[0].get('id')}")
    live = [deploy for deploy in deploys if deploy.get("status") == "live"]
    if len(live) != 1:
        raise OpsError(f"expected exactly one live deploy, found {len(live)}")
    return live[0]


def require_deploy(deploy: dict[str, Any], *, deploy_id: str, commit: str) -> None:
    if deploy.get("id") != deploy_id or deploy_commit(deploy) != commit:
        raise OpsError("deploy ID/commit does not match the approved artifact")


def require_rollback_artifact(deploy: dict[str, Any], *, deploy_id: str, commit: str) -> None:
    require_deploy(deploy, deploy_id=deploy_id, commit=commit)
    if deploy.get("status") not in ROLLBACK_ARTIFACT_STATUSES:
        raise OpsError(f"rollback artifact is not known-good: {deploy.get('status')}")


def wait_for_deploy(
    client: RenderClient,
    config: ProductionConfig,
    deploy_id: str,
    expected_commit: str,
    *,
    timeout_seconds: int = 900,
    interval_seconds: float = 10.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_status = ""
    while time.monotonic() < deadline:
        deploy = client.deploy_by_id(config.service_id, deploy_id)
        if deploy_commit(deploy) != expected_commit:
            raise OpsError("Render deploy commit changed while waiting")
        status = str(deploy.get("status") or "")
        if status != last_status:
            print(json.dumps({"deploy_id": deploy_id, "status": status, "commit": expected_commit}))
            last_status = status
        if status == "live":
            return deploy
        if status in FAILURE_STATUSES or status == "deactivated":
            raise OpsError(f"Render deploy entered failure state: {status}")
        if status not in IN_PROGRESS_STATUSES:
            raise OpsError(f"Render deploy entered unknown state: {status!r}")
        sleep(interval_seconds)
    raise OpsError(f"timed out waiting for Render deploy {deploy_id}")


def _bounded_health_body(stream: Any) -> tuple[bytes, bool]:
    try:
        body_with_marker = stream.read(HEALTH_BODY_CAPTURE_LIMIT + 1)
        complete = len(body_with_marker) <= HEALTH_BODY_CAPTURE_LIMIT
    except IncompleteRead as exc:
        body_with_marker = exc.partial
        complete = False
    return body_with_marker[:HEALTH_BODY_CAPTURE_LIMIT], complete


def verify_health(
    url: str,
    *,
    expected_commit: str,
    allow_legacy_missing_build: bool = False,
    timeout: float = HEALTH_REQUEST_TIMEOUT_SECONDS,
    user_agent: str = HEALTH_USER_AGENT,
    evidence: HealthEvidenceRun | None = None,
    capability: CapabilityFixtureRecorder | None = None,
    capability_surface: str = "",
) -> dict[str, Any]:
    started_wall = datetime.now(UTC).isoformat()
    started_mono = time.monotonic()
    try:
        with open_health_url(url, timeout=timeout, user_agent=user_agent) as response:
            body, body_complete = _bounded_health_body(response)
            if evidence is not None:
                evidence.record(
                    _health_event(
                        url=url,
                        user_agent=user_agent,
                        started_wall=started_wall,
                        started_mono=started_mono,
                        status=response.status,
                        headers=response.headers,
                        body=body,
                        body_complete=body_complete,
                        phase="response",
                    )
                )
            if response.geturl() != url:
                raise OpsError(f"health check redirected away from exact surface {url}")
            if response.status != 200:
                if capability is not None:
                    capability.terminal_child(
                        f"health.{capability_surface}.http-200",
                        outcome="expected-failure",
                        assertion_code=f"health.{capability_surface}.http-200.rejected",
                        subject_sha256=hashlib.sha256(body).hexdigest(),
                    )
                message = f"health check failed for {url}: HTTP {response.status}"
                if response.status in RETRYABLE_HEALTH_HTTP_STATUSES:
                    raise TransientHealthError(message)
                raise PermanentHealthHTTPError(message, status=response.status)
            if not body_complete:
                raise OpsError(f"health response exceeded evidence bound for {url}")
            if capability is not None:
                capability.terminal_child(
                    f"health.{capability_surface}.http-200",
                    outcome="passed",
                    assertion_code=f"health.{capability_surface}.http-200.capability-pass",
                    subject_sha256=hashlib.sha256(body).hexdigest(),
                )
            payload = json.loads(body.decode("utf-8"))
    except HTTPError as exc:
        try:
            body, body_complete = _bounded_health_body(exc)
        except Exception:
            body_complete = False
            body = b""
        if evidence is not None:
            evidence.record(
                _health_event(
                    url=url,
                    user_agent=user_agent,
                    started_wall=started_wall,
                    started_mono=started_mono,
                    status=exc.code,
                    headers=exc.headers,
                    body=body,
                    body_complete=body_complete,
                    phase="http-error",
                    error_class="HTTPError",
                )
            )
        if capability is not None:
            capability.terminal_child(
                f"health.{capability_surface}.http-200",
                outcome="expected-failure",
                assertion_code=f"health.{capability_surface}.http-200.rejected",
                subject_sha256=hashlib.sha256(body).hexdigest(),
            )
        message = f"health check failed for {url}: HTTP {exc.code}"
        if exc.code in RETRYABLE_HEALTH_HTTP_STATUSES:
            raise TransientHealthError(message) from exc
        raise PermanentHealthHTTPError(message, status=exc.code) from exc
    except (URLError, TimeoutError, ConnectionError, HTTPException) as exc:
        if evidence is not None:
            evidence.record(
                _health_event(
                    url=url,
                    user_agent=user_agent,
                    started_wall=started_wall,
                    started_mono=started_mono,
                    status=None,
                    headers=None,
                    body=b"",
                    body_complete=False,
                    phase="transport-error",
                    error_class=type(exc).__name__,
                )
            )
        raise TransientHealthError(
            f"health check failed for {url}: {type(exc).__name__}"
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        if capability is not None:
            capability.terminal_child(
                f"health.{capability_surface}.payload-contract",
                outcome="expected-failure",
                assertion_code=f"health.{capability_surface}.payload-contract.rejected",
                subject_sha256=hashlib.sha256(body).hexdigest(),
            )
        raise TransientHealthError(f"health check returned invalid JSON from {url}") from exc
    expected = require_commit(expected_commit, "expected health commit")
    subject_sha256 = hashlib.sha256(body).hexdigest()
    if payload == {"status": "ok", "service": "library"}:
        if allow_legacy_missing_build and capability is None:
            return payload
        if capability is not None:
            capability.terminal_child(
                f"health.{capability_surface}.payload-contract",
                outcome="expected-failure",
                assertion_code=f"health.{capability_surface}.payload-contract.rejected",
                subject_sha256=subject_sha256,
            )
        raise OpsError(f"Library health returned missing build identity from {url}")
    if not isinstance(payload, dict) or set(payload) != {"status", "service", "build"}:
        if capability is not None:
            capability.terminal_child(
                f"health.{capability_surface}.payload-contract",
                outcome="expected-failure",
                assertion_code=f"health.{capability_surface}.payload-contract.rejected",
                subject_sha256=subject_sha256,
            )
        raise OpsError(f"unexpected Library health payload from {url}")
    if payload["status"] != "ok" or payload["service"] != "library":
        if capability is not None:
            capability.terminal_child(
                f"health.{capability_surface}.payload-contract",
                outcome="expected-failure",
                assertion_code=f"health.{capability_surface}.payload-contract.rejected",
                subject_sha256=subject_sha256,
            )
        raise OpsError(f"unexpected Library health payload from {url}")
    build = payload["build"]
    if not isinstance(build, dict) or set(build) != {"git_sha"}:
        if capability is not None:
            capability.terminal_child(
                f"health.{capability_surface}.payload-contract",
                outcome="expected-failure",
                assertion_code=f"health.{capability_surface}.payload-contract.rejected",
                subject_sha256=subject_sha256,
            )
        raise OpsError(f"unexpected Library health build payload from {url}")
    if capability is not None:
        capability.terminal_child(
            f"health.{capability_surface}.payload-contract",
            outcome="passed",
            assertion_code=f"health.{capability_surface}.payload-contract.capability-pass",
            subject_sha256=subject_sha256,
        )

    observed = build["git_sha"]
    if observed is None:
        raise OpsError(f"Library health returned null build identity from {url}")
    if not isinstance(observed, str) or not COMMIT_RE.fullmatch(observed):
        raise OpsError(f"Library health returned invalid build identity from {url}")
    if observed != expected:
        raise TransientHealthError(
            f"Library health build mismatch from {url}: observed {observed}, expected {expected}"
        )
    return payload


def verify_health_surfaces(
    config: ProductionConfig,
    *,
    expected_commit: str,
    allow_legacy_missing_build: bool = False,
    evidence: HealthEvidenceRun | None = None,
    capability: CapabilityFixtureRecorder | None = None,
    readiness_timeout: float = HEALTH_READINESS_TIMEOUT_SECONDS,
    retry_interval: float = HEALTH_RETRY_INTERVAL_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    if readiness_timeout <= 0 or retry_interval <= 0:
        raise OpsError("health readiness timing must be positive")
    if capability is not None:
        capability.enter(CAPABILITY_COMPONENT_SURFACES)
    started_at = monotonic()
    deadline = started_at + readiness_timeout
    attempts = 0
    last_error: TransientHealthError | None = None
    origin_url = f"{config.origin_url}{config.health_path}"
    public_url = f"{config.public_url}{config.health_path}"
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        attempts += 1
        try:
            if capability is not None:
                capability.enter(CAPABILITY_COMPONENT_ORIGIN)
            origin = verify_health(
                origin_url,
                expected_commit=expected_commit,
                allow_legacy_missing_build=allow_legacy_missing_build,
                timeout=min(HEALTH_REQUEST_TIMEOUT_SECONDS, remaining),
                evidence=evidence,
                capability=capability,
                capability_surface="origin",
            )
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TransientHealthError("health readiness deadline elapsed after origin check")
            if capability is not None:
                capability.enter(CAPABILITY_COMPONENT_PUBLIC)
            public = verify_health(
                public_url,
                expected_commit=expected_commit,
                allow_legacy_missing_build=allow_legacy_missing_build,
                timeout=min(HEALTH_REQUEST_TIMEOUT_SECONDS, remaining),
                evidence=evidence,
                capability=capability,
                capability_surface="public",
            )
            if origin != public:
                raise OpsError("origin and public Library health payloads differ")
            finished_at = monotonic()
            if finished_at > deadline:
                raise TransientHealthError("health readiness deadline elapsed after public check")
            print(
                json.dumps(
                    {
                        "health": "ready",
                        "attempts": attempts,
                        "elapsed_seconds": round(finished_at - started_at, 3),
                    }
                ),
                file=sys.stderr,
            )
            return {"origin": origin, "public": public}
        except TransientHealthError as exc:
            last_error = exc
            now = monotonic()
            remaining = max(0.0, deadline - now)
            exhausted = remaining <= 0
            retry_in = 0.0 if exhausted else min(retry_interval, remaining)
            print(
                json.dumps(
                    {
                        "health": "not_ready",
                        "attempt": attempts,
                        "elapsed_seconds": round(now - started_at, 3),
                        "retry_in_seconds": retry_in,
                        "exhausted": exhausted,
                        "error": str(exc),
                    }
                ),
                file=sys.stderr,
            )
            if exhausted:
                break
            sleep(retry_in)
    detail = f": {last_error}" if last_error is not None else ""
    raise OpsError(
        f"health readiness failed after {readiness_timeout:g} seconds and {attempts} attempts{detail}"
    )


def _verifier_identity(
    *, repo_root: Path = REPOSITORY_ROOT, script_path: Path = SCRIPT_PATH
) -> dict[str, str]:
    try:
        root = repo_root.resolve(strict=True)
        script = script_path.resolve(strict=True)
        relative_script = script.relative_to(root)
        top_level = Path(
            subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
        ).resolve(strict=True)
        if top_level != root:
            raise OpsError("verifier repository root does not match the executing script")
        source_sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        if not COMMIT_RE.fullmatch(source_sha):
            raise OpsError("verifier source commit is invalid")
        tracked_changes = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        if tracked_changes:
            raise OpsError("verifier repository has tracked changes")
        committed_script = subprocess.run(
            ["git", "-C", str(root), "show", f"HEAD:{relative_script.as_posix()}"],
            check=True,
            capture_output=True,
        ).stdout
        script_bytes = script.read_bytes()
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise OpsError("failed to establish executing verifier identity") from exc
    if script_bytes != committed_script:
        raise OpsError("executing verifier does not match its source commit")
    return {
        "verifier_source_sha": source_sha,
        "verifier_script_sha256": hashlib.sha256(script_bytes).hexdigest(),
        "verifier_script_path": relative_script.as_posix(),
    }


def _command_health_evidence(
    args: argparse.Namespace, *, label: str, config: ProductionConfig
) -> HealthEvidenceRun:
    value = str(getattr(args, "evidence_dir", "") or "").strip()
    if not value:
        raise OpsError("PROD_EVIDENCE_DIR/--evidence-dir is required for health evidence")
    if not re.fullmatch(r"[0-9a-f]{64}", config.source_sha256):
        raise OpsError("production config lacks an immutable source digest")
    metadata = {
        **_verifier_identity(),
        "config_sha256": config.source_sha256,
        "service_id": config.service_id,
        "expected_commit": str(
            getattr(args, "commit", "")
            or getattr(args, "rollback_commit", "")
            or getattr(args, "expected_commit", "")
        ),
    }
    return HealthEvidenceRun(Path(value), label=label, metadata=metadata)


def _command_capability_fixture(
    args: argparse.Namespace,
    *,
    config: ProductionConfig,
    deploy_id: str,
    commit: str,
) -> CapabilityFixtureRecorder | None:
    value = str(getattr(args, "capability_fixture_dir", "") or "").strip()
    if not value:
        return None
    return CapabilityFixtureRecorder(
        Path(value),
        config=config,
        deploy_id=deploy_id,
        commit=commit,
        correlation_id=str(getattr(args, "capability_correlation_id", "") or ""),
        mutation_id=str(getattr(args, "capability_mutation_id", "") or ""),
    )


def command_health_client_proof(args: argparse.Namespace) -> dict[str, Any]:
    config = ProductionConfig.load(Path(args.config))
    expected_commit = require_commit(args.expected_commit, "expected health commit")
    allow_legacy_missing_build = _legacy_missing_build_allowed(
        args.allow_legacy_missing_build_for,
        expected_commit=expected_commit,
    )
    evidence = _command_health_evidence(args, label="health-client-proof", config=config)
    url = f"{config.public_url}{config.health_path}"
    proof_minute = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M")
    try:
        verify_health(
            url,
            expected_commit=expected_commit,
            allow_legacy_missing_build=allow_legacy_missing_build,
            user_agent=BLOCKED_BASELINE_USER_AGENT,
            evidence=evidence,
        )
    except PermanentHealthHTTPError as exc:
        if exc.status != 403:
            evidence.finish(
                {
                    "probe_kind": "run-outcome",
                    "outcome": "failed",
                    "stage": "blocked-baseline",
                    "error_class": type(exc).__name__,
                }
            )
            raise
    except Exception as exc:
        evidence.finish(
            {
                "probe_kind": "run-outcome",
                "outcome": "failed",
                "stage": "blocked-baseline",
                "error_class": type(exc).__name__,
            }
        )
        raise
    else:
        evidence.finish(
            {
                "probe_kind": "run-outcome",
                "outcome": "failed",
                "stage": "blocked-baseline",
                "error_class": "ExpectedHTTP403NotObserved",
            }
        )
        raise OpsError("blocked baseline User-Agent did not return HTTP 403")
    try:
        payload = verify_health(
            url,
            expected_commit=expected_commit,
            allow_legacy_missing_build=allow_legacy_missing_build,
            user_agent=HEALTH_USER_AGENT,
            evidence=evidence,
        )
    except Exception as exc:
        evidence.finish(
            {
                "probe_kind": "run-outcome",
                "outcome": "failed",
                "stage": "honest-gate",
                "error_class": type(exc).__name__,
            }
        )
        raise
    if datetime.now(UTC).strftime("%Y-%m-%dT%H:%M") != proof_minute:
        evidence.finish(
            {
                "probe_kind": "run-outcome",
                "outcome": "failed",
                "stage": "freshness",
                "error_class": "CrossMinuteProof",
            }
        )
        raise OpsError("health client proof crossed a UTC minute boundary; rerun it")
    evidence.finish({"probe_kind": "run-outcome", "outcome": "red-green-pass"})
    return {
        "baseline_user_agent_status": 403,
        "gate_user_agent_status": 200,
        "health": payload,
        "evidence_dir": str(evidence.path),
    }


def _client(args: argparse.Namespace) -> tuple[RenderClient, ProductionConfig]:
    config = ProductionConfig.load(Path(args.config))
    api_key = load_api_key(Path(args.env_file).expanduser())
    return RenderClient(api_key), config


def _confirm_apply(args: argparse.Namespace, config: ProductionConfig) -> None:
    if not args.apply:
        raise OpsError("mutation refused: pass --apply (Makefile requires APPLY=1)")
    if args.confirm_service_id != config.service_id:
        raise OpsError("mutation refused: exact service-ID confirmation does not match")


def _legacy_missing_build_allowed(value: str, *, expected_commit: str) -> bool:
    """Temporary AASB bridge for exact pre-AASR artifacts.

    Stop using it for preflight once the candidate is live; delete it after no pre-AASR
    artifact remains an approved rollback target.
    """
    if not value:
        return False
    approved = require_commit(value, "legacy missing-build commit")
    if approved != expected_commit:
        raise OpsError("legacy missing-build commit does not match the approved target")
    return True


def command_status(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    service = client.service(config.service_id)
    validate_service(service, config)
    deploys = client.deploys(config.service_id)
    live = current_live(deploys)
    details = service.get("serviceDetails") or {}
    return {
        "service": {
            "id": service.get("id"),
            "name": service.get("name"),
            "region": details.get("region"),
            "origin_url": details.get("url"),
            "public_url": config.public_url,
            "auto_deploy": service.get("autoDeploy"),
        },
        "live_deploy": safe_deploy(live),
    }


def command_deploy(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    _confirm_apply(args, config)
    commit = require_commit(args.commit)
    rollback_commit = require_commit(args.rollback_commit, "rollback commit")
    rollback_id = require_deploy_id(args.rollback_deploy_id, "rollback deploy ID")
    if args.timeout <= 0:
        raise OpsError("timeout must be positive")
    evidence = _command_health_evidence(args, label="deploy-health", config=config)
    try:
        verify_git_target(
            Path(args.repo_root),
            commit,
            expected_repo=config.repo,
            expected_branch=config.branch,
        )
        service = client.service(config.service_id)
        validate_service(service, config)
        live = current_live(client.deploys(config.service_id))
        require_rollback_artifact(live, deploy_id=rollback_id, commit=rollback_commit)
        created = client.deploy(config.service_id, commit)
        deploy_id = require_deploy_id(str(created.get("id") or ""), "created deploy ID")
        if deploy_commit(created) != commit:
            raise OpsError("Render created a deploy for the wrong commit")
        finished = wait_for_deploy(client, config, deploy_id, commit, timeout_seconds=args.timeout)
        final_live = current_live(client.deploys(config.service_id))
        require_deploy(final_live, deploy_id=deploy_id, commit=commit)
        health = verify_health_surfaces(config, expected_commit=commit, evidence=evidence)
    except Exception as exc:
        evidence.finish(
            {
                "probe_kind": "run-outcome",
                "outcome": "failed",
                "stage": "deploy",
                "error_class": type(exc).__name__,
            }
        )
        raise
    evidence.finish({"probe_kind": "run-outcome", "outcome": "passed", "stage": "deploy"})
    return {"deploy": safe_deploy(finished), "rollback": safe_deploy(live), "health": health}


def command_wait(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    deploy_id = require_deploy_id(args.deploy_id)
    commit = require_commit(args.commit)
    if args.timeout <= 0:
        raise OpsError("timeout must be positive")
    validate_service(client.service(config.service_id), config)
    finished = wait_for_deploy(client, config, deploy_id, commit, timeout_seconds=args.timeout)
    return {"deploy": safe_deploy(finished)}


def command_verify(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    deploy_id = require_deploy_id(args.deploy_id)
    commit = require_commit(args.commit)
    evidence = _command_health_evidence(args, label="verify-health", config=config)
    capability = _command_capability_fixture(
        args,
        config=config,
        deploy_id=deploy_id,
        commit=commit,
    )
    if capability is not None:
        capability.enter(CAPABILITY_COMPONENT_COMMAND)
    try:
        validate_service(client.service(config.service_id), config)
        artifact = client.deploy_by_id(config.service_id, deploy_id)
        require_deploy(artifact, deploy_id=deploy_id, commit=commit)
        if artifact.get("status") != "live":
            raise OpsError(f"expected deploy is not live: {artifact.get('status')}")
        live = current_live(client.deploys(config.service_id))
        require_deploy(live, deploy_id=deploy_id, commit=commit)
        health = verify_health_surfaces(
            config,
            expected_commit=commit,
            evidence=evidence,
            capability=capability,
        )
        if capability is not None:
            capability.finish(outcome="passed")
    except Exception as exc:
        if capability is not None:
            capability.finish(
                outcome="failed",
                error_code=(
                    str(exc)
                    if str(exc).startswith("capability-")
                    else type(exc).__name__
                ),
            )
        evidence.finish(
            {
                "probe_kind": "run-outcome",
                "outcome": "failed",
                "stage": "verify",
                "error_class": type(exc).__name__,
            }
        )
        raise
    evidence.finish({"probe_kind": "run-outcome", "outcome": "passed", "stage": "verify"})
    return {
        "deploy": safe_deploy(artifact),
        "health": health,
        "predicate_ids": postdeploy_predicate_inventory(),
    }


def command_rollback(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    _confirm_apply(args, config)
    rollback_commit = require_commit(args.rollback_commit, "rollback commit")
    allow_legacy_missing_build = _legacy_missing_build_allowed(
        args.allow_legacy_missing_build_for,
        expected_commit=rollback_commit,
    )
    rollback_id = require_deploy_id(args.rollback_deploy_id, "rollback deploy ID")
    current_commit = require_commit(args.current_commit, "current live commit")
    current_id = require_deploy_id(args.current_deploy_id, "current live deploy ID")
    if args.timeout <= 0:
        raise OpsError("timeout must be positive")
    evidence = _command_health_evidence(args, label="rollback-health", config=config)
    try:
        service = client.service(config.service_id)
        validate_service(service, config)
        live = current_live(client.deploys(config.service_id))
        require_deploy(live, deploy_id=current_id, commit=current_commit)
        if current_id == rollback_id:
            raise OpsError("current live deploy and rollback artifact must be different")
        artifact = client.deploy_by_id(config.service_id, rollback_id)
        require_rollback_artifact(artifact, deploy_id=rollback_id, commit=rollback_commit)
        created = client.rollback(config.service_id, rollback_id)
        created_id = require_deploy_id(str(created.get("id") or ""), "created rollback deploy ID")
        if deploy_commit(created) != rollback_commit:
            raise OpsError("Render created a rollback for the wrong commit")
        finished = wait_for_deploy(
            client, config, created_id, rollback_commit, timeout_seconds=args.timeout
        )
        final_live = current_live(client.deploys(config.service_id))
        require_deploy(final_live, deploy_id=created_id, commit=rollback_commit)
        health = verify_health_surfaces(
            config,
            expected_commit=rollback_commit,
            allow_legacy_missing_build=allow_legacy_missing_build,
            evidence=evidence,
        )
    except Exception as exc:
        evidence.finish(
            {
                "probe_kind": "run-outcome",
                "outcome": "failed",
                "stage": "rollback",
                "error_class": type(exc).__name__,
            }
        )
        raise
    evidence.finish({"probe_kind": "run-outcome", "outcome": "passed", "stage": "rollback"})
    return {"rollback_deploy": safe_deploy(finished), "health": health}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", default=os.environ.get("PROD_CONFIG", "ops/render-production.json"))
    p.add_argument("--env-file", default=os.environ.get("RENDER_ENV_FILE", "~/.aweb-render/env"))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    proof = sub.add_parser("health-client-proof")
    proof.add_argument("--expected-commit", default=os.environ.get("CURRENT_COMMIT", ""))
    proof.add_argument(
        "--allow-legacy-missing-build-for",
        default=os.environ.get("ALLOW_LEGACY_MISSING_BUILD_FOR", ""),
    )
    proof.add_argument("--evidence-dir", default=os.environ.get("PROD_EVIDENCE_DIR", ""))
    deploy = sub.add_parser("deploy")
    deploy.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    deploy.add_argument("--rollback-deploy-id", default=os.environ.get("ROLLBACK_DEPLOY_ID", ""))
    deploy.add_argument("--rollback-commit", default=os.environ.get("ROLLBACK_COMMIT", ""))
    deploy.add_argument("--repo-root", default=".")
    deploy.add_argument("--confirm-service-id", default=os.environ.get("CONFIRM_SERVICE_ID", ""))
    deploy.add_argument("--timeout", type=int, default=900)
    deploy.add_argument("--evidence-dir", default=os.environ.get("PROD_EVIDENCE_DIR", ""))
    deploy.add_argument("--apply", action="store_true", default=os.environ.get("APPLY") == "1")
    wait = sub.add_parser("wait")
    wait.add_argument("--deploy-id", default=os.environ.get("PROD_DEPLOY_ID", ""))
    wait.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    wait.add_argument("--timeout", type=int, default=900)
    verify = sub.add_parser("verify")
    verify.add_argument("--deploy-id", default=os.environ.get("PROD_DEPLOY_ID", ""))
    verify.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    verify.add_argument("--evidence-dir", default=os.environ.get("PROD_EVIDENCE_DIR", ""))
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--rollback-deploy-id", default=os.environ.get("ROLLBACK_DEPLOY_ID", ""))
    rollback.add_argument("--rollback-commit", default=os.environ.get("ROLLBACK_COMMIT", ""))
    rollback.add_argument("--current-deploy-id", default=os.environ.get("CURRENT_DEPLOY_ID", ""))
    rollback.add_argument("--current-commit", default=os.environ.get("CURRENT_COMMIT", ""))
    rollback.add_argument("--confirm-service-id", default=os.environ.get("CONFIRM_SERVICE_ID", ""))
    rollback.add_argument(
        "--allow-legacy-missing-build-for",
        default=os.environ.get("ALLOW_LEGACY_MISSING_BUILD_FOR", ""),
    )
    rollback.add_argument("--timeout", type=int, default=900)
    rollback.add_argument("--evidence-dir", default=os.environ.get("PROD_EVIDENCE_DIR", ""))
    rollback.add_argument("--apply", action="store_true", default=os.environ.get("APPLY") == "1")
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command in {"deploy", "verify", "rollback"} and not args.evidence_dir:
            raise OpsError("PROD_EVIDENCE_DIR/--evidence-dir is required for health evidence")
        if args.command == "status":
            result = command_status(args)
        elif args.command == "health-client-proof":
            if not args.evidence_dir:
                raise OpsError("PROD_EVIDENCE_DIR/--evidence-dir is required")
            result = command_health_client_proof(args)
        elif args.command == "deploy":
            result = command_deploy(args)
        elif args.command == "wait":
            result = command_wait(args)
        elif args.command == "verify":
            result = command_verify(args)
        elif args.command == "rollback":
            result = command_rollback(args)
        else:  # pragma: no cover
            raise OpsError("unsupported command")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except OpsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

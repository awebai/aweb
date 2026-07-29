#!/usr/bin/env python3
"""Validate Library's static AATK coverage contract and immutable run ledgers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from scripts import library_prod_gate, render_ops
except ModuleNotFoundError:  # direct ``python scripts/aatk.py`` execution
    import library_prod_gate  # type: ignore[no-redef]
    import render_ops  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "ops" / "aatk-manifest.json"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
FIELD_PATH_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
SENTINELS = ("NOTHING", "UNKNOWN", "EXISTS-BUT-NOT-INVOKED", "CANNOT-RUN-FROM-A-CLEAN-CHECKOUT")
PROOF_FIELDS = {
    "make_target",
    "layer",
    "surface",
    "path_fingerprint",
    "assertion_code",
    "safety_class",
    "allowed_substitutions",
}
ENFORCEMENT_HISTORY = {
    "architecture.static-dynamic-separation": "increment-1",
    "predicates.exact-universe": "increment-1",
    "schema.typed-contracts": "increment-1",
    "controls.structural-positive-negative-pair": "increment-1",
    "candidate-only.structural-allowlist": "increment-1",
    "validator.falsification": "increment-1",
}
IMPLEMENTED_ENFORCEMENT_IDS = frozenset(ENFORCEMENT_HISTORY)
DEFERRED_ENFORCEMENT_IDS = frozenset(
    {
        "runtime.path-fidelity",
        "execution.capability-obligation",
        "identity.incumbent-rollback-semantics",
        "receipts.freshness-immutability",
        "lifecycle.transitions",
        "safety.boundary-invocation",
        "controls.executed-same-path",
        "candidate-only.runtime-proof",
        "orchestrator.falsification",
    }
)

RECEIPT_FIELDS = {
    "predicate_id",
    "proof_kind",
    "manifest_sha256",
    "candidate_sha",
    "source_sha",
    "script_sha256",
    "config_sha256",
    "make_target",
    "normalized_arguments",
    "layer",
    "surface",
    "path_fingerprint",
    "substitutions",
    "safety_class",
    "parent_run_id",
    "run_id",
    "started_at",
    "finished_at",
    "fresh_until",
    "terminal",
    "artifact",
}


class AATKError(RuntimeError):
    """A safe validation failure with a stable reason code."""

    def __init__(self, code: str, location: str, detail: str) -> None:
        super().__init__(f"{code}: {location}: {detail}")
        self.code = code
        self.location = location


def fail(code: str, location: str, detail: str) -> None:
    raise AATKError(code, location, detail)


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(manifest)).hexdigest()


def load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail("invalid-json", label, str(exc))
    if not isinstance(value, dict):
        fail("invalid-object", label, "must be a JSON object")
    return value


def source_predicates_by_executor() -> dict[str, list[str]]:
    return {
        "scripts.library_prod_gate.POSTDEPLOY_PREDICATES": (
            library_prod_gate.postdeploy_predicate_inventory()
        ),
        "scripts.render_ops.POSTDEPLOY_PREDICATES": render_ops.postdeploy_predicate_inventory(),
    }


def source_capability_coverage() -> list[dict[str, Any]]:
    """Return exact source-owned coverage rows from the actual executors."""
    rows = [
        *library_prod_gate.aatk_predicate_coverage(),
        *render_ops.aatk_predicate_coverage(),
    ]
    instrumented = {
        str(row.get("id"))
        for row in rows
        if isinstance(row.get("obligations"), dict)
        and set(row["obligations"].values()) == {"instrumented-capability"}
    }
    if instrumented != render_ops.CAPABILITY_FIXTURE_PREDICATES:
        fail(
            "capability-emitter-registration",
            "source.capability_coverage",
            f"coverage/emitter mismatch: coverage={sorted(instrumented)} emitter={sorted(render_ops.CAPABILITY_FIXTURE_PREDICATES)}",
        )
    return sorted(
        rows,
        key=lambda row: (str(row.get("domain")), str(row.get("id"))),
    )


def source_predicates() -> frozenset[str]:
    inventory = source_predicates_by_executor()
    flattened = [predicate for predicates in inventory.values() for predicate in predicates]
    if len(flattened) != len(set(flattened)):
        fail("duplicate-source-predicate", "source.POSTDEPLOY_PREDICATES", "executor inventories overlap")
    return frozenset(flattened)


def candidate_only_predicates() -> frozenset[str]:
    return frozenset(render_ops.CANDIDATE_ONLY_POSTDEPLOY_PREDICATES) | frozenset(
        library_prod_gate.CANDIDATE_ONLY_POSTDEPLOY_PREDICATES
    )


def make_targets(makefile: Path = ROOT / "Makefile") -> frozenset[str]:
    try:
        text = makefile.read_text(encoding="utf-8")
    except OSError as exc:
        fail("makefile-unreadable", "Makefile", str(exc))
    return frozenset(
        match.group(1)
        for line in text.splitlines()
        if (match := re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*):(?:\s|$)", line))
    )


STATIC_FORBIDDEN_KEYS = {
    "run_id",
    "parent_run_id",
    "started_at",
    "finished_at",
    "fresh_until",
    "terminal",
    "outcome",
    "runtime_receipt",
}


def reject_static_runtime_state(value: Any, *, location: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in STATIC_FORBIDDEN_KEYS:
                fail("static-dynamic-contamination", f"{location}.{key}", "runtime state is forbidden in the static manifest")
            reject_static_runtime_state(child, location=f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_static_runtime_state(child, location=f"{location}[{index}]")


def reject_sentinels(value: Any, *, location: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            reject_sentinels(child, location=f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sentinels(child, location=f"{location}[{index}]")
    elif isinstance(value, str):
        upper = value.upper()
        for sentinel in SENTINELS:
            if sentinel in upper:
                fail("sentinel-value", location, f"contains forbidden sentinel {sentinel}")
        if not value.strip():
            fail("blank-value", location, "must not be blank")


def require_exact_keys(value: Any, expected: set[str], *, location: str, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code, location, "must be an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        fail(code, location, f"key mismatch: missing={missing} extra={extra}")
    return value


def require_stable_id(value: Any, *, location: str, code: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        fail(code, location, "must be a stable ID")
    return value


def require_string(value: Any, *, location: str, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(code, location, "must be a nonblank string")
    return value


def validate_proof_spec(value: Any, *, location: str, targets: frozenset[str]) -> dict[str, Any]:
    value = require_exact_keys(value, PROOF_FIELDS, location=location, code="invalid-proof")
    target = value["make_target"]
    if not isinstance(target, str) or target not in targets:
        fail("unchecked-command", f"{location}.make_target", f"Make target {target!r} is not checked in")
    fingerprint = value["path_fingerprint"]
    if (
        not isinstance(fingerprint, list)
        or not fingerprint
        or not all(isinstance(item, str) and ID_RE.fullmatch(item) for item in fingerprint)
        or len(fingerprint) != len(set(fingerprint))
    ):
        fail("invalid-path-fingerprint", f"{location}.path_fingerprint", "must be unique stable component IDs")
    substitutions = value["allowed_substitutions"]
    if (
        not isinstance(substitutions, list)
        or not all(isinstance(item, str) and ID_RE.fullmatch(item) for item in substitutions)
        or len(substitutions) != len(set(substitutions))
    ):
        fail("invalid-substitutions", f"{location}.allowed_substitutions", "must be stable IDs")
    if not isinstance(value["safety_class"], str) or value["safety_class"] not in {"read-only", "isolated", "postdeploy-read-only", "rollback-mutation"}:
        fail("invalid-safety-class", f"{location}.safety_class", "unrecognized safety class")
    for field in ("layer", "surface", "assertion_code"):
        require_stable_id(value[field], location=f"{location}.{field}", code="invalid-proof-field")
    return value


CAPABILITY_OBLIGATION_IDS = frozenset(
    {
        "runtime.path-fidelity",
        "safety.boundary-invocation",
        "controls.executed-same-path",
    }
)


def validate_capability_coverage(rows: Any) -> list[dict[str, Any]]:
    """Validate exact source-owned predicate-domain capability coverage."""
    if not isinstance(rows, list) or not rows:
        fail("capability-coverage", "manifest.capability_coverage", "must be a nonempty list")
    seen: set[tuple[str, str]] = set()
    candidate_ids: set[str] = set()
    identical_targets: list[tuple[str, str]] = []
    for index, raw_row in enumerate(rows):
        location = f"manifest.capability_coverage[{index}]"
        row = require_exact_keys(
            raw_row,
            {"domain", "id", "owner", "candidate_mapping", "obligations"},
            location=location,
            code="capability-coverage",
        )
        domain = row["domain"]
        if not isinstance(domain, str) or domain not in {
            "candidate-postdeploy",
            "current-incumbent",
        }:
            fail("capability-domain", f"{location}.domain", "invalid predicate domain")
        predicate_id = require_stable_id(
            row["id"], location=f"{location}.id", code="capability-coverage"
        )
        require_stable_id(
            row["owner"], location=f"{location}.owner", code="capability-coverage"
        )
        key = (domain, predicate_id)
        if key in seen:
            fail("duplicate-capability-predicate", f"{location}.id", str(key))
        seen.add(key)
        obligations = require_exact_keys(
            row["obligations"],
            CAPABILITY_OBLIGATION_IDS,
            location=f"{location}.obligations",
            code="capability-coverage",
        )
        for obligation_id, state in obligations.items():
            if not isinstance(state, str) or state not in {
                "deferred",
                "instrumented-capability",
            }:
                fail(
                    "capability-state",
                    f"{location}.obligations.{obligation_id}",
                    "must be deferred or instrumented-capability",
                )
        mapping = row["candidate_mapping"]
        if domain == "candidate-postdeploy":
            require_exact_keys(
                mapping,
                {"state"},
                location=f"{location}.candidate_mapping",
                code="candidate-mapping",
            )
            if mapping["state"] != "self":
                fail(
                    "candidate-mapping",
                    f"{location}.candidate_mapping.state",
                    "candidate predicates must map to self",
                )
            candidate_ids.add(predicate_id)
        else:
            if not isinstance(mapping, dict):
                fail("candidate-mapping", f"{location}.candidate_mapping", "must be an object")
            state = mapping.get("state")
            if state == "deferred":
                mapping = require_exact_keys(
                    mapping,
                    {"state", "blocked_obligation_ids"},
                    location=f"{location}.candidate_mapping",
                    code="candidate-mapping",
                )
                blocked = mapping["blocked_obligation_ids"]
                if (
                    not isinstance(blocked, list)
                    or not blocked
                    or not all(isinstance(item, str) for item in blocked)
                    or len(blocked) != len(set(blocked))
                    or not set(blocked) <= DEFERRED_ENFORCEMENT_IDS
                ):
                    fail(
                        "candidate-mapping",
                        f"{location}.candidate_mapping.blocked_obligation_ids",
                        "must be unique deferred global obligation IDs",
                    )
            elif state == "identical":
                mapping = require_exact_keys(
                    mapping,
                    {
                        "state",
                        "candidate_predicate_id",
                        "runtime",
                        "surface",
                        "assertion_code",
                    },
                    location=f"{location}.candidate_mapping",
                    code="candidate-mapping",
                )
                for field in (
                    "candidate_predicate_id",
                    "runtime",
                    "surface",
                    "assertion_code",
                ):
                    require_stable_id(
                        mapping[field],
                        location=f"{location}.candidate_mapping.{field}",
                        code="candidate-mapping",
                    )
                identical_targets.append((predicate_id, mapping["candidate_predicate_id"]))
            else:
                fail(
                    "candidate-mapping",
                    f"{location}.candidate_mapping.state",
                    "must be deferred or identical",
                )
    if candidate_ids != source_predicates():
        fail(
            "capability-universe",
            "manifest.capability_coverage",
            f"candidate coverage differs from source: missing={sorted(source_predicates() - candidate_ids)} extra={sorted(candidate_ids - source_predicates())}",
        )
    mapped_targets = [target for _, target in identical_targets]
    unknown_targets = sorted(set(mapped_targets) - candidate_ids)
    if unknown_targets:
        fail(
            "candidate-mapping",
            "manifest.capability_coverage",
            f"identical mappings target unknown candidate predicates {unknown_targets}",
        )
    if len(mapped_targets) != len(set(mapped_targets)):
        fail(
            "candidate-mapping",
            "manifest.capability_coverage",
            "identical mappings cannot flatten multiple source IDs onto one candidate ID",
        )
    if rows != source_capability_coverage():
        fail(
            "capability-source-mismatch",
            "manifest.capability_coverage",
            "manifest coverage must exactly equal source emitter registration",
        )
    return rows


def validate_capability_transcript(value: Any) -> dict[str, Any]:
    """Validate an untrusted child capability transcript, never lifecycle evidence."""
    transcript = require_exact_keys(
        value,
        {
            "schema",
            "transcript_class",
            "driver",
            "correlation_id",
            "mutation_id",
            "source",
            "config_sha256",
            "normalized_arguments",
            "substitutions",
            "observed_components",
            "children",
            "terminal",
        },
        location="capability",
        code="capability-transcript",
    )
    if transcript["schema"] != "library.aatk-capability-transcript.v1":
        fail("capability-transcript", "capability.schema", "unexpected schema")
    if transcript["transcript_class"] != "capability-fixture":
        fail(
            "capability-transcript",
            "capability.transcript_class",
            "must be capability-fixture",
        )
    if transcript["driver"] != "render_ops.command_verify":
        fail(
            "capability-driver",
            "capability.driver",
            "increment 2A proves only render_ops.command_verify",
        )
    require_stable_id(
        transcript["correlation_id"],
        location="capability.correlation_id",
        code="capability-transcript",
    )
    mutation_id = transcript["mutation_id"]
    if mutation_id != "":
        require_stable_id(
            mutation_id,
            location="capability.mutation_id",
            code="capability-transcript",
        )
    source = require_exact_keys(
        transcript["source"],
        {"verifier_source_sha", "verifier_script_sha256", "verifier_script_path"},
        location="capability.source",
        code="capability-source",
    )
    if not isinstance(source["verifier_source_sha"], str) or not COMMIT_RE.fullmatch(
        source["verifier_source_sha"]
    ):
        fail("capability-source", "capability.source.verifier_source_sha", "must be a commit")
    if not isinstance(source["verifier_script_sha256"], str) or not SHA_RE.fullmatch(
        source["verifier_script_sha256"]
    ):
        fail("capability-source", "capability.source.verifier_script_sha256", "must be sha256")
    if source["verifier_script_path"] != "scripts/render_ops.py":
        fail("capability-source", "capability.source.verifier_script_path", "unexpected script")
    if not isinstance(transcript["config_sha256"], str) or not SHA_RE.fullmatch(
        transcript["config_sha256"]
    ):
        fail("capability-source", "capability.config_sha256", "must be sha256")
    arguments = require_exact_keys(
        transcript["normalized_arguments"],
        {"commit", "deploy_id", "service_id"},
        location="capability.normalized_arguments",
        code="capability-arguments",
    )
    if not isinstance(arguments["commit"], str) or not COMMIT_RE.fullmatch(arguments["commit"]):
        fail("capability-arguments", "capability.normalized_arguments.commit", "must be a commit")
    for field in ("deploy_id", "service_id"):
        require_stable_id(
            arguments[field],
            location=f"capability.normalized_arguments.{field}",
            code="capability-arguments",
        )
    expected_substitutions = [
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
    ]
    if transcript["substitutions"] != expected_substitutions:
        fail(
            "capability-substitutions",
            "capability.substitutions",
            "must equal the isolated slice boundary allowlist",
        )
    components = transcript["observed_components"]
    if (
        not isinstance(components, list)
        or not components
        or not all(isinstance(item, str) and ID_RE.fullmatch(item) for item in components)
        or len(components) != len(set(components))
    ):
        fail(
            "capability-components",
            "capability.observed_components",
            "must be unique stable entered components",
        )
    allowed_component_paths = [
        [render_ops.CAPABILITY_COMPONENT_COMMAND],
        [
            render_ops.CAPABILITY_COMPONENT_COMMAND,
            render_ops.CAPABILITY_COMPONENT_SURFACES,
        ],
        [
            render_ops.CAPABILITY_COMPONENT_COMMAND,
            render_ops.CAPABILITY_COMPONENT_SURFACES,
            render_ops.CAPABILITY_COMPONENT_ORIGIN,
        ],
        [
            render_ops.CAPABILITY_COMPONENT_COMMAND,
            render_ops.CAPABILITY_COMPONENT_SURFACES,
            render_ops.CAPABILITY_COMPONENT_ORIGIN,
            render_ops.CAPABILITY_COMPONENT_PUBLIC,
        ],
    ]
    component_path_valid = components in allowed_component_paths
    children = transcript["children"]
    if not isinstance(children, list):
        fail("capability-children", "capability.children", "must be a list")
    seen_children: set[str] = set()
    for index, raw_child in enumerate(children):
        location = f"capability.children[{index}]"
        child = require_exact_keys(
            raw_child,
            {
                "predicate_id",
                "observed_subject_path",
                "terminal",
                "subject_artifact_sha256",
            },
            location=location,
            code="capability-child",
        )
        predicate_id = child["predicate_id"]
        if predicate_id not in render_ops.CAPABILITY_FIXTURE_PREDICATES:
            fail("capability-child", f"{location}.predicate_id", "predicate is outside slice")
        if predicate_id in seen_children:
            fail("capability-child", f"{location}.predicate_id", "duplicate terminal child")
        seen_children.add(predicate_id)
        path = child["observed_subject_path"]
        expected_path = [
            render_ops.CAPABILITY_COMPONENT_COMMAND,
            render_ops.CAPABILITY_COMPONENT_SURFACES,
            render_ops.CAPABILITY_COMPONENT_ORIGIN,
        ]
        if predicate_id.startswith("health.public."):
            expected_path.append(render_ops.CAPABILITY_COMPONENT_PUBLIC)
        if not isinstance(path, list) or path != expected_path:
            fail(
                "capability-path",
                f"{location}.observed_subject_path",
                f"must equal the exact entered subject path {expected_path}",
            )
        if path != components[: len(path)]:
            fail(
                "capability-path",
                f"{location}.observed_subject_path",
                "must be an entered path prefix",
            )
        terminal = require_exact_keys(
            child["terminal"],
            {"outcome", "assertion_code", "count"},
            location=f"{location}.terminal",
            code="capability-child",
        )
        if terminal["outcome"] not in {"passed", "expected-failure"}:
            fail("capability-child", f"{location}.terminal.outcome", "invalid outcome")
        if (
            terminal["outcome"] == "expected-failure"
            and mutation_id != f"{predicate_id}.dedicated-negative"
        ):
            fail(
                "capability-mutation",
                "capability.mutation_id",
                "negative child requires its dedicated single-variable mutation ID",
            )
        require_stable_id(
            terminal["assertion_code"],
            location=f"{location}.terminal.assertion_code",
            code="capability-child",
        )
        expected_assertion = (
            f"{predicate_id}.capability-pass"
            if terminal["outcome"] == "passed"
            else f"{predicate_id}.rejected"
        )
        if terminal["assertion_code"] != expected_assertion:
            fail(
                "capability-assertion",
                f"{location}.terminal.assertion_code",
                f"expected {expected_assertion}",
            )
        if terminal["count"] != 1 or isinstance(terminal["count"], bool):
            fail("capability-child", f"{location}.terminal.count", "must equal one")
        if not isinstance(child["subject_artifact_sha256"], str) or not SHA_RE.fullmatch(
            child["subject_artifact_sha256"]
        ):
            fail("capability-child", f"{location}.subject_artifact_sha256", "must be sha256")
    terminal = require_exact_keys(
        transcript["terminal"],
        {"outcome", "error_code", "count"},
        location="capability.terminal",
        code="capability-terminal",
    )
    if terminal["outcome"] not in {"passed", "failed"}:
        fail("capability-terminal", "capability.terminal.outcome", "invalid outcome")
    if not isinstance(terminal["error_code"], str):
        fail("capability-terminal", "capability.terminal.error_code", "must be a string")
    if terminal["count"] != 1 or isinstance(terminal["count"], bool):
        fail("capability-terminal", "capability.terminal.count", "must equal one")
    if terminal["outcome"] == "failed" and not component_path_valid:
        if terminal["error_code"] != "capability-path-mismatch":
            fail(
                "capability-components",
                "capability.observed_components",
                "invalid path requires the exact path-mismatch terminal code",
            )
    if terminal["outcome"] == "passed":
        if components != allowed_component_paths[-1]:
            fail(
                "capability-components",
                "capability.observed_components",
                "passing slice requires the complete exact subject path",
            )
        if mutation_id != "":
            fail(
                "capability-mutation",
                "capability.mutation_id",
                "passing capability cannot claim an active mutation",
            )
        if seen_children != render_ops.CAPABILITY_FIXTURE_PREDICATES:
            fail("capability-incomplete", "capability.children", "passing slice requires all five children")
        if any(child["terminal"]["outcome"] != "passed" for child in children):
            fail("capability-incomplete", "capability.children", "passing slice cannot contain a negative")
        expected_child_order = [
            "health.origin.http-200",
            "health.origin.payload-contract",
            "health.public.http-200",
            "health.public.payload-contract",
        ]
        if [child["predicate_id"] for child in children] != expected_child_order:
            fail(
                "capability-child-order",
                "capability.children",
                "passing children must preserve exact parallel execution order",
            )
        if terminal["error_code"] != "":
            fail("capability-terminal", "capability.terminal.error_code", "passing transcript has no error")
    return transcript


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        fail("manifest-contract", "manifest", "must be an object")
    reject_sentinels(manifest, location="manifest")
    reject_static_runtime_state(manifest, location="manifest")
    if manifest.get("schema") != "library.aatk-manifest.v1":
        fail("schema", "manifest.schema", "expected library.aatk-manifest.v1")
    targets = make_targets()
    required_top = {
        "schema",
        "service",
        "postdeploy_entrypoint",
        "protected_ci",
        "requirement_registry",
        "capability_coverage",
        "predicates",
    }
    require_exact_keys(manifest, required_top, location="manifest", code="manifest-contract")
    service = require_exact_keys(
        manifest["service"],
        {"id", "name", "repository"},
        location="manifest.service",
        code="service-contract",
    )
    for field in ("id", "name"):
        require_stable_id(
            service[field], location=f"manifest.service.{field}", code="service-contract"
        )
    repository = require_string(
        service["repository"],
        location="manifest.service.repository",
        code="service-contract",
    )
    if not repository.startswith("https://github.com/"):
        fail("service-contract", "manifest.service.repository", "must be a GitHub HTTPS URL")
    postdeploy = require_exact_keys(
        manifest["postdeploy_entrypoint"],
        {"make_target", "executor_contracts"},
        location="manifest.postdeploy_entrypoint",
        code="entrypoint",
    )
    if postdeploy["make_target"] != "prod-verify":
        fail("entrypoint", "manifest.postdeploy_entrypoint.make_target", "must identify make prod-verify")
    if postdeploy["make_target"] not in targets:
        fail("unchecked-command", "manifest.postdeploy_entrypoint.make_target", "target is not checked in")
    expected_executors = sorted(source_predicates_by_executor())
    if postdeploy["executor_contracts"] != expected_executors:
        fail("entrypoint", "manifest.postdeploy_entrypoint.executor_contracts", "must name the exact source executors")
    ci = require_exact_keys(
        manifest["protected_ci"],
        {"workflow", "events", "context", "app_id"},
        location="manifest.protected_ci",
        code="ci-contract",
    )
    for field in ("workflow", "context"):
        require_string(ci[field], location=f"manifest.protected_ci.{field}", code="ci-contract")
    if not isinstance(ci["app_id"], int) or isinstance(ci["app_id"], bool) or ci["app_id"] <= 0:
        fail("ci-contract", "manifest.protected_ci.app_id", "must be a positive integer")
    if ci["events"] != ["pull_request", "push:main"]:
        fail("ci-contract", "manifest.protected_ci.events", "must bind pull requests and main pushes")

    capability_coverage = validate_capability_coverage(manifest["capability_coverage"])
    candidate_coverage_owner = {
        row["id"]: row["owner"]
        for row in capability_coverage
        if row["domain"] == "candidate-postdeploy"
    }

    registry = manifest["requirement_registry"]
    if not isinstance(registry, list) or not registry:
        fail("enforcement-registry", "manifest.requirement_registry", "must be nonempty")
    statuses: dict[str, str] = {}
    for index, obligation in enumerate(registry):
        location = f"manifest.requirement_registry[{index}]"
        if not isinstance(obligation, dict):
            fail("enforcement-registry", location, "must be an object")
        status = obligation.get("status")
        if not isinstance(status, str) or status not in {"implemented", "deferred"}:
            fail(
                "enforcement-registry",
                f"{location}.status",
                "must be implemented or deferred",
            )
        required_obligation = {
            "id",
            "status",
            "owner",
            "enforcement_target",
            "blocked_lifecycle_stages",
            "nonclaim_code",
        }
        if status == "implemented":
            required_obligation.add("first_enforced_increment")
        obligation = require_exact_keys(
            obligation,
            required_obligation,
            location=location,
            code="enforcement-registry",
        )
        obligation_id = require_stable_id(
            obligation["id"], location=f"{location}.id", code="enforcement-registry"
        )
        if obligation_id in statuses:
            fail("enforcement-registry", f"{location}.id", "duplicate obligation")
        status = obligation["status"]
        for field in ("owner", "enforcement_target", "nonclaim_code"):
            require_stable_id(
                obligation[field],
                location=f"{location}.{field}",
                code="enforcement-registry",
            )
        stages = obligation["blocked_lifecycle_stages"]
        if not isinstance(stages, list) or not all(isinstance(item, str) for item in stages):
            fail("enforcement-registry", f"{location}.blocked_lifecycle_stages", "must be a string list")
        if status == "deferred" and stages != ["preplan", "release-close"]:
            fail("enforcement-registry", f"{location}.blocked_lifecycle_stages", "deferred enforcement must block preplan and release-close")
        if status == "implemented" and stages != []:
            fail("enforcement-registry", f"{location}.blocked_lifecycle_stages", "implemented enforcement cannot block a lifecycle stage")
        if status == "implemented":
            first_increment = require_stable_id(
                obligation["first_enforced_increment"],
                location=f"{location}.first_enforced_increment",
                code="enforcement-history",
            )
            if ENFORCEMENT_HISTORY.get(obligation_id) != first_increment:
                fail(
                    "enforcement-history",
                    f"{location}.first_enforced_increment",
                    "does not equal source-owned enforcement history",
                )
        elif obligation_id in ENFORCEMENT_HISTORY:
            fail(
                "enforcement-history",
                f"{location}.status",
                "source-implemented obligation cannot be deferred",
            )
        statuses[obligation_id] = status
    implemented = frozenset(key for key, status in statuses.items() if status == "implemented")
    deferred = frozenset(key for key, status in statuses.items() if status == "deferred")
    if implemented != IMPLEMENTED_ENFORCEMENT_IDS:
        fail("enforcement-registry", "manifest.requirement_registry", f"implemented IDs differ from source: missing={sorted(IMPLEMENTED_ENFORCEMENT_IDS - implemented)} extra={sorted(implemented - IMPLEMENTED_ENFORCEMENT_IDS)}")
    if deferred != DEFERRED_ENFORCEMENT_IDS:
        fail("enforcement-registry", "manifest.requirement_registry", f"deferred IDs differ from source: missing={sorted(DEFERRED_ENFORCEMENT_IDS - deferred)} extra={sorted(deferred - DEFERRED_ENFORCEMENT_IDS)}")

    rows = manifest["predicates"]
    if not isinstance(rows, list) or not rows:
        fail("missing-cell", "manifest.predicates", "must be a nonempty list")
    row_by_id: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        location = f"manifest.predicates[{index}]"
        required = {"id", "owner", "current_production", "exact_source", "negative_controls", "postdeploy", "rollback", "expiry"}
        row = require_exact_keys(row, required, location=location, code="invalid-row")
        predicate_id = require_stable_id(
            row["id"], location=f"{location}.id", code="invalid-predicate-id"
        )
        owner = require_stable_id(
            row["owner"], location=f"{location}.owner", code="invalid-owner"
        )
        if (
            predicate_id in candidate_coverage_owner
            and candidate_coverage_owner[predicate_id] != owner
        ):
            fail(
                "capability-owner",
                f"{location}.owner",
                "predicate owner must equal source-owned capability coverage",
            )
        if predicate_id in row_by_id:
            fail("duplicate-predicate", f"{location}.id", predicate_id)
        row_by_id[predicate_id] = row

        current = row["current_production"]
        if (
            not isinstance(current, dict)
            or not isinstance(current.get("state"), str)
            or current.get("state") not in {"applicable", "candidate-only-absent"}
        ):
            fail("current-state", f"{location}.current_production", "invalid state")
        if current["state"] == "applicable":
            current = require_exact_keys(
                current,
                {"state", "proof"},
                location=f"{location}.current_production",
                code="current-state",
            )
            validate_proof_spec(current["proof"], location=f"{location}.current_production.proof", targets=targets)
            if predicate_id in candidate_only_predicates():
                fail("candidate-only-permissive", f"{location}.current_production.state", "candidate-only predicate must declare the incumbent absence")
        else:
            current = require_exact_keys(
                current,
                {"state", "absence"},
                location=f"{location}.current_production",
                code="current-state",
            )
            if predicate_id not in candidate_only_predicates():
                fail("candidate-only-permissive", f"{location}.current_production.state", "predicate is not source-allowlisted candidate-only semantics")
            absence = require_exact_keys(
                current["absence"],
                {"incumbent_shape", "absent_paths", "mechanical_reason_code", "shared_transport_waived"},
                location=f"{location}.current_production.absence",
                code="candidate-only-absence",
            )
            for field in ("incumbent_shape", "mechanical_reason_code"):
                require_stable_id(
                    absence[field],
                    location=f"{location}.current_production.absence.{field}",
                    code="candidate-only-absence",
                )
            if absence["shared_transport_waived"] is not False:
                fail("candidate-only-transport-waiver", f"{location}.current_production.absence.shared_transport_waived", "transport/environment cannot be waived")
            absent_paths = absence["absent_paths"]
            if (
                not isinstance(absent_paths, list)
                or not absent_paths
                or not all(
                    isinstance(item, str) and FIELD_PATH_RE.fullmatch(item)
                    for item in absent_paths
                )
                or len(absent_paths) != len(set(absent_paths))
            ):
                fail("candidate-only-absence", f"{location}.current_production.absence.absent_paths", "must be unique stable field paths")

        exact_source = row["exact_source"]
        if (
            not isinstance(exact_source, dict)
            or not isinstance(exact_source.get("state"), str)
            or exact_source.get("state") not in {"required", "not-required"}
        ):
            fail("exact-source-state", f"{location}.exact_source", "invalid state")
        if exact_source["state"] == "required":
            exact_source = require_exact_keys(
                exact_source,
                {"state", "proof"},
                location=f"{location}.exact_source",
                code="exact-source-state",
            )
            validate_proof_spec(exact_source["proof"], location=f"{location}.exact_source.proof", targets=targets)
        else:
            exact_source = require_exact_keys(
                exact_source,
                {"state", "reason_code"},
                location=f"{location}.exact_source",
                code="exact-source-state",
            )
            if current["state"] == "candidate-only-absent":
                fail("candidate-only-without-source-positive", f"{location}.exact_source.state", "candidate-only semantics require an exact-source positive")
            require_stable_id(
                exact_source["reason_code"],
                location=f"{location}.exact_source.reason_code",
                code="exact-source-reason",
            )

        negatives = row["negative_controls"]
        if not isinstance(negatives, list) or not negatives:
            fail("missing-negative", f"{location}.negative_controls", "at least one faithful negative is required")
        seen_mutations: set[str] = set()
        positive = exact_source.get("proof") if exact_source["state"] == "required" else current.get("proof")
        for mutation_index, negative in enumerate(negatives):
            negative_location = f"{location}.negative_controls[{mutation_index}]"
            if not isinstance(negative, dict) or set(negative) != {"mutation_id", "polarity", "expected_error_code", "proof"}:
                fail("negative-contract", negative_location, "must identify one mutation, polarity, exact error, and proof")
            mutation_id = require_stable_id(
                negative["mutation_id"],
                location=f"{negative_location}.mutation_id",
                code="negative-contract",
            )
            if mutation_id in seen_mutations:
                fail("negative-contract", f"{negative_location}.mutation_id", "must be unique")
            seen_mutations.add(mutation_id)
            if not isinstance(negative["polarity"], str) or negative["polarity"] not in {"single-variable", "forbidden-permissive-path"}:
                fail("negative-contract", f"{negative_location}.polarity", "invalid polarity")
            require_stable_id(
                negative["expected_error_code"],
                location=f"{negative_location}.expected_error_code",
                code="negative-contract",
            )
            negative_proof = validate_proof_spec(negative["proof"], location=f"{negative_location}.proof", targets=targets)
            if positive is not None and negative_proof["path_fingerprint"] != positive["path_fingerprint"]:
                fail("unit-only-substitution", f"{negative_location}.proof.path_fingerprint", "negative must drive the positive path")

        validate_proof_spec(row["postdeploy"], location=f"{location}.postdeploy", targets=targets)
        rollback = row["rollback"]
        if (
            not isinstance(rollback, dict)
            or not isinstance(rollback.get("state"), str)
            or rollback.get("state") not in {"required", "mechanically-not-applicable"}
        ):
            fail("rollback-state", f"{location}.rollback", "invalid state")
        if rollback["state"] == "required":
            rollback = require_exact_keys(
                rollback,
                {"state", "proof", "artifact_identity"},
                location=f"{location}.rollback",
                code="rollback-state",
            )
            validate_proof_spec(rollback["proof"], location=f"{location}.rollback.proof", targets=targets)
            identity = require_exact_keys(
                rollback["artifact_identity"],
                {"deploy_id_argument", "commit_argument", "shape_code"},
                location=f"{location}.rollback.artifact_identity",
                code="rollback-identity",
            )
            for field in ("deploy_id_argument", "commit_argument"):
                value = identity[field]
                if not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]+", value):
                    fail("rollback-identity", f"{location}.rollback.artifact_identity.{field}", "must be an environment argument ID")
            require_stable_id(
                identity["shape_code"],
                location=f"{location}.rollback.artifact_identity.shape_code",
                code="rollback-identity",
            )
        else:
            rollback = require_exact_keys(
                rollback,
                {"state", "reason_code"},
                location=f"{location}.rollback",
                code="rollback-state",
            )
            require_stable_id(
                rollback["reason_code"],
                location=f"{location}.rollback.reason_code",
                code="rollback-reason",
            )
        expiry = require_exact_keys(
            row["expiry"],
            {"kind", "condition_code"},
            location=f"{location}.expiry",
            code="expiry",
        )
        if not isinstance(expiry["kind"], str) or expiry["kind"] not in {"never", "incumbent-change", "rollback-artifact-change"}:
            fail("expiry", f"{location}.expiry.kind", "invalid expiry kind")
        require_stable_id(
            expiry["condition_code"],
            location=f"{location}.expiry.condition_code",
            code="expiry",
        )

    source = source_predicates()
    present = frozenset(row_by_id)
    missing = sorted(source - present)
    extra = sorted(present - source)
    if missing:
        fail("missing-predicate", "manifest.predicates", f"source predicates without rows: {missing}")
    if extra:
        fail("unknown-predicate", "manifest.predicates", f"rows without source predicates: {extra}")
    return manifest


def parse_time(value: Any, *, location: str) -> datetime:
    if not isinstance(value, str):
        fail("invalid-time", location, "must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        fail("invalid-time", location, str(exc))
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.min.replace(tzinfo=UTC).utcoffset():
        fail("invalid-time", location, "must carry UTC offset")
    return parsed


def validate_receipt(
    receipt: Any,
    *,
    location: str,
    row: dict[str, Any],
    manifest_sha: str,
    index: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        fail("invalid-receipt", location, "must be an object")
    missing = sorted(RECEIPT_FIELDS - set(receipt))
    if missing:
        fail("missing-receipt-field", location, f"missing fields {missing}")
    proof_kind = receipt["proof_kind"]
    if proof_kind == "capability-fixture":
        fail(
            "capability-not-lifecycle-evidence",
            f"{location}.proof_kind",
            "isolated capability transcripts cannot satisfy lifecycle evidence",
        )
    expected_keys = RECEIPT_FIELDS | (
        {"mutation_id", "expected_error_code"} if proof_kind == "negative" else set()
    )
    receipt = require_exact_keys(
        receipt, expected_keys, location=location, code="invalid-receipt"
    )
    if receipt["predicate_id"] != row["id"]:
        fail("receipt-predicate", f"{location}.predicate_id", "does not match indexed row")
    if receipt["manifest_sha256"] != manifest_sha:
        fail("wrong-manifest", f"{location}.manifest_sha256", "receipt is not bound to this manifest")
    for field in ("candidate_sha", "source_sha"):
        if receipt[field] != index["candidate_sha"] or not COMMIT_RE.fullmatch(str(receipt[field])):
            fail("wrong-sha", f"{location}.{field}", "must equal the indexed candidate SHA")
    for field in ("script_sha256", "config_sha256"):
        if not isinstance(receipt[field], str) or not SHA_RE.fullmatch(receipt[field]):
            fail("invalid-digest", f"{location}.{field}", "must be lowercase sha256")
    if not isinstance(proof_kind, str) or proof_kind not in {
        "current-production",
        "exact-source",
        "negative",
        "postdeploy",
        "rollback",
    }:
        fail("proof-kind", f"{location}.proof_kind", "invalid proof kind")
    if proof_kind == "current-production":
        spec = row["current_production"].get("proof")
    elif proof_kind == "exact-source":
        spec = row["exact_source"].get("proof")
    elif proof_kind == "postdeploy":
        spec = row["postdeploy"]
    elif proof_kind == "rollback":
        spec = row["rollback"].get("proof")
    else:
        mutation_id = require_stable_id(
            receipt.get("mutation_id"),
            location=f"{location}.mutation_id",
            code="negative-mutation",
        )
        require_stable_id(
            receipt.get("expected_error_code"),
            location=f"{location}.expected_error_code",
            code="unrelated-failure",
        )
        matches = [item for item in row["negative_controls"] if item["mutation_id"] == mutation_id]
        if len(matches) != 1:
            fail("negative-mutation", f"{location}.mutation_id", "unknown or missing mutation")
        spec = matches[0]["proof"]
        if receipt.get("expected_error_code") != matches[0]["expected_error_code"]:
            fail("unrelated-failure", f"{location}.expected_error_code", "does not match the dedicated negative")
    if not isinstance(spec, dict):
        fail("proof-not-required", location, f"{proof_kind} is not required for this predicate")
    for field in ("make_target", "layer", "surface", "path_fingerprint", "safety_class"):
        if receipt[field] != spec[field]:
            fail("proof-fidelity", f"{location}.{field}", "does not match the static path contract")
    substitutions = receipt["substitutions"]
    if (
        not isinstance(substitutions, list)
        or not all(isinstance(item, str) and ID_RE.fullmatch(item) for item in substitutions)
        or len(substitutions) != len(set(substitutions))
        or not set(substitutions) <= set(spec["allowed_substitutions"])
    ):
        fail("unapproved-substitution", f"{location}.substitutions", "contains a duplicate, malformed, or unapproved boundary substitution")
    if not isinstance(receipt["normalized_arguments"], dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in receipt["normalized_arguments"].items()
    ):
        fail("arguments", f"{location}.normalized_arguments", "must be a normalized string map")
    if not isinstance(receipt["parent_run_id"], str) or receipt["parent_run_id"] != index["run_id"]:
        fail("mixed-run", f"{location}.parent_run_id", "receipt belongs to another top-level run")
    require_string(receipt["run_id"], location=f"{location}.run_id", code="run-id")
    started = parse_time(receipt["started_at"], location=f"{location}.started_at")
    finished = parse_time(receipt["finished_at"], location=f"{location}.finished_at")
    fresh_until = parse_time(receipt["fresh_until"], location=f"{location}.fresh_until")
    if not started <= finished <= fresh_until:
        fail("invalid-expiry", location, "requires started <= finished <= fresh_until")
    if proof_kind in {"current-production", "exact-source", "negative"} and now > fresh_until:
        fail("stale-receipt", f"{location}.fresh_until", "pre-mutation proof has expired")
    terminal = require_exact_keys(
        receipt["terminal"],
        {"outcome", "assertion_code", "count"},
        location=f"{location}.terminal",
        code="nonterminal",
    )
    if not isinstance(terminal["count"], int) or isinstance(terminal["count"], bool) or terminal["count"] != 1:
        fail("multiple-terminal", f"{location}.terminal.count", "must equal one")
    expected_outcome = "expected-failure" if proof_kind == "negative" else "passed"
    if terminal["outcome"] != expected_outcome:
        fail("terminal-outcome", f"{location}.terminal.outcome", f"expected {expected_outcome}")
    expected_assertion = (
        receipt.get("expected_error_code") if proof_kind == "negative" else spec["assertion_code"]
    )
    if terminal["assertion_code"] != expected_assertion:
        fail("unrelated-failure", f"{location}.terminal.assertion_code", "does not prove the required assertion")
    artifact = require_exact_keys(
        receipt["artifact"],
        {"sha256", "location", "complete", "private_no_replace"},
        location=f"{location}.artifact",
        code="artifact",
    )
    if not isinstance(artifact["sha256"], str) or not SHA_RE.fullmatch(artifact["sha256"]):
        fail("artifact", f"{location}.artifact.sha256", "must be lowercase sha256")
    require_string(
        artifact["location"], location=f"{location}.artifact.location", code="artifact"
    )
    if artifact["complete"] is not True or artifact["private_no_replace"] is not True:
        fail("incomplete-artifact", f"{location}.artifact", "must be complete and privately no-replace published")
    return receipt


def validate_index(
    manifest: dict[str, Any], index: dict[str, Any], *, mode: str, now: datetime
) -> dict[str, Any]:
    validate_manifest(manifest)
    if not isinstance(index, dict):
        fail("index-contract", "index", "must be an object")
    reject_sentinels(index, location="index")
    expected_schema = "library.aatk-evidence-index.v1"
    if index.get("schema") != expected_schema:
        fail("schema", "index.schema", f"expected {expected_schema}")
    index = require_exact_keys(
        index,
        {
            "schema",
            "run_id",
            "candidate_sha",
            "manifest_sha256",
            "incumbent",
            "rollback",
            "ci",
            "receipts",
        },
        location="index",
        code="index-contract",
    )
    require_string(index["run_id"], location="index.run_id", code="index-contract")
    digest = manifest_digest(manifest)
    if index["manifest_sha256"] != digest:
        fail("wrong-manifest", "index.manifest_sha256", "does not match canonical manifest digest")
    if not isinstance(index["candidate_sha"], str) or not COMMIT_RE.fullmatch(index["candidate_sha"]):
        fail("wrong-sha", "index.candidate_sha", "must be a full commit")
    for identity_name in ("incumbent", "rollback"):
        identity = require_exact_keys(
            index[identity_name],
            {"service_id", "deploy_id", "commit", "shape_code"},
            location=f"index.{identity_name}",
            code="artifact-identity",
        )
        for field in ("service_id", "deploy_id", "shape_code"):
            require_stable_id(
                identity[field],
                location=f"index.{identity_name}.{field}",
                code="artifact-identity",
            )
        if not isinstance(identity["commit"], str) or not COMMIT_RE.fullmatch(identity["commit"]):
            fail("artifact-identity", f"index.{identity_name}.commit", "must be a full commit")
    ci = require_exact_keys(
        index["ci"],
        {"workflow", "context", "app_id", "event", "head_sha", "conclusion"},
        location="index.ci",
        code="wrong-ci-gate",
    )
    spec_ci = manifest["protected_ci"]
    if not isinstance(ci, dict) or any(
        ci.get(key) != spec_ci[key] for key in ("workflow", "context", "app_id")
    ) or ci.get("event") not in spec_ci["events"]:
        fail("wrong-ci-gate", "index.ci", "must bind the exact protected workflow/context/app/event")
    if ci.get("head_sha") != index["candidate_sha"] or ci.get("conclusion") != "success":
        fail("wrong-ci-gate", "index.ci", "must be a successful run on the candidate SHA")

    rows = {row["id"]: row for row in manifest["predicates"]}
    receipts = index["receipts"]
    if not isinstance(receipts, list):
        fail("invalid-receipts", "index.receipts", "must be a list")
    seen: set[tuple[str, str, str]] = set()
    by_predicate: dict[str, list[dict[str, Any]]] = {key: [] for key in rows}
    for receipt_index, receipt in enumerate(receipts):
        location = f"index.receipts[{receipt_index}]"
        predicate_id = receipt.get("predicate_id") if isinstance(receipt, dict) else None
        if not isinstance(predicate_id, str) or predicate_id not in rows:
            fail("unknown-predicate", f"{location}.predicate_id", "receipt has no manifest row")
        validated = validate_receipt(
            receipt,
            location=location,
            row=rows[predicate_id],
            manifest_sha=digest,
            index=index,
            now=now,
        )
        key = (
            validated["predicate_id"],
            validated["proof_kind"],
            str(validated.get("mutation_id") or ""),
        )
        if key in seen:
            fail("duplicate-receipt", location, str(key))
        seen.add(key)
        by_predicate[validated["predicate_id"]].append(validated)

    for predicate_id, row in rows.items():
        kinds = [receipt["proof_kind"] for receipt in by_predicate[predicate_id]]
        expected_pre = (
            "current-production"
            if row["current_production"]["state"] == "applicable"
            else "exact-source"
        )
        if expected_pre not in kinds:
            fail("missing-receipt", f"predicate.{predicate_id}.{expected_pre}", "pre-mutation positive is required")
        expected_mutations = {item["mutation_id"] for item in row["negative_controls"]}
        seen_mutations = {
            str(receipt.get("mutation_id"))
            for receipt in by_predicate[predicate_id]
            if receipt["proof_kind"] == "negative"
        }
        if expected_mutations != seen_mutations:
            fail("missing-receipt", f"predicate.{predicate_id}.negative", f"expected mutations {sorted(expected_mutations)}")
        if mode == "release":
            if "postdeploy" not in kinds:
                fail("missing-receipt", f"predicate.{predicate_id}.postdeploy", "release close requires a terminal postdeploy receipt")
            if row["rollback"]["state"] == "required" and "rollback" not in kinds:
                fail("missing-receipt", f"predicate.{predicate_id}.rollback", "release close requires the declared rollback proof")
    if DEFERRED_ENFORCEMENT_IDS:
        fail(
            "unenforced-obligation",
            f"lifecycle.{mode}",
            f"blocked by deferred enforcement IDs {sorted(DEFERRED_ENFORCEMENT_IDS)}",
        )
    return index


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    sub = command.add_subparsers(dest="command", required=True)
    inventory = sub.add_parser("inventory")
    inventory.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    spec = sub.add_parser("spec")
    spec.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    for name in ("preplan", "release"):
        validator = sub.add_parser(name)
        validator.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
        validator.add_argument("--index", type=Path, required=True)
        validator.add_argument("--now", default="")
    return command


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "inventory":
            inventory = source_predicates_by_executor()
            print(json.dumps({"executors": inventory, "predicate_count": sum(map(len, inventory.values()))}, sort_keys=True))
            return 0
        manifest = load_object(args.manifest, label="manifest")
        if args.command == "spec":
            validate_manifest(manifest)
            print(json.dumps({"manifest_sha256": manifest_digest(manifest), "predicate_count": len(source_predicates()), "state": "spec-valid"}, sort_keys=True))
        else:
            index = load_object(args.index, label="evidence index")
            now = parse_time(args.now, location="--now") if args.now else datetime.now(UTC)
            validate_index(manifest, index, mode=args.command, now=now)
            state = "premutation-proven" if args.command == "preplan" else "closed"
            print(json.dumps({"candidate_sha": index["candidate_sha"], "manifest_sha256": manifest_digest(manifest), "state": state}, sort_keys=True))
        return 0
    except AATKError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

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
IMPLEMENTED_ENFORCEMENT_IDS = frozenset(
    {
        "architecture.static-dynamic-separation",
        "predicates.exact-universe",
        "schema.typed-contracts",
        "controls.structural-positive-negative-pair",
        "candidate-only.structural-allowlist",
        "validator.falsification",
    }
)
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


def validate_proof_spec(value: Any, *, location: str, targets: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("invalid-proof", location, "must be an object")
    missing = sorted(PROOF_FIELDS - set(value))
    if missing:
        fail("missing-cell", location, f"missing fields {missing}")
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
    if not isinstance(substitutions, list) or not all(
        isinstance(item, str) and ID_RE.fullmatch(item) for item in substitutions
    ):
        fail("invalid-substitutions", f"{location}.allowed_substitutions", "must be stable IDs")
    if value["safety_class"] not in {"read-only", "isolated", "postdeploy-read-only", "rollback-mutation"}:
        fail("invalid-safety-class", f"{location}.safety_class", "unrecognized safety class")
    for field in ("layer", "surface", "assertion_code"):
        if not isinstance(value[field], str) or not ID_RE.fullmatch(value[field]):
            fail("invalid-proof-field", f"{location}.{field}", "must be a stable ID")
    return value


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
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
        "predicates",
    }
    missing_top = sorted(required_top - set(manifest))
    if missing_top:
        fail("missing-cell", "manifest", f"missing fields {missing_top}")
    postdeploy = manifest["postdeploy_entrypoint"]
    if not isinstance(postdeploy, dict) or postdeploy.get("make_target") != "prod-verify":
        fail("entrypoint", "manifest.postdeploy_entrypoint", "must identify make prod-verify")
    if postdeploy.get("make_target") not in targets:
        fail("unchecked-command", "manifest.postdeploy_entrypoint.make_target", "target is not checked in")
    ci = manifest["protected_ci"]
    if not isinstance(ci, dict) or set(ci) != {"workflow", "events", "context", "app_id"}:
        fail("ci-contract", "manifest.protected_ci", "must bind workflow, events, context, and app_id")
    if not isinstance(ci.get("app_id"), int) or ci["app_id"] <= 0:
        fail("ci-contract", "manifest.protected_ci.app_id", "must be a positive integer")
    if ci.get("events") != ["pull_request", "push:main"]:
        fail("ci-contract", "manifest.protected_ci.events", "must bind pull requests and main pushes")

    registry = manifest["requirement_registry"]
    if not isinstance(registry, list) or not registry:
        fail("enforcement-registry", "manifest.requirement_registry", "must be nonempty")
    statuses: dict[str, str] = {}
    for index, obligation in enumerate(registry):
        location = f"manifest.requirement_registry[{index}]"
        required_obligation = {
            "id",
            "status",
            "owner",
            "enforcement_target",
            "blocked_lifecycle_stages",
            "nonclaim_code",
        }
        if not isinstance(obligation, dict) or set(obligation) != required_obligation:
            fail("enforcement-registry", location, "must use the exact typed obligation fields")
        obligation_id = obligation["id"]
        if not isinstance(obligation_id, str) or not ID_RE.fullmatch(obligation_id):
            fail("enforcement-registry", f"{location}.id", "must be a stable ID")
        if obligation_id in statuses:
            fail("enforcement-registry", f"{location}.id", "duplicate obligation")
        status = obligation["status"]
        if status not in {"implemented", "deferred"}:
            fail("enforcement-registry", f"{location}.status", "must be implemented or deferred")
        stages = obligation["blocked_lifecycle_stages"]
        if status == "deferred" and stages != ["preplan", "release-close"]:
            fail("enforcement-registry", f"{location}.blocked_lifecycle_stages", "deferred enforcement must block preplan and release-close")
        if status == "implemented" and stages != []:
            fail("enforcement-registry", f"{location}.blocked_lifecycle_stages", "implemented enforcement cannot block a lifecycle stage")
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
        if not isinstance(row, dict):
            fail("invalid-row", location, "must be an object")
        required = {"id", "owner", "current_production", "exact_source", "negative_controls", "postdeploy", "rollback", "expiry"}
        missing = sorted(required - set(row))
        if missing:
            fail("missing-cell", location, f"missing fields {missing}")
        predicate_id = row["id"]
        if not isinstance(predicate_id, str) or not ID_RE.fullmatch(predicate_id):
            fail("invalid-predicate-id", f"{location}.id", "must be a stable ID")
        if predicate_id in row_by_id:
            fail("duplicate-predicate", f"{location}.id", predicate_id)
        row_by_id[predicate_id] = row

        current = row["current_production"]
        if not isinstance(current, dict) or current.get("state") not in {"applicable", "candidate-only-absent"}:
            fail("current-state", f"{location}.current_production", "invalid state")
        if current["state"] == "applicable":
            validate_proof_spec(current.get("proof"), location=f"{location}.current_production.proof", targets=targets)
            if predicate_id in candidate_only_predicates():
                fail("candidate-only-permissive", f"{location}.current_production.state", "candidate-only predicate must declare the incumbent absence")
        else:
            if predicate_id not in candidate_only_predicates():
                fail("candidate-only-permissive", f"{location}.current_production.state", "predicate is not source-allowlisted candidate-only semantics")
            absence = current.get("absence")
            required_absence = {"incumbent_shape", "absent_paths", "mechanical_reason_code", "shared_transport_waived"}
            if not isinstance(absence, dict) or set(absence) != required_absence:
                fail("candidate-only-absence", f"{location}.current_production.absence", "must identify exact incumbent shape and absent fields")
            if absence["shared_transport_waived"] is not False:
                fail("candidate-only-transport-waiver", f"{location}.current_production.absence.shared_transport_waived", "transport/environment cannot be waived")
            if not isinstance(absence["absent_paths"], list) or not absence["absent_paths"]:
                fail("candidate-only-absence", f"{location}.current_production.absence.absent_paths", "must be nonempty")

        exact_source = row["exact_source"]
        if not isinstance(exact_source, dict) or exact_source.get("state") not in {"required", "not-required"}:
            fail("exact-source-state", f"{location}.exact_source", "invalid state")
        if exact_source["state"] == "required":
            validate_proof_spec(exact_source.get("proof"), location=f"{location}.exact_source.proof", targets=targets)
        elif current["state"] == "candidate-only-absent":
            fail("candidate-only-without-source-positive", f"{location}.exact_source.state", "candidate-only semantics require an exact-source positive")
        elif not isinstance(exact_source.get("reason_code"), str):
            fail("exact-source-reason", f"{location}.exact_source.reason_code", "required for not-required")

        negatives = row["negative_controls"]
        if not isinstance(negatives, list) or not negatives:
            fail("missing-negative", f"{location}.negative_controls", "at least one faithful negative is required")
        seen_mutations: set[str] = set()
        positive = exact_source.get("proof") if exact_source["state"] == "required" else current.get("proof")
        for mutation_index, negative in enumerate(negatives):
            negative_location = f"{location}.negative_controls[{mutation_index}]"
            if not isinstance(negative, dict) or set(negative) != {"mutation_id", "polarity", "expected_error_code", "proof"}:
                fail("negative-contract", negative_location, "must identify one mutation, polarity, exact error, and proof")
            mutation_id = negative["mutation_id"]
            if not isinstance(mutation_id, str) or not ID_RE.fullmatch(mutation_id) or mutation_id in seen_mutations:
                fail("negative-contract", f"{negative_location}.mutation_id", "must be a unique stable ID")
            seen_mutations.add(mutation_id)
            if negative["polarity"] not in {"single-variable", "forbidden-permissive-path"}:
                fail("negative-contract", f"{negative_location}.polarity", "invalid polarity")
            negative_proof = validate_proof_spec(negative["proof"], location=f"{negative_location}.proof", targets=targets)
            if positive is not None and negative_proof["path_fingerprint"] != positive["path_fingerprint"]:
                fail("unit-only-substitution", f"{negative_location}.proof.path_fingerprint", "negative must drive the positive path")

        validate_proof_spec(row["postdeploy"], location=f"{location}.postdeploy", targets=targets)
        rollback = row["rollback"]
        if not isinstance(rollback, dict) or rollback.get("state") not in {"required", "mechanically-not-applicable"}:
            fail("rollback-state", f"{location}.rollback", "invalid state")
        if rollback["state"] == "required":
            validate_proof_spec(rollback.get("proof"), location=f"{location}.rollback.proof", targets=targets)
            identity = rollback.get("artifact_identity")
            if not isinstance(identity, dict) or set(identity) != {"deploy_id_argument", "commit_argument", "shape_code"}:
                fail("rollback-identity", f"{location}.rollback.artifact_identity", "must separately pin deploy, commit, and shape")
        elif not isinstance(rollback.get("reason_code"), str):
            fail("rollback-reason", f"{location}.rollback.reason_code", "required for mechanically-not-applicable")
        expiry = row["expiry"]
        if not isinstance(expiry, dict) or set(expiry) != {"kind", "condition_code"}:
            fail("expiry", f"{location}.expiry", "must be machine-evaluable")
        if expiry["kind"] not in {"never", "incumbent-change", "rollback-artifact-change"}:
            fail("expiry", f"{location}.expiry.kind", "invalid expiry kind")

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
    proof_kind = receipt["proof_kind"]
    if proof_kind not in {"current-production", "exact-source", "negative", "postdeploy", "rollback"}:
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
        mutation_id = receipt.get("mutation_id")
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
    if not isinstance(substitutions, list) or not set(substitutions) <= set(spec["allowed_substitutions"]):
        fail("unapproved-substitution", f"{location}.substitutions", "contains a boundary substitution not allowed by the manifest")
    if not isinstance(receipt["normalized_arguments"], dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in receipt["normalized_arguments"].items()
    ):
        fail("arguments", f"{location}.normalized_arguments", "must be a normalized string map")
    if receipt["parent_run_id"] != index["run_id"]:
        fail("mixed-run", f"{location}.parent_run_id", "receipt belongs to another top-level run")
    if not isinstance(receipt["run_id"], str) or not receipt["run_id"].strip():
        fail("run-id", f"{location}.run_id", "must be nonblank")
    started = parse_time(receipt["started_at"], location=f"{location}.started_at")
    finished = parse_time(receipt["finished_at"], location=f"{location}.finished_at")
    fresh_until = parse_time(receipt["fresh_until"], location=f"{location}.fresh_until")
    if not started <= finished <= fresh_until:
        fail("invalid-expiry", location, "requires started <= finished <= fresh_until")
    if proof_kind in {"current-production", "exact-source", "negative"} and now > fresh_until:
        fail("stale-receipt", f"{location}.fresh_until", "pre-mutation proof has expired")
    terminal = receipt["terminal"]
    if not isinstance(terminal, dict) or set(terminal) != {"outcome", "assertion_code", "count"}:
        fail("nonterminal", f"{location}.terminal", "must contain one exact terminal outcome")
    if terminal["count"] != 1:
        fail("multiple-terminal", f"{location}.terminal.count", "must equal one")
    expected_outcome = "expected-failure" if proof_kind == "negative" else "passed"
    if terminal["outcome"] != expected_outcome:
        fail("terminal-outcome", f"{location}.terminal.outcome", f"expected {expected_outcome}")
    expected_assertion = (
        receipt.get("expected_error_code") if proof_kind == "negative" else spec["assertion_code"]
    )
    if terminal["assertion_code"] != expected_assertion:
        fail("unrelated-failure", f"{location}.terminal.assertion_code", "does not prove the required assertion")
    artifact = receipt["artifact"]
    if not isinstance(artifact, dict) or set(artifact) != {"sha256", "location", "complete", "private_no_replace"}:
        fail("artifact", f"{location}.artifact", "must identify complete immutable evidence")
    if not isinstance(artifact["sha256"], str) or not SHA_RE.fullmatch(artifact["sha256"]):
        fail("artifact", f"{location}.artifact.sha256", "must be lowercase sha256")
    if artifact["complete"] is not True or artifact["private_no_replace"] is not True:
        fail("incomplete-artifact", f"{location}.artifact", "must be complete and privately no-replace published")
    return receipt


def validate_index(
    manifest: dict[str, Any], index: dict[str, Any], *, mode: str, now: datetime
) -> dict[str, Any]:
    validate_manifest(manifest)
    reject_sentinels(index, location="index")
    expected_schema = "library.aatk-evidence-index.v1"
    if index.get("schema") != expected_schema:
        fail("schema", "index.schema", f"expected {expected_schema}")
    for field in ("run_id", "candidate_sha", "manifest_sha256", "incumbent", "rollback", "ci", "receipts"):
        if field not in index:
            fail("missing-cell", "index", f"missing {field}")
    digest = manifest_digest(manifest)
    if index["manifest_sha256"] != digest:
        fail("wrong-manifest", "index.manifest_sha256", "does not match canonical manifest digest")
    if not isinstance(index["candidate_sha"], str) or not COMMIT_RE.fullmatch(index["candidate_sha"]):
        fail("wrong-sha", "index.candidate_sha", "must be a full commit")
    for identity_name in ("incumbent", "rollback"):
        identity = index[identity_name]
        if not isinstance(identity, dict) or set(identity) != {"service_id", "deploy_id", "commit", "shape_code"}:
            fail("artifact-identity", f"index.{identity_name}", "must separately identify service/deploy/commit/shape")
        if not COMMIT_RE.fullmatch(str(identity["commit"])):
            fail("artifact-identity", f"index.{identity_name}.commit", "must be a full commit")
    ci = index["ci"]
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
        if not isinstance(receipt, dict) or receipt.get("predicate_id") not in rows:
            fail("unknown-predicate", f"{location}.predicate_id", "receipt has no manifest row")
        validated = validate_receipt(
            receipt,
            location=location,
            row=rows[receipt["predicate_id"]],
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

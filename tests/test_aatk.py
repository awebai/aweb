from __future__ import annotations

import copy
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import aatk

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "ops" / "aatk-manifest.json"
CANDIDATE = "a" * 40
OTHER_COMMIT = "b" * 40
DIGEST = "c" * 64
START = "2026-07-29T07:00:00Z"
FINISH = "2026-07-29T07:00:01Z"
FRESH = "2026-07-29T08:00:00Z"
NOW = datetime(2026, 7, 29, 7, 30, tzinfo=UTC)


def manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def row_by_id(value: dict, predicate_id: str) -> dict:
    return next(row for row in value["predicates"] if row["id"] == predicate_id)


def coverage_row(value: dict, domain: str, predicate_id: str) -> dict:
    return next(
        row
        for row in value["capability_coverage"]
        if row["domain"] == domain and row["id"] == predicate_id
    )


def proof_for(row: dict, kind: str, mutation_id: str = "") -> tuple[dict, str]:
    if kind == "current-production":
        return row["current_production"]["proof"], ""
    if kind == "exact-source":
        return row["exact_source"]["proof"], ""
    if kind == "postdeploy":
        return row["postdeploy"], ""
    if kind == "rollback":
        return row["rollback"]["proof"], ""
    negative = next(
        item for item in row["negative_controls"] if item["mutation_id"] == mutation_id
    )
    return negative["proof"], negative["expected_error_code"]


def receipt(
    value: dict,
    row: dict,
    kind: str,
    *,
    parent_run_id: str = "aatk-run-1",
    mutation_id: str = "",
) -> dict:
    proof, negative_error = proof_for(row, kind, mutation_id)
    assertion = negative_error if kind == "negative" else proof["assertion_code"]
    result = {
        "predicate_id": row["id"],
        "proof_kind": kind,
        "manifest_sha256": aatk.manifest_digest(value),
        "candidate_sha": CANDIDATE,
        "source_sha": CANDIDATE,
        "script_sha256": DIGEST,
        "config_sha256": DIGEST,
        "make_target": proof["make_target"],
        "normalized_arguments": {},
        "layer": proof["layer"],
        "surface": proof["surface"],
        "path_fingerprint": proof["path_fingerprint"],
        "substitutions": [],
        "safety_class": proof["safety_class"],
        "parent_run_id": parent_run_id,
        "run_id": f"{row['id']}-{kind}-{mutation_id or 'positive'}",
        "started_at": START,
        "finished_at": FINISH,
        "fresh_until": FRESH,
        "terminal": {
            "outcome": "expected-failure" if kind == "negative" else "passed",
            "assertion_code": assertion,
            "count": 1,
        },
        "artifact": {
            "sha256": DIGEST,
            "location": f"private://{row['id']}/{kind}",
            "complete": True,
            "private_no_replace": True,
        },
    }
    if kind == "negative":
        result["mutation_id"] = mutation_id
        result["expected_error_code"] = negative_error
    return result


def evidence_index(value: dict, *, release: bool = False) -> dict:
    receipts = []
    for row in value["predicates"]:
        positive = (
            "current-production"
            if row["current_production"]["state"] == "applicable"
            else "exact-source"
        )
        receipts.append(receipt(value, row, positive))
        for negative in row["negative_controls"]:
            receipts.append(
                receipt(value, row, "negative", mutation_id=negative["mutation_id"])
            )
        if release:
            receipts.append(receipt(value, row, "postdeploy"))
            if row["rollback"]["state"] == "required":
                receipts.append(receipt(value, row, "rollback"))
    return {
        "schema": "library.aatk-evidence-index.v1",
        "run_id": "aatk-run-1",
        "candidate_sha": CANDIDATE,
        "manifest_sha256": aatk.manifest_digest(value),
        "incumbent": {
            "service_id": "srv-library",
            "deploy_id": "dep-incumbent",
            "commit": OTHER_COMMIT,
            "shape_code": "legacy-incumbent",
        },
        "rollback": {
            "service_id": "srv-library",
            "deploy_id": "dep-rollback",
            "commit": OTHER_COMMIT,
            "shape_code": "approved-rollback",
        },
        "ci": {
            "workflow": value["protected_ci"]["workflow"],
            "context": value["protected_ci"]["context"],
            "app_id": value["protected_ci"]["app_id"],
            "event": "push:main",
            "head_sha": CANDIDATE,
            "conclusion": "success",
        },
        "receipts": receipts,
    }


def assert_error(code: str, location: str, function, *args, **kwargs) -> aatk.AATKError:
    with pytest.raises(aatk.AATKError) as raised:
        function(*args, **kwargs)
    assert raised.value.code == code
    assert raised.value.location == location
    return raised.value


def test_canonical_partial_manifest_is_spec_valid_and_matches_executor_universe() -> None:
    value = manifest()
    assert aatk.validate_manifest(value) is value
    inventory = aatk.source_predicates_by_executor()
    assert set(inventory) == {
        "scripts.library_prod_gate.POSTDEPLOY_PREDICATES",
        "scripts.render_ops.POSTDEPLOY_PREDICATES",
    }
    assert {row["id"] for row in value["predicates"]} == aatk.source_predicates()
    assert sum(map(len, inventory.values())) == 50
    assert value["capability_coverage"] == aatk.source_capability_coverage()
    assert len(value["capability_coverage"]) == 72
    candidate_rows = [
        row for row in value["capability_coverage"] if row["domain"] == "candidate-postdeploy"
    ]
    current_rows = [
        row for row in value["capability_coverage"] if row["domain"] == "current-incumbent"
    ]
    assert len(candidate_rows) == 50
    assert {row["id"] for row in current_rows} == set(
        aatk.library_prod_gate.current_incumbent_predicate_inventory()
    )
    assert len(current_rows) == 22
    instrumented = {
        row["id"]
        for row in value["capability_coverage"]
        if set(row["obligations"].values()) == {"instrumented-capability"}
    }
    assert instrumented == {
        "health.origin.http-200",
        "health.origin.payload-contract",
        "health.public.http-200",
        "health.public.payload-contract",
    }
    assert aatk.DEFERRED_ENFORCEMENT_IDS >= aatk.CAPABILITY_OBLIGATION_IDS


def test_capability_coverage_rejects_deleted_source_row() -> None:
    value = manifest()
    del value["capability_coverage"][0]
    assert_error(
        "capability-universe",
        "manifest.capability_coverage",
        aatk.validate_manifest,
        value,
    )


def test_capability_coverage_rejects_duplicate_domain_id() -> None:
    value = manifest()
    value["capability_coverage"].append(copy.deepcopy(value["capability_coverage"][0]))
    index = len(value["capability_coverage"]) - 1
    assert_error(
        "duplicate-capability-predicate",
        f"manifest.capability_coverage[{index}].id",
        aatk.validate_manifest,
        value,
    )


def test_capability_coverage_rejects_unknown_or_renamed_id() -> None:
    value = manifest()
    value["capability_coverage"][0]["id"] = "orphaned.renamed.predicate"
    assert_error(
        "capability-universe",
        "manifest.capability_coverage",
        aatk.validate_manifest,
        value,
    )


def test_current_incumbent_registration_has_four_identities_and_18_deferred() -> None:
    value = manifest()
    current_rows = [
        row for row in value["capability_coverage"] if row["domain"] == "current-incumbent"
    ]
    identical = {
        row["id"]: row["candidate_mapping"]["candidate_predicate_id"]
        for row in current_rows
        if row["candidate_mapping"]["state"] == "identical"
    }
    assert identical == {
        "materialize.profile-pin.claude-code": "materialize.profile-pin.claude-code",
        "materialize.profile-pin.pi": "materialize.profile-pin.pi",
        "materialize.public.claude-code.http-200": "materialize.public.claude-code.http-200",
        "materialize.public.pi.http-200": "materialize.public.pi.http-200",
    }
    release_owned = {
        row["id"] for row in current_rows if row["owner"] == "release-infrastructure"
    }
    assert release_owned == {
        predicate_id
        for predicate_id in aatk.library_prod_gate.current_incumbent_predicate_inventory()
        if predicate_id.startswith("origin-route.")
        or predicate_id.startswith("materialize.public-continuation.")
    }
    assert {row["owner"] for row in current_rows} == {
        "library-service",
        "release-infrastructure",
    }
    deferred = [
        row for row in current_rows if row["candidate_mapping"]["state"] == "deferred"
    ]
    assert len(deferred) == 18
    base = {
        "runtime.path-fidelity",
        "execution.capability-obligation",
        "safety.boundary-invocation",
        "controls.executed-same-path",
        "orchestrator.falsification",
    }
    response_contracts = {
        "materialize.origin.response-contract.claude-code",
        "materialize.origin.response-contract.pi",
        "materialize.response-contract.claude-code",
        "materialize.response-contract.pi",
    }
    for row in deferred:
        expected = base | ({"candidate-only.runtime-proof"} if row["id"] in response_contracts else set())
        assert set(row["candidate_mapping"]["blocked_obligation_ids"]) == expected


def test_current_incumbent_semantic_descriptors_cover_both_domains() -> None:
    descriptors = aatk.source_semantic_descriptors()
    keys = {(row["domain"], row["id"]) for row in descriptors}
    current_ids = set(aatk.library_prod_gate.current_incumbent_predicate_inventory())
    assert {predicate_id for domain, predicate_id in keys if domain == "current-incumbent"} == current_ids
    assert {
        predicate_id for domain, predicate_id in keys if domain == "candidate-postdeploy"
    } == {
        "materialize.profile-pin.claude-code",
        "materialize.profile-pin.pi",
        "materialize.public.claude-code.http-200",
        "materialize.public.pi.http-200",
        "materialize.response-contract.claude-code",
        "materialize.response-contract.pi",
    }


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("runtime", "pi"),
        ("surface", "generated-origin"),
        ("assertion", "strict-candidate-response-shape"),
    ],
)
def test_identical_mapping_rejects_source_semantic_mismatch(
    monkeypatch: pytest.MonkeyPatch, field: str, replacement: str
) -> None:
    descriptors = copy.deepcopy(aatk.source_semantic_descriptors())
    current = next(
        row
        for row in descriptors
        if row["domain"] == "current-incumbent"
        and row["id"] == "materialize.public.claude-code.http-200"
    )
    current[field] = replacement
    monkeypatch.setattr(
        aatk.library_prod_gate,
        "aatk_semantic_descriptors",
        lambda: copy.deepcopy(descriptors),
    )
    assert_error(
        "candidate-semantic-mismatch",
        f"source.semantic_descriptors.current-incumbent.materialize.public.claude-code.http-200.{field}",
        aatk.validate_manifest,
        manifest(),
    )


def test_identical_mapping_rejects_unknown_target() -> None:
    value = manifest()
    row = coverage_row(
        value, "current-incumbent", "materialize.public.claude-code.http-200"
    )
    row["candidate_mapping"]["candidate_predicate_id"] = "orphaned.candidate.target"
    row_index = value["capability_coverage"].index(row)
    assert_error(
        "candidate-mapping-target",
        f"manifest.capability_coverage[{row_index}].candidate_mapping.candidate_predicate_id",
        aatk.validate_manifest,
        value,
    )


def test_identical_mapping_rejects_duplicate_flattened_target() -> None:
    value = manifest()
    first = coverage_row(
        value, "current-incumbent", "materialize.profile-pin.claude-code"
    )
    second = coverage_row(value, "current-incumbent", "materialize.profile-pin.pi")
    second["candidate_mapping"]["candidate_predicate_id"] = first["candidate_mapping"][
        "candidate_predicate_id"
    ]
    second_index = value["capability_coverage"].index(second)
    assert_error(
        "duplicate-candidate-mapping-target",
        f"manifest.capability_coverage[{second_index}].candidate_mapping.candidate_predicate_id",
        aatk.validate_manifest,
        value,
    )


@pytest.mark.parametrize("mutation", ["omitted", "unknown", "renamed"])
def test_current_incumbent_registration_rejects_inventory_mismatch(mutation: str) -> None:
    value = manifest()
    row = next(
        item for item in value["capability_coverage"] if item["domain"] == "current-incumbent"
    )
    if mutation == "omitted":
        value["capability_coverage"].remove(row)
    else:
        prefix = "orphaned" if mutation == "unknown" else mutation
        row["id"] = f"{prefix}.current-incumbent.predicate"
    assert_error(
        "current-incumbent-universe",
        "manifest.capability_coverage",
        aatk.validate_manifest,
        value,
    )


def test_semantic_descriptors_reject_duplicate_domain_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptors = copy.deepcopy(aatk.source_semantic_descriptors())
    descriptors.append(copy.deepcopy(descriptors[0]))
    monkeypatch.setattr(
        aatk.library_prod_gate,
        "aatk_semantic_descriptors",
        lambda: copy.deepcopy(descriptors),
    )
    assert_error(
        "duplicate-semantic-descriptor",
        f"source.semantic_descriptors[{len(descriptors) - 1}].id",
        aatk.validate_manifest,
        manifest(),
    )


@pytest.mark.parametrize("domain", ["candidate-postdeploy", "current-incumbent"])
@pytest.mark.parametrize("mutation", ["omitted", "unknown", "renamed"])
def test_semantic_descriptors_reject_inventory_mismatch(
    monkeypatch: pytest.MonkeyPatch, domain: str, mutation: str
) -> None:
    descriptors = copy.deepcopy(aatk.source_semantic_descriptors())
    row = next(item for item in descriptors if item["domain"] == domain)
    if mutation == "omitted":
        descriptors.remove(row)
    else:
        prefix = "orphaned" if mutation == "unknown" else mutation
        row["id"] = f"{prefix}.semantic.predicate"
    monkeypatch.setattr(
        aatk.library_prod_gate,
        "aatk_semantic_descriptors",
        lambda: copy.deepcopy(descriptors),
    )
    assert_error(
        "semantic-descriptor-universe",
        f"source.semantic_descriptors.{domain}",
        aatk.validate_manifest,
        manifest(),
    )


def test_capability_coverage_rejects_manifest_only_status_edit() -> None:
    value = manifest()
    value["capability_coverage"][0]["obligations"][
        "runtime.path-fidelity"
    ] = "instrumented-capability"
    assert_error(
        "capability-source-mismatch",
        "manifest.capability_coverage",
        aatk.validate_manifest,
        value,
    )


def test_emitter_registration_cannot_diverge_from_instrumented_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest()
    monkeypatch.setattr(
        aatk.render_ops,
        "CAPABILITY_FIXTURE_PREDICATES",
        frozenset({"health.origin.http-200"}),
    )
    assert_error(
        "capability-emitter-registration",
        "source.capability_coverage",
        aatk.validate_manifest,
        value,
    )


def test_source_coverage_omission_cannot_hide_behind_complete_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest()
    coverage = copy.deepcopy(aatk.render_ops.AATK_PREDICATE_COVERAGE)
    coverage.pop("health.origin.http-200")
    monkeypatch.setattr(aatk.render_ops, "AATK_PREDICATE_COVERAGE", coverage)
    assert_error(
        "capability-emitter-registration",
        "source.capability_coverage",
        aatk.validate_manifest,
        value,
    )


def test_implemented_obligations_have_immutable_source_history() -> None:
    value = manifest()
    implemented = {
        row["id"]: row["first_enforced_increment"]
        for row in value["requirement_registry"]
        if row["status"] == "implemented"
    }
    assert implemented == aatk.ENFORCEMENT_HISTORY
    assert all(
        "first_enforced_increment" not in row
        for row in value["requirement_registry"]
        if row["status"] == "deferred"
    )


def test_enforcement_history_rejects_rewritten_increment() -> None:
    value = manifest()
    row = next(item for item in value["requirement_registry"] if item["status"] == "implemented")
    index = value["requirement_registry"].index(row)
    row["first_enforced_increment"] = "increment-2a"
    assert_error(
        "enforcement-history",
        f"manifest.requirement_registry[{index}].first_enforced_increment",
        aatk.validate_manifest,
        value,
    )


def test_deferred_obligation_rejects_unearned_history() -> None:
    value = manifest()
    row = next(item for item in value["requirement_registry"] if item["status"] == "deferred")
    index = value["requirement_registry"].index(row)
    row["first_enforced_increment"] = "increment-2a"
    assert_error(
        "enforcement-registry",
        f"manifest.requirement_registry[{index}]",
        aatk.validate_manifest,
        value,
    )


@pytest.mark.parametrize("mode", ["preplan", "release"])
def test_lifecycle_validation_machine_blocks_on_every_deferred_obligation(mode: str) -> None:
    value = manifest()
    index = evidence_index(value, release=mode == "release")
    error = assert_error(
        "unenforced-obligation",
        f"lifecycle.{mode}",
        aatk.validate_index,
        value,
        index,
        mode=mode,
        now=NOW,
    )
    for obligation_id in sorted(aatk.DEFERRED_ENFORCEMENT_IDS):
        assert obligation_id in str(error)


@pytest.mark.parametrize("proof_kind", ["capability-fixture", "current-incumbent-debug"])
def test_debug_and_capability_output_are_forbidden_as_lifecycle_evidence(
    proof_kind: str,
) -> None:
    value = manifest()
    row = value["predicates"][0]
    candidate_index = evidence_index(value)
    candidate_receipt = receipt(value, row, "current-production")
    candidate_receipt["proof_kind"] = proof_kind
    assert_error(
        "capability-not-lifecycle-evidence",
        "index.receipts[0].proof_kind",
        lambda candidate: aatk.validate_receipt(
            candidate,
            location="index.receipts[0]",
            row=row,
            manifest_sha=aatk.manifest_digest(value),
            index=candidate_index,
            now=NOW,
        ),
        candidate_receipt,
    )


@pytest.mark.parametrize("sentinel", aatk.SENTINELS)
def test_each_release_finding_sentinel_is_independently_rejected(sentinel: str) -> None:
    value = manifest()
    value["predicates"][0]["owner"] = sentinel
    assert_error(
        "sentinel-value",
        "manifest.predicates[0].owner",
        aatk.validate_manifest,
        value,
    )


def test_service_object_rejects_untyped_identity() -> None:
    value = manifest()
    value["service"] = 123
    assert_error("service-contract", "manifest.service", aatk.validate_manifest, value)


def test_predicate_owner_rejects_untyped_value() -> None:
    value = manifest()
    value["predicates"][0]["owner"] = 123
    assert_error(
        "invalid-owner", "manifest.predicates[0].owner", aatk.validate_manifest, value
    )


def test_predicate_owner_must_equal_source_coverage_owner() -> None:
    value = manifest()
    value["predicates"][0]["owner"] = "another-owner"
    assert_error(
        "capability-owner",
        "manifest.predicates[0].owner",
        aatk.validate_manifest,
        value,
    )


def test_proof_object_rejects_unknown_authoritative_field() -> None:
    value = manifest()
    value["predicates"][0]["postdeploy"]["passed"] = True
    assert_error(
        "invalid-proof",
        "manifest.predicates[0].postdeploy",
        aatk.validate_manifest,
        value,
    )


def test_registry_owner_rejects_untyped_value() -> None:
    value = manifest()
    value["requirement_registry"][0]["owner"] = 123
    assert_error(
        "enforcement-registry",
        "manifest.requirement_registry[0].owner",
        aatk.validate_manifest,
        value,
    )


def test_expiry_condition_rejects_untyped_value() -> None:
    value = manifest()
    value["predicates"][0]["expiry"]["condition_code"] = 123
    assert_error(
        "expiry",
        "manifest.predicates[0].expiry.condition_code",
        aatk.validate_manifest,
        value,
    )


def test_candidate_absence_shape_rejects_untyped_value() -> None:
    value = manifest()
    row = row_by_id(value, "health.public.build-sha")
    row["current_production"]["absence"]["incumbent_shape"] = 123
    index = value["predicates"].index(row)
    assert_error(
        "candidate-only-absence",
        f"manifest.predicates[{index}].current_production.absence.incumbent_shape",
        aatk.validate_manifest,
        value,
    )


@pytest.mark.parametrize(
    ("mutate", "code", "location"),
    [
        (
            lambda value: value["requirement_registry"][0].__setitem__("status", {}),
            "enforcement-registry",
            "manifest.requirement_registry[0].status",
        ),
        (
            lambda value: value["predicates"][0]["current_production"].__setitem__(
                "state", {}
            ),
            "current-state",
            "manifest.predicates[0].current_production",
        ),
        (
            lambda value: value["predicates"][0]["negative_controls"][0].__setitem__(
                "polarity", {}
            ),
            "negative-contract",
            "manifest.predicates[0].negative_controls[0].polarity",
        ),
        (
            lambda value: value["predicates"][0]["expiry"].__setitem__("kind", {}),
            "expiry",
            "manifest.predicates[0].expiry.kind",
        ),
    ],
)
def test_malformed_nested_manifest_returns_typed_aatk_error(
    mutate, code: str, location: str
) -> None:
    value = manifest()
    mutate(value)
    assert_error(code, location, aatk.validate_manifest, value)


def test_blank_cell_is_rejected_with_exact_row_and_cell() -> None:
    value = manifest()
    value["predicates"][0]["owner"] = " "
    assert_error("blank-value", "manifest.predicates[0].owner", aatk.validate_manifest, value)


def test_static_manifest_cannot_embed_a_runtime_receipt() -> None:
    value = manifest()
    value["predicates"][0]["run_id"] = "runtime-result"
    assert_error(
        "static-dynamic-contamination",
        "manifest.predicates[0].run_id",
        aatk.validate_manifest,
        value,
    )


def test_deleted_predicate_row_is_not_an_invisible_blank() -> None:
    value = manifest()
    deleted = value["predicates"].pop(0)["id"]
    error = assert_error(
        "missing-predicate", "manifest.predicates", aatk.validate_manifest, value
    )
    assert deleted in str(error)


def test_renamed_predicate_exposes_the_missing_source_id() -> None:
    value = manifest()
    renamed = value["predicates"][0]["id"]
    value["predicates"][0]["id"] = "orphan.predicate"
    error = assert_error(
        "missing-predicate", "manifest.predicates", aatk.validate_manifest, value
    )
    assert renamed in str(error)


def test_unknown_or_orphaned_predicate_row_is_rejected() -> None:
    value = manifest()
    orphan = copy.deepcopy(value["predicates"][0])
    orphan["id"] = "orphan.predicate"
    value["predicates"].append(orphan)
    error = assert_error(
        "unknown-predicate", "manifest.predicates", aatk.validate_manifest, value
    )
    assert "orphan.predicate" in str(error)


def test_duplicate_predicate_row_is_rejected_before_set_collapse() -> None:
    value = manifest()
    value["predicates"].append(copy.deepcopy(value["predicates"][0]))
    index = len(value["predicates"]) - 1
    assert_error(
        "duplicate-predicate",
        f"manifest.predicates[{index}].id",
        aatk.validate_manifest,
        value,
    )


def test_lifecycle_index_path_is_exported_not_make_interpolated() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    lifecycle_recipes = makefile.split("aatk-validate-preplan:\n", 1)[1]
    assert "export AATK_EVIDENCE_INDEX" in makefile
    assert "$(AATK_EVIDENCE_INDEX)" not in lifecycle_recipes
    assert lifecycle_recipes.count('"$$AATK_EVIDENCE_INDEX"') == 4


def test_lifecycle_index_path_cannot_inject_a_shell_command(tmp_path: Path) -> None:
    marker = tmp_path / "injected"
    payload = f'{tmp_path}/missing"; touch {marker}; #'
    completed = subprocess.run(
        ["make", "aatk-validate-preplan", f"AATK_EVIDENCE_INDEX={payload}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert not marker.exists()
    assert "invalid-json" in completed.stderr


def test_nonchecked_entrypoint_is_rejected() -> None:
    value = manifest()
    value["predicates"][0]["current_production"]["proof"]["make_target"] = "curl-production"
    assert_error(
        "unchecked-command",
        "manifest.predicates[0].current_production.proof.make_target",
        aatk.validate_manifest,
        value,
    )


def test_positive_and_negative_must_remain_on_the_same_declared_path() -> None:
    value = manifest()
    value["predicates"][0]["negative_controls"][0]["proof"]["path_fingerprint"][-1] = "unit.checker-only"
    assert_error(
        "unit-only-substitution",
        "manifest.predicates[0].negative_controls[0].proof.path_fingerprint",
        aatk.validate_manifest,
        value,
    )


def test_every_row_requires_a_positive_and_a_negative() -> None:
    value = manifest()
    value["predicates"][0]["negative_controls"] = []
    assert_error(
        "missing-negative",
        "manifest.predicates[0].negative_controls",
        aatk.validate_manifest,
        value,
    )


def test_transport_predicate_cannot_use_candidate_only_escape_hatch() -> None:
    value = manifest()
    row = row_by_id(value, "health.public.http-200")
    row["current_production"] = copy.deepcopy(
        row_by_id(value, "health.public.build-sha")["current_production"]
    )
    index = value["predicates"].index(row)
    assert_error(
        "candidate-only-permissive",
        f"manifest.predicates[{index}].current_production.state",
        aatk.validate_manifest,
        value,
    )


def test_candidate_only_state_cannot_waive_shared_transport() -> None:
    value = manifest()
    row = row_by_id(value, "health.public.build-sha")
    row["current_production"]["absence"]["shared_transport_waived"] = True
    index = value["predicates"].index(row)
    assert_error(
        "candidate-only-transport-waiver",
        f"manifest.predicates[{index}].current_production.absence.shared_transport_waived",
        aatk.validate_manifest,
        value,
    )


def test_candidate_only_state_requires_exact_source_positive() -> None:
    value = manifest()
    row = row_by_id(value, "health.public.build-sha")
    row["exact_source"] = {"state": "not-required", "reason_code": "convenient"}
    index = value["predicates"].index(row)
    assert_error(
        "candidate-only-without-source-positive",
        f"manifest.predicates[{index}].exact_source.state",
        aatk.validate_manifest,
        value,
    )


def test_editing_deferred_status_cannot_clear_source_enforcement_blocker() -> None:
    value = manifest()
    obligation = next(
        item for item in value["requirement_registry"] if item["status"] == "deferred"
    )
    obligation_index = value["requirement_registry"].index(obligation)
    obligation["status"] = "implemented"
    obligation["blocked_lifecycle_stages"] = []
    assert_error(
        "enforcement-registry",
        f"manifest.requirement_registry[{obligation_index}]",
        aatk.validate_manifest,
        value,
    )


@pytest.mark.parametrize(
    ("mutate", "code", "location"),
    [
        (
            lambda value, index: index.__setitem__("manifest_sha256", DIGEST),
            "wrong-manifest",
            "index.manifest_sha256",
        ),
        (
            lambda value, index: index.__setitem__("candidate_sha", "short"),
            "wrong-sha",
            "index.candidate_sha",
        ),
        (
            lambda value, index: index["ci"].__setitem__("app_id", 1),
            "wrong-ci-gate",
            "index.ci",
        ),
        (
            lambda value, index: index["ci"].__setitem__("context", "another-check"),
            "wrong-ci-gate",
            "index.ci",
        ),
        (
            lambda value, index: index["ci"].__setitem__("event", "workflow_dispatch"),
            "wrong-ci-gate",
            "index.ci",
        ),
    ],
)
def test_index_binding_mutations_fail_for_exact_reason(mutate, code: str, location: str) -> None:
    value = manifest()
    index = evidence_index(value)
    mutate(value, index)
    assert_error(code, location, aatk.validate_index, value, index, mode="preplan", now=NOW)


@pytest.mark.parametrize(
    ("field", "replacement", "code", "suffix"),
    [
        ("source_sha", OTHER_COMMIT, "wrong-sha", "source_sha"),
        ("script_sha256", "short", "invalid-digest", "script_sha256"),
        ("config_sha256", "short", "invalid-digest", "config_sha256"),
        ("parent_run_id", "another-run", "mixed-run", "parent_run_id"),
        ("fresh_until", "2026-07-29T06:00:00Z", "invalid-expiry", ""),
    ],
)
def test_receipt_binding_and_expiry_mutations_fail_for_exact_reason(
    field: str, replacement: str, code: str, suffix: str
) -> None:
    value = manifest()
    index = evidence_index(value)
    index["receipts"][0][field] = replacement
    location = "index.receipts[0]" + (f".{suffix}" if suffix else "")
    assert_error(code, location, aatk.validate_index, value, index, mode="preplan", now=NOW)


def test_stale_receipt_is_rejected_independently_from_invalid_ordering() -> None:
    value = manifest()
    index = evidence_index(value)
    index["receipts"][0]["fresh_until"] = "2026-07-29T07:10:00Z"
    assert_error(
        "stale-receipt",
        "index.receipts[0].fresh_until",
        aatk.validate_index,
        value,
        index,
        mode="preplan",
        now=NOW,
    )


def test_success_without_one_terminal_record_is_rejected() -> None:
    value = manifest()
    index = evidence_index(value)
    index["receipts"][0]["terminal"]["count"] = 0
    assert_error(
        "multiple-terminal",
        "index.receipts[0].terminal.count",
        aatk.validate_index,
        value,
        index,
        mode="preplan",
        now=NOW,
    )


def test_unrelated_failure_cannot_satisfy_a_dedicated_negative() -> None:
    value = manifest()
    index = evidence_index(value)
    negative_index = next(
        i for i, item in enumerate(index["receipts"]) if item["proof_kind"] == "negative"
    )
    index["receipts"][negative_index]["terminal"]["assertion_code"] = "process.nonzero"
    assert_error(
        "unrelated-failure",
        f"index.receipts[{negative_index}].terminal.assertion_code",
        aatk.validate_index,
        value,
        index,
        mode="preplan",
        now=NOW,
    )


def test_index_rejects_unknown_top_level_field() -> None:
    value = manifest()
    index = evidence_index(value)
    index["authoritative_note"] = "passed"
    assert_error(
        "index-contract", "index", aatk.validate_index, value, index, mode="preplan", now=NOW
    )


def test_receipt_rejects_unknown_proof_field() -> None:
    value = manifest()
    index = evidence_index(value)
    index["receipts"][0]["passed"] = True
    assert_error(
        "invalid-receipt",
        "index.receipts[0]",
        aatk.validate_index,
        value,
        index,
        mode="preplan",
        now=NOW,
    )


@pytest.mark.parametrize(
    ("mutate", "code", "location"),
    [
        (
            lambda receipt: receipt.__setitem__("proof_kind", {}),
            "proof-kind",
            "index.receipts[0].proof_kind",
        ),
        (
            lambda receipt: receipt.__setitem__("substitutions", [{}]),
            "unapproved-substitution",
            "index.receipts[0].substitutions",
        ),
        (
            lambda receipt: receipt.__setitem__("terminal", []),
            "nonterminal",
            "index.receipts[0].terminal",
        ),
        (
            lambda receipt: receipt.__setitem__("artifact", []),
            "artifact",
            "index.receipts[0].artifact",
        ),
    ],
)
def test_malformed_nested_receipt_returns_typed_aatk_error(
    mutate, code: str, location: str
) -> None:
    value = manifest()
    index = evidence_index(value)
    mutate(index["receipts"][0])
    assert_error(code, location, aatk.validate_index, value, index, mode="preplan", now=NOW)


def test_duplicate_receipt_cannot_be_reused_as_another_proof() -> None:
    value = manifest()
    index = evidence_index(value)
    index["receipts"].append(copy.deepcopy(index["receipts"][0]))
    duplicate_index = len(index["receipts"]) - 1
    assert_error(
        "duplicate-receipt",
        f"index.receipts[{duplicate_index}]",
        aatk.validate_index,
        value,
        index,
        mode="preplan",
        now=NOW,
    )


def test_receipt_for_unknown_predicate_is_rejected() -> None:
    value = manifest()
    index = evidence_index(value)
    index["receipts"][0]["predicate_id"] = "orphan.predicate"
    assert_error(
        "unknown-predicate",
        "index.receipts[0].predicate_id",
        aatk.validate_index,
        value,
        index,
        mode="preplan",
        now=NOW,
    )


def test_missing_positive_receipt_cannot_be_hidden_by_negatives() -> None:
    value = manifest()
    index = evidence_index(value)
    predicate_id = value["predicates"][0]["id"]
    index["receipts"] = [
        item
        for item in index["receipts"]
        if not (
            item["predicate_id"] == predicate_id
            and item["proof_kind"] == "current-production"
        )
    ]
    assert_error(
        "missing-receipt",
        f"predicate.{predicate_id}.current-production",
        aatk.validate_index,
        value,
        index,
        mode="preplan",
        now=NOW,
    )


def test_release_close_requires_each_child_postdeploy_receipt() -> None:
    value = manifest()
    index = evidence_index(value, release=True)
    predicate_id = value["predicates"][0]["id"]
    index["receipts"] = [
        item
        for item in index["receipts"]
        if not (
            item["predicate_id"] == predicate_id
            and item["proof_kind"] == "postdeploy"
        )
    ]
    assert_error(
        "missing-receipt",
        f"predicate.{predicate_id}.postdeploy",
        aatk.validate_index,
        value,
        index,
        mode="release",
        now=NOW,
    )


def test_release_close_requires_each_declared_rollback_receipt() -> None:
    value = manifest()
    index = evidence_index(value, release=True)
    row = next(item for item in value["predicates"] if item["rollback"]["state"] == "required")
    predicate_id = row["id"]
    index["receipts"] = [
        item
        for item in index["receipts"]
        if not (
            item["predicate_id"] == predicate_id
            and item["proof_kind"] == "rollback"
        )
    ]
    assert_error(
        "missing-receipt",
        f"predicate.{predicate_id}.rollback",
        aatk.validate_index,
        value,
        index,
        mode="release",
        now=NOW,
    )

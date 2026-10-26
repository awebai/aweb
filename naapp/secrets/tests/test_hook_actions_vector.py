"""secrets' transition-to-hook-action table (secrets §11.5) against the frozen
aweb.hooks catalog (docs/vectors/hook-catalog-v1.json).

The table is data S13's tests read. Here it may name only actions, decisions,
refusal codes, dispositions, acts and authorities the catalog defines, and each
row's example event must pass the catalog's own validator.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from aweb_naapp.hooks.catalog import PayloadRefused, load_catalog
from aweb_naapp.runtime.audit import AuditKind

AWEB_ROOT = Path(__file__).resolve().parents[3]
CATALOG_BYTES = (AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes()
CATALOG_DOCUMENT = json.loads(CATALOG_BYTES)
CATALOG = load_catalog(CATALOG_BYTES)
TABLE = json.loads((Path(__file__).parents[1] / "vectors" / "hook-actions-v1.json").read_text())
USE_APPROVAL = json.loads(
    (Path(__file__).parents[1] / "vectors" / "use-approval-v1.json").read_text()
)

USE = "post-secret-use-hook"
GOVERNANCE = "post-governance-hook"
USE_FIELDS = CATALOG_DOCUMENT["hooks"][USE]["fields"]
GOVERNANCE_HOOK = CATALOG_DOCUMENT["hooks"][GOVERNANCE]

# What secrets returns to an agent. There is no value for a returned credential,
# because returning a credential does not exist (secrets §11.5, decision 4).
SECRETS_DISPOSITIONS = {"returned", "withheld", "stored_as_secret"}


def test_the_table_names_the_catalog_it_was_checked_against():
    assert TABLE["catalog"] == CATALOG_DOCUMENT["catalog"]
    assert (CATALOG.id, CATALOG.version) == (TABLE["catalog"]["id"], TABLE["catalog"]["version"])


def test_every_state_of_the_dispatch_machine_is_mapped_once():
    transitions = [row["transition"] for row in TABLE["use_transitions"]]
    assert len(transitions) == len(set(transitions))
    assert set(transitions) == set(TABLE["states"]) - {"received"} | {"approval_approved"}


def test_use_actions_and_decisions_equal_the_catalog_enums():
    assert {row["action"] for row in TABLE["use_transitions"]} == set(USE_FIELDS["action"]["enum"])
    decisions = {
        row["approval_decision"] for row in TABLE["use_transitions"] if "approval_decision" in row
    }
    assert decisions == set(USE_FIELDS["approval_decision"]["enum"])


def test_refusal_codes_equal_the_catalog_enum():
    assert set(TABLE["refusal_codes"]) == set(USE_FIELDS["refusal_code"]["enum"])
    assert len(TABLE["refusal_codes"]) == len(set(TABLE["refusal_codes"]))


def test_dispositions_equal_what_secrets_returns():
    assert set(TABLE["dispositions"]) == SECRETS_DISPOSITIONS
    assert set(USE_FIELDS["disposition"]["enum"]) == SECRETS_DISPOSITIONS


@pytest.mark.parametrize("row", TABLE["use_transitions"], ids=lambda row: row["transition"])
def test_each_use_transition_example_is_a_valid_catalog_event(row):
    for example in row["examples"]:
        assert example["action"] == row["action"]
        if "approval_decision" in row:
            assert example["approval_decision"] == row["approval_decision"]
        CATALOG.validate(USE, example)
        assert CATALOG.is_audit_critical(USE, example) is row["audit_critical"]


def test_the_examples_cover_every_disposition_and_both_op_kinds():
    examples = [e for row in TABLE["use_transitions"] for e in row["examples"]]
    assert {e["disposition"] for e in examples if "disposition" in e} == SECRETS_DISPOSITIONS
    assert {e["op_kind"] for e in examples} == {"broker", "run_job"}


@pytest.mark.parametrize("row", TABLE["governance_acts"], ids=lambda row: row["act"])
def test_each_governance_act_exists_with_the_catalog_direction(row):
    assert row["act"] in GOVERNANCE_HOOK["fields"]["act"]["enum"]
    assert row["direction"] == GOVERNANCE_HOOK["act_directions"][row["act"]]
    assert row["example"]["act"] == row["act"]
    CATALOG.validate(GOVERNANCE, row["example"])


def test_authorities_equal_the_catalog_enum():
    assert set(TABLE["authorities"]) == set(GOVERNANCE_HOOK["fields"]["authority"]["enum"])


def test_governance_acts_cover_the_complete_catalog_enum():
    acts = [row["act"] for row in TABLE["governance_acts"]]
    assert len(acts) == len(set(acts))
    assert set(acts) == set(GOVERNANCE_HOOK["fields"]["act"]["enum"])


def test_example_secret_kinds_are_use_approval_kinds():
    kinds = {
        example["secret_kind"]
        for row in TABLE["use_transitions"]
        for example in row["examples"]
        if "secret_kind" in example
    }
    assert kinds and kinds <= set(USE_APPROVAL["secret_kinds"])


def test_b3_lifecycle_maps_every_approver_kind_once():
    kinds = [row["audit_kind"] for row in TABLE["b3_lifecycle"]]
    assert len(kinds) == len(set(kinds))
    assert set(kinds) == {kind.value for kind in AuditKind if kind.name.startswith("APPROVER_")}
    assert {row["audit_kind"] for row in TABLE["b3_lifecycle"] if row["hook"] is None} == {
        "approver_logged_in",
        "approver_enrolment_reissued",
    }
    for row in TABLE["b3_lifecycle"]:
        if row["hook"] is None:
            assert row["exclusion"] and "example" not in row


@pytest.mark.parametrize("row", TABLE["b3_lifecycle"], ids=lambda row: row["audit_kind"])
def test_b3_governance_payloads_follow_the_catalog_and_availability_rule(row):
    if row["hook"] is None:
        return
    assert row["hook"] == GOVERNANCE
    payload = row["example"]
    CATALOG.validate(GOVERNANCE, payload)
    assert CATALOG.is_audit_critical(GOVERNANCE, payload) is (payload["direction"] == "widening")


def test_b3_completion_examples_preserve_original_authority_and_candidate_states():
    rows = {row["audit_kind"]: row["example"] for row in TABLE["b3_lifecycle"] if row["hook"]}
    assert rows["approver_redesignated"]["act"] == "credential.recovered"
    assert rows["approver_enrolled"]["act"] == "credential.enrolled"
    assert (
        rows["approver_enrolled"]["owner_act_sha256"]
        == rows["approver_designated"]["owner_act_sha256"]
    )
    scheduled = rows["approver_contact_change_by_owner_scheduled"]
    proven = rows["approver_contact_proven"]
    cancelled = rows["approver_contact_change_cancelled"]
    assert scheduled["approval_evidence_sha256"] == proven["approval_evidence_sha256"]
    assert scheduled["approval_id"] == proven["approval_id"]
    assert cancelled["approval_evidence_sha256"] != proven["approval_evidence_sha256"]
    assert "approval_id" not in cancelled
    contacts = [
        payload for payload in rows.values() if payload.get("resource_type") == "pending_contact"
    ]
    assert len(contacts) == 4
    assert len({payload["resource_ref"] for payload in contacts}) == 1
    assert proven["before_ref"] == scheduled["after_ref"]
    assert cancelled["before_ref"] == proven["after_ref"]
    assert len({scheduled["after_ref"], proven["after_ref"], cancelled["after_ref"]}) == 3
    assert {payload["reason_code"] for payload in contacts} == {
        "contact_change_scheduled",
        "contact_proven",
        "contact_change_cancelled",
    }


@pytest.mark.parametrize("case", TABLE["b3_payload_refusals"], ids=lambda case: case["name"])
def test_b3_invalid_payload_variants_are_refused(case):
    row = next(row for row in TABLE["b3_lifecycle"] if row["audit_kind"] == case["audit_kind"])
    payload = dict(row["example"])
    payload.update(case["set"])
    for field in case["remove"]:
        payload.pop(field)
    with pytest.raises(PayloadRefused):
        CATALOG.validate(GOVERNANCE, payload)


@pytest.mark.parametrize(
    "row", TABLE["change_governance"], ids=lambda row: row["kind"] + "/" + row["op"]
)
def test_change_item_governance_examples_use_actual_approval_and_resource_identity(row):
    payload = row["example"]
    CATALOG.validate(GOVERNANCE, payload)
    assert CATALOG.is_audit_critical(GOVERNANCE, payload)
    assert payload["authority"] == "passkey_session"
    assert payload["approval_id"] and payload["approval_evidence_sha256"]
    assert "policy_digest" not in payload
    if row["kind"] == "secret":
        assert payload["act"] == "resource.changed"
        assert payload["resource_type"] == "secret"
        assert payload["before_ref"] != payload["after_ref"]
    elif row["kind"] == "grant_template":
        assert payload["act"] == ("grant.created" if row["op"] == "create" else "grant.changed")
        assert payload["resource_type"] == "grant_template"
        assert payload["resource_ref"] == "gtp_sts-derived"
    else:
        assert row["kind"] == "change_set_policy"
        assert payload["act"] == "policy.changed"
        assert payload["resource_type"] == "change_set_policy"
        assert payload["resource_ref"] == "inst_5d2a9c31"


@pytest.mark.parametrize("row", TABLE["job_current_revisions"], ids=lambda row: row["name"])
def test_job_current_receipts_are_widening_and_cite_actual_approval(row):
    payload = row["example"]
    CATALOG.validate(GOVERNANCE, payload)
    assert CATALOG.is_audit_critical(GOVERNANCE, payload)
    assert payload["act"] == (
        "resource.created" if row["op"] == "create" else "resource.version_added"
    )
    assert payload["resource_type"] == "job"
    assert payload["resource_ref"] == "nightly-backup"
    assert payload["authority"] == "passkey_session"
    assert payload["approval_id"] and payload["approval_evidence_sha256"]
    if row["op"] == "update":
        assert payload["before_ref"] != payload["after_ref"]


def test_a_stored_body_restore_gets_a_new_current_revision_and_approval():
    rows = {row["name"]: row for row in TABLE["job_current_revisions"]}
    assert set(rows) == {"create", "update_new_definition", "restore_stored_definition"}
    created, updated, restored = (
        rows[name] for name in ("create", "update_new_definition", "restore_stored_definition")
    )
    assert created["definition_fixture"] == restored["definition_fixture"]
    assert updated["definition_fixture"] != restored["definition_fixture"]
    assert updated["example"]["before_ref"] == created["example"]["after_ref"]
    assert restored["example"]["before_ref"] == updated["example"]["after_ref"]
    for field in ("after_ref", "approval_id", "approval_evidence_sha256"):
        assert len({row["example"][field] for row in rows.values()}) == 3


@pytest.mark.parametrize("case", TABLE["job_payload_refusals"], ids=lambda case: case["name"])
def test_invalid_job_receipt_payloads_are_refused(case):
    row = next(
        row for row in TABLE["job_current_revisions"] if row["name"] == "update_new_definition"
    )
    payload = dict(row["example"])
    payload.update(case["set"])
    for field in case["remove"]:
        payload.pop(field)
    with pytest.raises(PayloadRefused) as refused:
        CATALOG.validate(GOVERNANCE, payload)
    assert (refused.value.code, refused.value.field) == (case["error"], case["field"])

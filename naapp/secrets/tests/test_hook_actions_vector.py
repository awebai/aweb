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
from aweb_naapp.hooks.catalog import load_catalog

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


def test_example_secret_kinds_are_use_approval_kinds():
    kinds = {
        example["secret_kind"]
        for row in TABLE["use_transitions"]
        for example in row["examples"]
        if "secret_kind" in example
    }
    assert kinds and kinds <= set(USE_APPROVAL["secret_kinds"])

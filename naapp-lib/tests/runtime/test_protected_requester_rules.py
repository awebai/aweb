"""Closed requester rules and their validated subject/phase bindings."""
from dataclasses import fields, replace

import pytest

from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS, RequesterRule, operation_spec


def test_requester_rule_has_exactly_three_closed_fields():
    assert tuple(field.name for field in fields(RequesterRule)) == ("proof", "principal_bound_to", "bound_in")
    for name, value in (("proof", "anonymous"), ("principal_bound_to", "any_path"), ("bound_in", "later")):
        values = dict(proof="registered_requester", principal_bound_to="nothing", bound_in="every_phase")
        values[name] = value
        with pytest.raises(ValueError, match="requester rule"):
            RequesterRule(**values)


def test_existing_rows_use_only_the_three_reviewed_rule_values():
    expected = {
        ("team.agent.admit", "default"): ("registered_requester", "subject_root", "every_phase"),
        ("identity.root.endorse", "default"): ("registered_requester", "subject_root", "prepare_only"),
        ("team.agent.remove", "default"): ("registered_requester_or_own_certificate", "subject_root", "every_phase"),
        ("team.agent.remove", "owner_approved"): ("registered_requester_or_owner_session", "nothing", "every_phase"),
        ("human-role.revoke", "default"): ("registered_requester", "nothing", "every_phase"),
    }
    assert set(expected) == set(OPERATIONS)
    for selector, values in expected.items():
        row = operation_spec(*selector)
        assert (row.requester.proof, row.requester.principal_bound_to, row.requester.bound_in) == values
        assert row.owner_initiable is (values[0] == "registered_requester_or_owner_session")
        assert row.supports_self_removal is (values[0] == "registered_requester_or_own_certificate")
    # These eligibility flags cannot diverge from the proof rule in another row.
    row = operation_spec("team.agent.remove", "owner_approved")
    changed = replace(row, requester=RequesterRule("registered_requester", "nothing", "every_phase"))
    assert not changed.owner_initiable and not changed.supports_self_removal


@pytest.mark.parametrize("name", ["identity.root.endorse", "team.agent.admit"])
@pytest.mark.parametrize("purpose", ["prepare", "approval", "execute", "receipt"])
def test_subject_binding_uses_the_rows_phase_rule(name, purpose):
    from aweb_naapp.runtime.protected_signer import (
        ProtectedSigner,
        RestrictedRequester,
        SignerRefused,
    )
    from tests.runtime.test_protected_identity_artifacts import ROOT, operation

    selected = operation(name)
    owner = RestrictedRequester(ROOT, selected.context)
    other = RestrictedRequester(selected.context.human_id, selected.context)
    ProtectedSigner._check_requester_subject(selected, owner, purpose=purpose)
    if selected.spec.requester.bound_in == "every_phase" or purpose == "prepare":
        with pytest.raises(SignerRefused, match="scope_refused"):
            ProtectedSigner._check_requester_subject(selected, other, purpose=purpose)
    else:
        # The human who approves a root is not the root; prepare-only binding
        # must not be silently applied again to its approval or retained read.
        ProtectedSigner._check_requester_subject(selected, other, purpose=purpose)


@pytest.mark.parametrize("fields", [frozenset(), frozenset({"deployment_root"}), frozenset({"root_id", "root_id_or_self"})])
def test_subject_binding_field_is_refused_when_the_catalog_is_built(fields):
    row = operation_spec("team.agent.admit")
    with pytest.raises(ValueError, match="requester subject"):
        replace(row, codec=replace(row.codec, subject_fields=fields))


def test_own_certificate_proof_requires_the_self_subject_field_at_catalog_build():
    row = operation_spec("team.agent.remove")
    with pytest.raises(ValueError, match="requester subject"):
        replace(row, codec=replace(row.codec, subject_fields=frozenset({"root_id"})))


def test_current_rows_declare_the_same_subject_fields_as_their_existing_schema():
    expected = {
        ("team.agent.admit", "default"): "root_id",
        ("identity.root.endorse", "default"): "root_id",
        ("team.agent.remove", "default"): "root_id_or_self",
        ("team.agent.remove", "owner_approved"): None,
        ("human-role.revoke", "default"): None,
    }
    for selector, row in OPERATIONS.items():
        assert row.requester_subject_field == expected[selector]
        if row.codec.subject_schema is not None:
            assert row.codec.subject_fields == frozenset(row.codec.subject_schema["required"])

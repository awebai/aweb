"""The member action is selected from served definitions and its declared hook."""

from dataclasses import replace

import pytest
from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS, operation_spec

from aweb.protected_signing.member_actions import member_removal_definition


def test_member_action_requires_a_served_definition_with_its_actual_hook():
    row = operation_spec("team.agent.remove", "owner_approved")
    assert member_removal_definition(tuple(OPERATIONS.values())) is row
    assert member_removal_definition(tuple(spec for spec in OPERATIONS.values() if spec is not row)) is None
    other = replace(row, effect=replace(row.effect, initiation_prepare="prepare_another_action"))
    assert member_removal_definition((other, row)) is row
    assert member_removal_definition((other,)) is None


def test_ambiguous_member_actions_are_a_startup_error():
    row = operation_spec("team.agent.remove", "owner_approved")
    with pytest.raises(ValueError, match="ambiguous member-removal"):
        member_removal_definition((row, replace(row, variant="another")))

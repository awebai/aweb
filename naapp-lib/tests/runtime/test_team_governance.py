"""The typed team-governance wire and revision rules; no authority is mocked."""

from dataclasses import FrozenInstanceError

import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key

from aweb_naapp.hooks.owner_act import validate_owner_act_subject
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.protected_signer import SignerRefused

TEAM = "demo:example.org"
OWNER_ACT = "team.owner.change"
PERMISSIONS_ACT = "team.controller-permissions.change"
PERMISSION = "human-role.revoke/default"


@pytest.fixture
def humans():
    return sorted(
        stable_id_from_did_key(did_from_public_key(generate_keypair()[1])) for _ in range(2)
    )


def subject(operation, humans):
    values = (
        {"old_owners": humans[:1], "new_owners": humans}
        if operation == OWNER_ACT
        else {"old_permissions": [], "new_permissions": [PERMISSION]}
    )
    return {"team_id": TEAM, "expected_revision": 1, **values}


@pytest.mark.parametrize("operation", [OWNER_ACT, PERMISSIONS_ACT])
def test_team_governance_uses_the_existing_closed_owner_act_subject_codec(operation, humans):
    value = subject(operation, humans)
    assert validate_owner_act_subject(operation, value) == value
    for changed in (
        {**value, "expected_revision": True},
        {**value, "expected_revision": 0},
        {**value, "expected_revision": 2**53},
        {**value, "team_id": "another/format"},
        {**value, "principal": humans[0]},
        {k: v for k, v in value.items() if k != "expected_revision"},
    ):
        with pytest.raises(Refused):
            validate_owner_act_subject(operation, changed)


def test_owner_change_is_a_distinct_sorted_bounded_set(humans):
    value = subject(OWNER_ACT, humans)
    for owners in (
        [humans[0], humans[0]],
        list(reversed(humans)),
        humans * 33,
        ["agent"],
        "*",
        [True],
    ):
        with pytest.raises(Refused):
            validate_owner_act_subject(OWNER_ACT, {**value, "new_owners": owners})


def test_controller_permission_entries_name_an_operation_and_variant(humans):
    value = subject(PERMISSIONS_ACT, humans)
    for permissions in (
        [PERMISSION, PERMISSION],
        ["*"],
        ["human-role.revoke"],
        ["sign_bytes/*"],
        [False],
    ):
        with pytest.raises(Refused):
            validate_owner_act_subject(PERMISSIONS_ACT, {**value, "new_permissions": permissions})


def test_owner_and_permission_changes_consume_one_shared_exact_revision(humans):
    from aweb_naapp.runtime.protected_signer.governance import GovernanceState

    state = GovernanceState(TEAM, 1, tuple(humans[:1]), ())
    changed = state.transition(OWNER_ACT, subject(OWNER_ACT, humans))
    assert changed.revision == 2 and changed.owners == tuple(humans)
    assert state.revision == 1 and state.owners == tuple(humans[:1])
    # An owner mutation makes a previously prepared permission change stale.
    with pytest.raises(SignerRefused, match="stale_binding"):
        changed.transition(PERMISSIONS_ACT, subject(PERMISSIONS_ACT, humans))
    permissions = {**subject(PERMISSIONS_ACT, humans), "expected_revision": 2}
    final = changed.transition(PERMISSIONS_ACT, permissions)
    assert final.revision == 3 and final.permissions == (PERMISSION,)
    assert final.owners == tuple(humans)


def test_transition_checks_the_old_values_and_preserves_at_least_one_owner(humans):
    from aweb_naapp.runtime.protected_signer.governance import GovernanceState

    state = GovernanceState(TEAM, 1, tuple(humans[:1]), ())
    for operation, value, code in (
        (OWNER_ACT, {**subject(OWNER_ACT, humans), "old_owners": humans}, "operation_mismatch"),
        (OWNER_ACT, {**subject(OWNER_ACT, humans), "new_owners": []}, "last_owner_protected"),
        (
            OWNER_ACT,
            {**subject(OWNER_ACT, humans), "team_id": "other:example.org"},
            "scope_refused",
        ),
        (
            PERMISSIONS_ACT,
            {**subject(PERMISSIONS_ACT, humans), "old_permissions": [PERMISSION]},
            "operation_mismatch",
        ),
    ):
        with pytest.raises(SignerRefused, match=code):
            state.transition(operation, value)


@pytest.mark.parametrize(
    "permission",
    [
        "not-a-catalog-operation/default",
        "human-role.revoke/unknown",
        "namespace.register/default",
        "identity.human.rotate/default",
    ],
)
def test_permissions_cannot_authorize_unknown_operations_or_a_different_key_role(
    permission, humans
):
    from aweb_naapp.runtime.protected_signer.governance import GovernanceState

    state = GovernanceState(TEAM, 1, tuple(humans[:1]), ())
    with pytest.raises(SignerRefused):
        state.transition(
            PERMISSIONS_ACT, {**subject(PERMISSIONS_ACT, humans), "new_permissions": [permission]}
        )


def test_snapshot_and_transition_do_not_retain_mutable_caller_values(humans):
    from aweb_naapp.runtime.protected_signer.governance import GovernanceState

    owners = humans[:1]
    state = GovernanceState(TEAM, 1, owners, [])
    owners.append(humans[1])
    assert state.owners == tuple(humans[:1])
    value = subject(OWNER_ACT, humans)
    changed = state.transition(OWNER_ACT, value)
    expected = tuple(humans)
    value["new_owners"].clear()
    assert changed.owners == expected
    with pytest.raises(FrozenInstanceError):
        state.revision = 9


def test_revision_overflow_cannot_create_a_nonportable_record(humans):
    from aweb_naapp.runtime.protected_signer.governance import GovernanceState

    state = GovernanceState(TEAM, 2**53 - 1, tuple(humans[:1]), ())
    with pytest.raises(SignerRefused):
        state.transition(
            OWNER_ACT, {**subject(OWNER_ACT, humans), "expected_revision": state.revision}
        )

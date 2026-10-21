"""aweb.secrets.change/1: which change sets are well formed, and when one can be confirmed."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from awid.did import did_from_public_key, stable_id_from_public_key
from nacl.signing import SigningKey

from aweb_secrets.change import (
    KINDS,
    ChangeRefused,
    check_confirmable,
    check_confirmer,
    covered_bytes,
    parse_change,
    validate_change,
)

POLICY = {"ref": "change-policy", "version": 1}
_KEY = bytes(SigningKey(b"\x01" * 32).verify_key)
DID_KEY = did_from_public_key(_KEY)
DID_AW = stable_id_from_public_key(_KEY)
OTHER_DID_KEY = did_from_public_key(bytes(SigningKey(b"\x02" * 32).verify_key))
ISSUED = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def _change(**overrides: Any) -> dict[str, Any]:
    change: dict[str, Any] = {
        "v": 1,
        "type": "aweb.secrets.change",
        "change_id": "chg_1",
        "installation_id": "inst_1",
        "install_generation": 1,
        "team_id": "backend:acme.com",
        "drafter": {"via": "console", "scope": "secrets.owner.p1", "subject": "approver-1"},
        "base_revision": 7,
        "changes": [
            {
                "kind": "secret_value",
                "op": "create",
                "ref": "payments-live",
                "after": {"v": 1, "secret_ref": "payments-live", "version": 2},
            }
        ],
        "reason": "rotate the payments key",
        "issued_at": "2026-10-20T12:00:00Z",
        "expires_at": "2026-10-20T12:15:00Z",
    }
    change.update(overrides)
    return change


def _member(**overrides: Any) -> dict[str, Any]:
    member: dict[str, Any] = {
        "via": "team_auth",
        "principal": overrides.get("did_aw", DID_KEY),
        "member_did_key": DID_KEY,
        "certificate_id": "0b4c2c1e-7f4e-4a53-9d43-2f1f0d2c6a11",
        "alias": "alice",
    }
    member.update(overrides)
    return member


CURRENT = {"installation_id": "inst_1", "install_generation": 1, "team_id": "backend:acme.com"}


def _confirm(change: dict[str, Any], current_revision: int, now: datetime, **current: Any) -> None:
    check_confirmable(change, **{**CURRENT, **current}, current_revision=current_revision, now=now)


def _item(kind: str, op: str, ref: str, after: dict[str, Any]) -> dict[str, Any]:
    return {"kind": kind, "op": op, "ref": ref, "after": after}


def test_a_well_formed_change_is_accepted() -> None:
    validate_change(_change())


def test_the_kinds_are_exactly_the_widening_items() -> None:
    assert set(KINDS) == {
        "change_set_policy",
        "secret",
        "secret_value",
        "destination",
        "operation",
        "job",
        "runner",
        "grant",
        "role",
        "approver",
        "approver_contact",
        "policy",
        "reenable",
    }


def test_a_member_may_draft() -> None:
    validate_change(_change(drafter=_member()))
    validate_change(_change(drafter=_member(did_aw=DID_AW)))


@pytest.mark.parametrize(
    "drafter",
    [
        {"via": "console", "scope": "secrets.owner.p1"},
        {"via": "console", "scope": "s", "subject": "a", "alias": "x"},
        {"via": "email", "subject": "a"},
        {"via": "team_auth", "principal": "p"},
    ],
)
def test_a_drafter_of_another_shape_is_refused(drafter: dict[str, Any]) -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(drafter=drafter))


@pytest.mark.parametrize(
    "item",
    [
        _item("secret_value", "update", "k", {"v": 1, "secret_ref": "k", "version": 2}),
        _item("vault", "create", "k", {"v": 1}),
        _item("role", "delete", "k", {"v": 1, "role": "r", "principal": "p"}),
    ],
)
def test_an_unknown_kind_or_a_kind_with_another_op_is_refused(item: dict[str, Any]) -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[item]))


@pytest.mark.parametrize(
    "after",
    [
        {"secret_ref": "k", "version": 2},
        {"v": 2, "secret_ref": "k", "version": 2},
        {"v": 1, "secret_ref": "k"},
        {"v": 1, "secret_ref": "k", "version": 2, "value": "x"},
        {"v": 1, "secret_ref": "k", "version": "2"},
        {"v": 1, "secret_ref": "k", "version": 0},
        {"v": 1, "secret_ref": "", "version": 2},
        {"v": True, "secret_ref": "k", "version": 2},
    ],
)
def test_an_after_outside_its_frozen_shape_is_refused(after: dict[str, Any]) -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[_item("secret_value", "create", "k", after)]))


def test_a_value_change_names_the_secret_it_changes() -> None:
    with pytest.raises(ChangeRefused):
        validate_change(
            _change(
                changes=[
                    _item("secret_value", "create", "k", {"v": 1, "secret_ref": "j", "version": 2})
                ]
            )
        )


@pytest.mark.parametrize(
    "item",
    [
        _item(
            "approver",
            "create",
            "ops-approver",
            {
                "v": 1,
                "approver_ref": "ops-approver",
                "contact": "ops@acme.com",
                "covers": ["payments-live"],
                "principal": None,
            },
        ),
        _item(
            "approver_contact",
            "update",
            "ops-approver",
            {"v": 1, "approver_ref": "ops-approver", "contact": "ops2@acme.com"},
        ),
        _item(
            "role",
            "create",
            "secrets.owner",
            {"v": 1, "role": "secrets.owner", "principal": DID_AW},
        ),
        _item(
            "reenable",
            "enable",
            "payments-live",
            {"v": 1, "target_kind": "secret", "target_ref": "payments-live"},
        ),
    ],
)
def test_each_shape_this_task_owns_is_accepted(item: dict[str, Any]) -> None:
    validate_change(_change(changes=[item]))


def test_reenable_names_only_a_kind_that_can_be_disabled() -> None:
    item = _item("reenable", "enable", "k", {"v": 1, "target_kind": "role", "target_ref": "k"})
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[item]))


@pytest.mark.parametrize("kind", ["secret", "destination", "operation", "job", "runner", "grant"])
def test_a_kind_whose_shape_is_not_frozen_yet_is_refused(kind: str) -> None:
    op = "create"
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[_item(kind, op, "k", {"v": 1})]))


def test_an_empty_change_set_is_refused() -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[]))


def test_the_same_object_twice_in_one_change_set_is_refused() -> None:
    item = _item("secret_value", "create", "k", {"v": 1, "secret_ref": "k", "version": 2})
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[item, copy.deepcopy(item)]))


@pytest.mark.parametrize(
    "overrides",
    [
        {"v": 2},
        {"type": "aweb.secrets.use-approval"},
        {"base_revision": -1},
        {"base_revision": "7"},
        {"install_generation": 0},
        {"reason": "x" * 1001},
        {"issued_at": "2026-10-20 12:00:00"},
        {"expires_at": "2026-10-20T11:59:59Z"},
        {"change_id": ""},
        {"extra": "field"},
    ],
)
def test_an_envelope_outside_its_frozen_shape_is_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(**overrides))


def test_a_missing_envelope_field_is_refused() -> None:
    change = _change()
    del change["reason"]
    with pytest.raises(ChangeRefused):
        validate_change(change)


def test_received_json_with_a_float_or_a_duplicate_key_is_refused() -> None:
    raw = json.dumps(_change())
    with pytest.raises(ChangeRefused):
        parse_change(raw.replace('"base_revision": 7', '"base_revision": 7.0').encode())
    with pytest.raises(ChangeRefused):
        parse_change(raw.replace('"v": 1,', '"v": 1, "v": 1,', 1).encode())


def test_parsing_received_json_validates_it() -> None:
    assert parse_change(json.dumps(_change()).encode()) == _change()
    with pytest.raises(ChangeRefused):
        parse_change(json.dumps(_change(changes=[])).encode())


def test_the_covered_bytes_carry_b2s_prefix_and_change_with_any_field() -> None:
    covered = covered_bytes(_change(), POLICY)
    assert covered.startswith(b"aweb.approval-request/1\n")
    assert covered != covered_bytes(_change(base_revision=8), POLICY)
    assert covered != covered_bytes(_change(), {"ref": "change-policy", "version": 2})


def test_covered_bytes_refuse_a_malformed_change() -> None:
    with pytest.raises(ChangeRefused):
        covered_bytes(_change(changes=[]), POLICY)


def test_a_change_drafted_against_the_current_revision_can_be_confirmed() -> None:
    _confirm(_change(), current_revision=7, now=ISSUED)


def test_a_change_drafted_against_an_earlier_revision_is_refused() -> None:
    with pytest.raises(ChangeRefused) as refused:
        _confirm(_change(), current_revision=8, now=ISSUED)
    assert refused.value.code == "base_revision_stale"


def test_an_expired_change_is_refused() -> None:
    with pytest.raises(ChangeRefused) as refused:
        _confirm(_change(), current_revision=7, now=datetime(2026, 10, 20, 12, 15, tzinfo=UTC))
    assert refused.value.code == "change_expired"


def test_only_a_secret_is_widened_by_update() -> None:
    assert {kind: set(ops) for kind, ops in KINDS.items()} == {
        "change_set_policy": {"update"},
        "secret": {"create", "update"},
        "secret_value": {"create"},
        "destination": {"create"},
        "operation": {"create"},
        "job": {"create", "update"},
        "runner": {"create", "update"},
        "grant": {"create"},
        "role": {"create"},
        "approver": {"create"},
        "approver_contact": {"update"},
        "policy": {"create"},
        "reenable": {"enable"},
    }


@pytest.mark.parametrize("role", ["secrets.owner", "secrets.role.deployers", "secrets.role.a_1-b"])
def test_a_role_is_the_owner_or_a_named_user_role(role: str) -> None:
    item = _item("role", "create", role, {"v": 1, "role": role, "principal": DID_KEY})
    validate_change(_change(changes=[item]))


@pytest.mark.parametrize(
    "role",
    [
        "owner",
        "secrets.approver",
        "secrets.role.",
        "secrets.role.Deployers",
        "secrets.role._x",
        "secrets.role." + "a" * 116,
    ],
)
def test_any_other_role_name_is_refused(role: str) -> None:
    item = _item("role", "create", role, {"v": 1, "role": role, "principal": DID_KEY})
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[item]))


@pytest.mark.parametrize("principal", ["alice", "did:web:acme.com", "did:aw:", "did:key:"])
def test_a_role_goes_only_to_a_did_aw_or_did_key_principal(principal: str) -> None:
    item = _item(
        "role", "create", "secrets.owner", {"v": 1, "role": "secrets.owner", "principal": principal}
    )
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[item]))


@pytest.mark.parametrize("principal", [None, DID_AW, "alice"])
def test_an_approver_links_to_no_principal_or_a_did(principal: str | None) -> None:
    after = {
        "v": 1,
        "approver_ref": "ops",
        "contact": "ops@acme.com",
        "covers": ["payments-live"],
        "principal": principal,
    }
    item = _item("approver", "create", "ops", after)
    if principal == "alice":
        with pytest.raises(ChangeRefused):
            validate_change(_change(changes=[item]))
    else:
        validate_change(_change(changes=[item]))


@pytest.mark.parametrize(
    "current",
    [
        {"installation_id": "inst_2"},
        {"install_generation": 2},
        {"team_id": "backend:other.com"},
    ],
)
def test_a_change_for_another_installation_generation_or_team_is_refused(
    current: dict[str, Any],
) -> None:
    with pytest.raises(ChangeRefused) as refused:
        _confirm(_change(), current_revision=7, now=ISSUED, **current)
    assert refused.value.code == "change_wrong_installation"


@pytest.mark.parametrize(
    "timestamp",
    [
        "２026-10-20T12:00:00Z",
        "\u0662026-10-20T12:00:00Z",
        "2026-10-20T12:00:00.5Z",
        "2026-02-30T12:00:00Z",
    ],
)
def test_a_timestamp_outside_ascii_utc_seconds_is_refused(timestamp: str) -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(issued_at=timestamp))


def test_a_change_set_lives_at_most_seven_days() -> None:
    validate_change(_change(expires_at="2026-10-27T12:00:00Z"))
    with pytest.raises(ChangeRefused):
        validate_change(_change(expires_at="2026-10-27T12:00:01Z"))


@pytest.mark.parametrize(
    "principal",
    [
        DID_AW + "\u200b",
        "did:aw:\u200b" + DID_AW[7:],
        DID_KEY.replace("z6Mk", "z6M\u202ek"),
        DID_AW[:-1],
        DID_KEY[:-1],
        "did:aw:" + "1" * 300,
        "did:key:" + DID_KEY[9:],
        "did:aw:0OIl",
    ],
)
def test_every_principal_field_takes_only_an_exact_did(principal: str) -> None:
    role = _item(
        "role", "create", "secrets.owner", {"v": 1, "role": "secrets.owner", "principal": principal}
    )
    approver = _item(
        "approver",
        "create",
        "ops",
        {
            "v": 1,
            "approver_ref": "ops",
            "contact": "o@a.com",
            "covers": ["k"],
            "principal": principal,
        },
    )
    for change in (
        _change(changes=[role]),
        _change(changes=[approver]),
        _change(drafter=_member(principal=principal)),
        _change(drafter=_member(did_aw=principal)),
        _change(drafter=_member(member_did_key=principal, principal=principal)),
    ):
        with pytest.raises(ChangeRefused):
            validate_change(change)


def test_a_member_did_key_must_be_a_did_key() -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(drafter=_member(member_did_key=DID_AW, principal=DID_AW)))


@pytest.mark.parametrize(
    "drafter",
    [
        {"did_aw": DID_AW, "principal": DID_KEY},
        {"principal": DID_AW},
        {"principal": OTHER_DID_KEY},
    ],
)
def test_a_drafter_principal_is_its_did_aw_else_its_did_key(drafter: dict[str, Any]) -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(drafter=_member(**drafter)))


# Four eyes for change sets (decision 61)


def _relax_four_eyes(ref: str = "inst_1", distinct_approver: str = "not_required") -> dict:
    return _item(
        "change_set_policy",
        "update",
        ref,
        {"v": 1, "distinct_approver": distinct_approver},
    )


def test_a_change_set_may_relax_four_eyes_for_its_installation() -> None:
    validate_change(_change(changes=[_relax_four_eyes()]))


def test_a_change_set_never_carries_requiring_four_eyes() -> None:
    # Requiring four eyes narrows, so it is applied directly, never confirmed.
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[_relax_four_eyes(distinct_approver="required")]))


def test_the_four_eyes_setting_belongs_to_the_change_sets_installation() -> None:
    with pytest.raises(ChangeRefused):
        validate_change(_change(changes=[_relax_four_eyes(ref="inst_2")]))


def test_while_four_eyes_is_required_the_drafter_cannot_confirm() -> None:
    member = _change(drafter=_member())
    with pytest.raises(ChangeRefused) as refused:
        check_confirmer(member, distinct_approver="required", confirmer=DID_KEY)
    assert refused.value.code == "distinct_approver_required"
    check_confirmer(member, distinct_approver="required", confirmer=OTHER_DID_KEY)
    check_confirmer(member, distinct_approver="not_required", confirmer=DID_KEY)


def test_a_console_drafter_is_compared_by_the_principal_behind_its_scope() -> None:
    console = _change()
    with pytest.raises(ChangeRefused):
        check_confirmer(
            console, distinct_approver="required", confirmer=DID_KEY, drafter_principal=DID_KEY
        )
    check_confirmer(
        console, distinct_approver="required", confirmer=OTHER_DID_KEY, drafter_principal=DID_KEY
    )


def test_an_unknown_four_eyes_setting_is_refused() -> None:
    with pytest.raises(ValueError):
        check_confirmer(_change(), distinct_approver="sometimes", confirmer=DID_KEY)

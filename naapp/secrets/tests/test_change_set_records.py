"""Confirmed change sets write secrets' own records (S8's), on real PostgreSQL.

A secret and its first value arrive in one change set; a value replaces the
last one, destroying it in the same transaction (design §6.2); destinations,
operations, grants, grant templates and policies are each built from their
record v1 and stored through S8.
"""

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from aweb_naapp.egress import InternalDestinations
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import records
from aweb_secrets.change import ChangeRefused
from aweb_secrets.change_sets import ChangeSets, DraftLimit
from aweb_secrets.custody import CustodyUnavailable
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy
from tests.test_change_sets import (  # noqa: F401
    ALICE,
    BOB,
    CAROL,
    SECRET,
    SECRET_ID,
    TEAM,
    World,
    by_member,
    change_set,
    decide,
    draft,
    enrol_owner,
    sealed_value,
    secret_value,
    world,
)
from tests.test_change_sets import confirm as confirm_change
from tests.test_grant_record import TEMPLATE, USE
from tests.test_operation_record import REFUND

DESTINATION = {
    "v": 1,
    "destination_id": "dst_charges01",
    "secret_id": SECRET_ID,
    "scheme": "https",
    "host": "api.payments.example",
    "port": 443,
    "path": "/v1/charges/**",
    "methods": ["GET", "POST"],
    "query_rules": {"expand": {"presence": "optional", "repeatable": False}},
    "header_allow": ["accept", "idempotency-key"],
    "network": "public",
    "cidr": None,
}
POLICY_BODY = {
    "approval": "none",
    "approvers": [],
    "approval_ttl_s": 900,
    "rate": [],
    "windows": None,
    "operations": [],
    "open_request": True,
    "request": {"max_bytes": 65536},
    "result": {"max_bytes": 65536},
    "requires_attestation": None,
    "distinct_approver": "not_required",
}


def grant_after() -> dict[str, Any]:
    """S8's sample use grant, to Carol, open-request only, under ``POLICY_BODY``."""
    return {
        **USE,
        "subject": {"principal": CAROL.principal_did},
        "operations": [],
        "open_request": True,
        "policy_digest": Policy.from_body(POLICY_BODY).digest,
    }


def item(kind: str, op: str, ref: str, after: dict[str, Any]) -> dict[str, Any]:
    return {"kind": kind, "op": op, "ref": ref, "after": after}


async def confirmed(world: World, changes: list[dict[str, Any]], sealed_values=(), base=0) -> None:  # noqa: F811
    change = change_set(drafter=by_member(CAROL), changes=changes, base_revision=base)
    await decide(world, await draft(world, change, sealed_values), "alice@acme.com")
    await confirm_change(world, change)


async def stored_secret(world: World) -> records.StoredSecret | None:  # noqa: F811
    async with world.db.transaction() as tx:
        return await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, "payments-live")


async def test_a_secret_and_its_first_value_arrive_together(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world, b"first")
    await confirmed(
        world,
        [item("secret", "create", "payments-live", SECRET), secret_value(first.version)],
        [first],
    )
    stored = await stored_secret(world)
    assert stored is not None and stored.active_version == first.version
    assert (await world.custody.opener.open(first)).reveal() == b"first"


async def test_a_new_value_replaces_and_destroys_the_old_one(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world, b"first")
    await confirmed(
        world,
        [item("secret", "create", "payments-live", SECRET), secret_value(first.version)],
        [first],
    )
    second = await sealed_value(world, b"second")
    await confirmed(world, [secret_value(second.version)], [second], base=1)
    stored = await stored_secret(world)
    assert stored is not None and stored.active_version == second.version
    with pytest.raises(CustodyUnavailable):
        await world.custody.opener.open(first)


async def test_a_value_change_set_must_carry_exactly_its_sealed_values(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    missing = change_set(
        drafter=by_member(CAROL),
        changes=[item("secret", "create", "payments-live", SECRET), secret_value(first.version)],
    )
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, missing)
    assert refused.value.code == "sealed_value_missing"
    unbound = change_set(
        drafter=by_member(CAROL), changes=[item("secret", "create", "payments-live", SECRET)]
    )
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, unbound, [first])
    assert refused.value.code == "sealed_value_unbound"


async def test_a_value_for_an_unknown_secret_is_refused_at_draft(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    with pytest.raises(ChangeRefused) as refused:
        await draft(
            world,
            change_set(drafter=by_member(CAROL), changes=[secret_value(first.version)]),
            [first],
        )
    assert refused.value.code == "secret_unknown"


async def test_a_destination_grant_and_policy_are_stored(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    policy = Policy.from_body(POLICY_BODY)
    grant = grant_after()
    first = await sealed_value(world)
    await confirmed(
        world,
        [
            item("secret", "create", "payments-live", SECRET),
            secret_value(first.version),
            item("destination", "create", "dst_charges01", DESTINATION),
            item("policy", "create", policy.digest, {"v": 1, **POLICY_BODY}),
            item("grant", "create", "grt_77c1aa", grant),
        ],
        [first],
    )
    async with world.db.transaction() as tx:
        assert [
            d.destination_id for d in await records.destinations(tx, INSTALLATION_ID, SECRET_ID)
        ] == ["dst_charges01"]
        grants = await records.active_grants(
            tx, INSTALLATION_ID, SECRET_ID, principal_did=CAROL.principal_did, roles=[]
        )
    assert [g.grant_id for g in grants] == ["grt_77c1aa"]


INTERNAL = {
    **DESTINATION,
    "host": "10.0.4.7",
    "path": "/v1/**",
    "network": "internal",
    "cidr": "10.0.4.0/24",
}


async def test_an_internal_destination_needs_the_deploy_to_allow_it(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    changes = [
        item("secret", "create", "payments-live", SECRET),
        secret_value(first.version),
        item("destination", "create", "dst_charges01", INTERNAL),
    ]
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, change_set(drafter=by_member(CAROL), changes=changes), [first])
    assert refused.value.code == "internal_destinations_disabled"


async def test_an_internal_destination_drafted_while_allowed_is_refused_once_disabled(
    world: World,  # noqa: F811
) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    allowing = replace(
        world,
        change_sets=ChangeSets(
            world.db,
            approvals=world.approvals,
            passkeys=world.passkeys,
            directory=world.directory,
            custody=world.custody,
            draft_limit=DraftLimit(count=2, window=timedelta(hours=1)),
            internal_destinations=InternalDestinations.ALLOWED,
        ),
    )
    first = await sealed_value(world)
    change = change_set(
        drafter=by_member(CAROL),
        changes=[
            item("secret", "create", "payments-live", SECRET),
            secret_value(first.version),
            item("destination", "create", "dst_charges01", INTERNAL),
        ],
    )
    await decide(world, await draft(allowing, change, [first]), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, change)
    assert refused.value.code == "internal_destinations_disabled"
    assert await stored_secret(world) is None


async def test_an_unprojected_operation_on_a_sensitive_secret_is_refused(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    sensitive = {**SECRET, "sensitivity": "sensitive"}
    unprojected = copy.deepcopy(REFUND)
    unprojected["response"]["projection"] = None
    change = change_set(
        drafter=by_member(CAROL),
        changes=[
            item("secret", "create", "payments-live", sensitive),
            secret_value(first.version),
            item("operation", "create", "refund", unprojected),
        ],
    )
    await decide(world, await draft(world, change, [first]), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, change)
    assert refused.value.code == "operation_not_allowed"


async def test_an_operation_becomes_the_current_one(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    await confirmed(
        world,
        [
            item("secret", "create", "payments-live", SECRET),
            secret_value(first.version),
            item("operation", "create", "refund", REFUND),
        ],
        [first],
    )
    async with world.db.transaction() as tx:
        current = await records.current_operation(tx, INSTALLATION_ID, SECRET_ID, "refund")
    assert current is not None
    assert current.digest == OperationTemplate.from_after(REFUND).digest


async def test_a_grant_needs_its_policy(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    change = change_set(
        drafter=by_member(CAROL),
        changes=[
            item("secret", "create", "payments-live", SECRET),
            secret_value(first.version),
            item("grant", "create", "grt_77c1aa", grant_after()),
        ],
    )
    await decide(world, await draft(world, change, [first]), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, change)
    assert refused.value.code == "record_missing"


async def test_a_grant_template_is_created_then_updated(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    await confirmed(world, [item("grant_template", "create", "gtp_sts-derived", TEMPLATE)])
    updated = {**TEMPLATE, "subject": {"role": "secrets.role.operators"}}
    await confirmed(world, [item("grant_template", "update", "gtp_sts-derived", updated)], base=1)
    async with world.db.transaction() as tx:
        stored = await records.grant_template(tx, INSTALLATION_ID, "gtp_sts-derived")
    assert stored is not None and stored.after == updated
    again = change_set(
        drafter=by_member(BOB),
        changes=[item("grant_template", "create", "gtp_sts-derived", TEMPLATE)],
        base_revision=2,
    )
    await decide(world, await draft(world, again), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, again)
    assert refused.value.code == "record_exists"


@pytest.mark.parametrize("secret_id", [SECRET_ID, "sec_other01"])
async def test_a_secret_id_or_ref_is_created_once(world: World, secret_id: str) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    await confirmed(
        world,
        [item("secret", "create", "payments-live", SECRET), secret_value(first.version)],
        [first],
    )
    again = change_set(
        drafter=by_member(CAROL),
        changes=[item("secret", "create", "payments-live", {**SECRET, "secret_id": secret_id})],
        base_revision=1,
    )
    await decide(world, await draft(world, again), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, again)
    assert refused.value.code == "record_exists"


async def test_a_destination_for_a_secret_the_team_does_not_hold_is_refused(
    world: World,  # noqa: F811
) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(
        drafter=by_member(CAROL),
        changes=[item("destination", "create", "dst_charges01", DESTINATION)],
    )
    await decide(world, await draft(world, change), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, change)
    assert refused.value.code == "record_missing"


@pytest.mark.parametrize("kind", ["destination", "grant"])
async def test_creating_a_destination_or_grant_twice_is_refused(world: World, kind: str) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    policy = Policy.from_body(POLICY_BODY)
    first = await sealed_value(world)
    created = {
        "destination": item("destination", "create", "dst_charges01", DESTINATION),
        "grant": item("grant", "create", "grt_77c1aa", grant_after()),
    }[kind]
    await confirmed(
        world,
        [
            item("secret", "create", "payments-live", SECRET),
            secret_value(first.version),
            item("policy", "create", policy.digest, {"v": 1, **POLICY_BODY}),
            created,
        ],
        [first],
    )
    again = change_set(drafter=by_member(BOB), changes=[created], base_revision=1)
    await decide(world, await draft(world, again), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, again)
    assert refused.value.code == "record_exists"


async def test_a_secret_update_replaces_its_record(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = await sealed_value(world)
    await confirmed(
        world,
        [item("secret", "create", "payments-live", SECRET), secret_value(first.version)],
        [first],
    )
    described = {**SECRET, "description": "Live payments key, rotated quarterly"}
    await confirmed(world, [item("secret", "update", "payments-live", described)], base=1)
    stored = await stored_secret(world)
    assert stored is not None
    assert stored.record.after == described
    assert stored.active_version == first.version


async def test_a_secret_update_cannot_take_another_secrets_ref(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    other = {**SECRET, "secret_id": "sec_other01", "ref": "payments-test"}
    await confirmed(
        world,
        [
            item("secret", "create", "payments-live", SECRET),
            item("secret", "create", "payments-test", other),
        ],
    )
    renamed = change_set(
        drafter=by_member(BOB),
        changes=[item("secret", "update", "payments-live", {**other, "ref": "payments-live"})],
        base_revision=1,
    )
    await decide(world, await draft(world, renamed), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, renamed)
    assert refused.value.code == "record_exists"


async def test_updating_an_unknown_secret_is_refused(world: World) -> None:  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(
        drafter=by_member(CAROL), changes=[item("secret", "update", "payments-live", SECRET)]
    )
    await decide(world, await draft(world, change), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm_change(world, change)
    assert refused.value.code == "record_missing"

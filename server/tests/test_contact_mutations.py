"""Native contact acceptance and owner transfer use the real storage owner."""

from uuid import UUID

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key, stable_id_from_did_key
from aweb.db import TransactionInfra
from aweb.messaging.contacts import (
    add_contact,
    add_handle_contact,
    ensure_identity_contact,
    transfer_contacts,
)
from aweb.service_errors import ConflictError


def _identity():
    key = did_from_public_key(bytes(SigningKey.generate().verify_key))
    return key, stable_id_from_did_key(key)


async def _rows(db):
    return [
        dict(row)
        for row in await db.fetch_all(
            "SELECT * FROM {{tables.contacts}} ORDER BY contact_id"
        )
    ]


@pytest.mark.asyncio
async def test_retry_preserves_complete_existing_acceptance(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    controller, did = _identity()
    owner = _identity()[1]
    arguments = dict(
        owner_did=owner,
        contact_address="example.test/member",
        contact_did_aw=did,
        binding_controller_did=controller,
        label="Original label",
    )
    first = await add_contact(TransactionInfra(None, db), **arguments, status="pending")
    before = await _rows(db)
    # Same identity under a new resolving controller cannot rewrite acceptance.
    repeated = await ensure_identity_contact(
        db=db,
        **{
            **arguments,
            "binding_controller_did": _identity()[0],
            "label": "New label",
        },
    )
    assert repeated["contact_id"] == first["contact_id"]
    assert repeated["binding_controller_did"] == controller
    assert repeated["binding_accepted_at"] == first["binding_accepted_at"]
    assert repeated["status"] == "pending"
    assert repeated["label"] == "Original label"
    assert await _rows(db) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy", [True, False])
async def test_existing_contact_requires_explicit_binding_acceptance(
    aweb_cloud_db, legacy
):
    db = aweb_cloud_db.aweb_db
    controller, old_did = _identity()
    owner = _identity()[1]
    await add_contact(
        TransactionInfra(None, db),
        owner_did=owner,
        contact_address="example.test/member",
        label="Keep me",
        status="pending",
        contact_did_aw=None if legacy else old_did,
        binding_controller_did=None if legacy else controller,
    )
    before = await _rows(db)
    with pytest.raises(ConflictError) as refused:
        await ensure_identity_contact(
            db=db,
            owner_did=owner,
            contact_address="example.test/member",
            contact_did_aw=_identity()[1],
            binding_controller_did=controller,
        )
    assert refused.value.detail["code"] == "contact_identity_binding_required"
    assert refused.value.detail["message"].endswith(
        "Use the contact's explicit bind operation before retrying."
    )
    assert await _rows(db) == before


@pytest.mark.asyncio
async def test_reciprocal_contacts_share_caller_transaction(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    controller, left = _identity()
    right = _identity()[1]
    with pytest.raises(RuntimeError, match="host counter failed"):
        async with db.transaction() as tx:
            for owner, target, address in [
                (left, right, "example.test/right"),
                (right, left, "example.test/left"),
            ]:
                await ensure_identity_contact(
                    db=tx,
                    owner_did=owner,
                    contact_address=address,
                    contact_did_aw=target,
                    binding_controller_did=controller,
                )
            raise RuntimeError("host counter failed")
    assert await _rows(db) == []


@pytest.mark.asyncio
async def test_transfer_prefers_bound_then_target_and_preserves_survivors(
    aweb_cloud_db,
):
    db = aweb_cloud_db.aweb_db
    old, target = _identity()[1], _identity()[1]
    controller, did = _identity()
    old_bound = await add_contact(
        TransactionInfra(None, db),
        owner_did=old,
        contact_address="example.test/bound",
        contact_did_aw=did,
        binding_controller_did=controller,
        label="Source bound",
        status="pending",
    )
    await add_contact(
        TransactionInfra(None, db),
        owner_did=target,
        contact_address="example.test/bound",
        label="Unbound target",
    )
    target_bound = await add_contact(
        TransactionInfra(None, db),
        owner_did=target,
        contact_address="example.test/equal",
        contact_did_aw=did,
        binding_controller_did=controller,
        label="Target bound",
        status="pending",
    )
    await add_contact(
        TransactionInfra(None, db),
        owner_did=old,
        contact_address="example.test/equal",
        contact_did_aw=did,
        binding_controller_did=controller,
        label="Other label",
    )
    handle = await add_handle_contact(
        TransactionInfra(None, db),
        owner_did=target,
        handle_namespace="example.test",
        target_agent_name="member",
        label="Target handle",
        status="pending",
    )
    await add_handle_contact(
        TransactionInfra(None, db),
        owner_did=old,
        handle_namespace="example.test",
        target_agent_name="member",
        label="Source handle",
    )
    before = {row["contact_id"]: row for row in await _rows(db)}

    result = await transfer_contacts(
        db=db, old_owner_dids=[old], target_owner_did=target
    )

    assert (result.moved, result.merged) == (1, 3)
    after = await _rows(db)
    expected_ids = {
        UUID(item["contact_id"]) for item in [old_bound, target_bound, handle]
    }
    assert {row["contact_id"] for row in after} == expected_ids
    for row in after:
        assert row == {**before[row["contact_id"]], "owner_did": target}
    retried = await transfer_contacts(
        db=db, old_owner_dids=[old], target_owner_did=target
    )
    assert (retried.moved, retried.merged) == (0, 0)
    assert await _rows(db) == after


@pytest.mark.asyncio
async def test_transfer_checks_every_binding_before_any_merge(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    old, target = _identity()[1], _identity()[1]
    controller = _identity()[0]
    for owner in [old, target]:
        await add_contact(
            TransactionInfra(None, db),
            owner_did=owner,
            contact_address="example.test/merge",
            label=owner,
        )
        await add_contact(
            TransactionInfra(None, db),
            owner_did=owner,
            contact_address="example.test/conflict",
            contact_did_aw=_identity()[1],
            binding_controller_did=controller,
            label=owner,
        )
    before = await _rows(db)
    with pytest.raises(ConflictError) as refused:
        await transfer_contacts(db=db, old_owner_dids=[old], target_owner_did=target)
    assert refused.value.detail["code"] == "contact_transfer_binding_conflict"
    assert refused.value.detail["message"].endswith(
        "Resolve the conflicting contact bindings explicitly before retrying the transfer."
    )
    assert await _rows(db) == before

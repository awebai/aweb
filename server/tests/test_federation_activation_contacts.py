from __future__ import annotations

import pytest

from aweb.messaging.contacts import (
    add_contact,
    bind_contact_identity,
    has_exact_active_identity_contact,
)
from aweb.service_errors import ConflictError


class _DB:
    def __init__(self, manager) -> None:
        self.manager = manager

    def get_manager(self, _name="aweb"):
        return self.manager


@pytest.mark.asyncio
async def test_address_only_contact_is_inert_until_identity_bound(aweb_cloud_db) -> None:
    db = _DB(aweb_cloud_db.aweb_db)
    await add_contact(
        db,
        owner_did="did:aw:owner",
        contact_address="alpha.example/alice",
        label="Alice",
    )

    assert not await has_exact_active_identity_contact(
        db,
        owner_dids=["did:aw:owner"],
        contact_address="alpha.example/alice",
        contact_did_aw="did:aw:alice",
    )


@pytest.mark.asyncio
async def test_contact_authority_requires_exact_address_and_stable_identity(aweb_cloud_db) -> None:
    db = _DB(aweb_cloud_db.aweb_db)
    await add_contact(
        db,
        owner_did="did:aw:owner",
        contact_address="alpha.example/alice",
        contact_did_aw="did:aw:alice",
        binding_controller_did="did:key:z6Mkcontroller",
        label="Alice",
    )

    assert await has_exact_active_identity_contact(
        db,
        owner_dids=["did:aw:owner"],
        contact_address="alpha.example/alice",
        contact_did_aw="did:aw:alice",
    )
    assert not await has_exact_active_identity_contact(
        db,
        owner_dids=["did:aw:owner"],
        contact_address="alpha.example/alice",
        contact_did_aw="did:aw:replacement",
    )
    assert not await has_exact_active_identity_contact(
        db,
        owner_dids=["did:aw:owner"],
        contact_address="alpha.example/mallory",
        contact_did_aw="did:aw:alice",
    )


@pytest.mark.asyncio
async def test_contact_binding_requires_explicit_cas_for_reassignment(aweb_cloud_db) -> None:
    db = _DB(aweb_cloud_db.aweb_db)
    contact = await add_contact(
        db,
        owner_did="did:aw:owner",
        contact_address="alpha.example/alice",
        label="Alice",
    )
    await bind_contact_identity(
        db,
        owner_dids=["did:aw:owner"],
        contact_id=contact["contact_id"],
        contact_address="alpha.example/alice",
        expected_old_did_aw=None,
        contact_did_aw="did:aw:alice",
        controller_did="did:key:z6Mkcontroller",
        replacement_accepted=False,
    )

    with pytest.raises(ConflictError, match="explicit acceptance"):
        await bind_contact_identity(
            db,
            owner_dids=["did:aw:owner"],
            contact_id=contact["contact_id"],
            contact_address="alpha.example/alice",
            expected_old_did_aw="did:aw:alice",
            contact_did_aw="did:aw:replacement",
            controller_did="did:key:z6Mkcontroller",
            replacement_accepted=False,
        )

    await bind_contact_identity(
        db,
        owner_dids=["did:aw:owner"],
        contact_id=contact["contact_id"],
        contact_address="alpha.example/alice",
        expected_old_did_aw="did:aw:alice",
        contact_did_aw="did:aw:replacement",
        controller_did="did:key:z6Mkcontroller",
        replacement_accepted=True,
    )
    assert await has_exact_active_identity_contact(
        db,
        owner_dids=["did:aw:owner"],
        contact_address="alpha.example/alice",
        contact_did_aw="did:aw:replacement",
    )


@pytest.mark.asyncio
async def test_contact_binding_cannot_substitute_another_address(aweb_cloud_db) -> None:
    db = _DB(aweb_cloud_db.aweb_db)
    contact = await add_contact(
        db,
        owner_did="did:aw:owner",
        contact_address="alpha.example/alice",
        label="Alice",
    )

    with pytest.raises(ConflictError):
        await bind_contact_identity(
            db,
            owner_dids=["did:aw:owner"],
            contact_id=contact["contact_id"],
            contact_address="alpha.example/mallory",
            expected_old_did_aw=None,
            contact_did_aw="did:aw:mallory",
            controller_did="did:key:z6Mkcontroller",
            replacement_accepted=False,
        )

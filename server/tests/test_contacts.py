"""Tests for the contacts service layer against the identity-owned schema."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aweb.messaging.contacts import (
    add_contact,
    add_handle_contact,
    get_contact_addresses,
    is_address_in_contacts,
    list_contacts,
    remove_contact,
    resolve_handle_contact_agent,
)
from aweb.service_errors import ConflictError, ValidationError


class _DbShim:
    """Minimal shim matching the db.get_manager() interface."""

    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


@pytest.mark.asyncio
async def test_add_and_list_contacts(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-alice"

    result = await add_contact(
        db_shim,
        owner_did=owner_did,
        contact_address="example.com/alice",
        label="Alice at Example",
    )

    assert result["contact_address"] == "example.com/alice"
    assert result["label"] == "Alice at Example"
    assert result["contact_id"]

    contacts = await list_contacts(db_shim, owner_did=owner_did)
    assert len(contacts) == 1
    assert contacts[0]["contact_address"] == "example.com/alice"
    assert contacts[0]["reference_type"] == "identity"
    assert contacts[0]["status"] == "active"


@pytest.mark.asyncio
async def test_add_contact_normalizes_hosted_handle_address(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-hosted-handle"

    result = await add_contact(
        db_shim,
        owner_did=owner_did,
        contact_address="@jane/c3po",
        label="C-3PO",
    )

    assert result["contact_address"] == "jane.aweb.ai/c3po"


@pytest.mark.asyncio
async def test_add_duplicate_contact_raises(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-bob"

    await add_contact(
        db_shim, owner_did=owner_did, contact_address="example.com/bob", label=""
    )

    with pytest.raises(ConflictError, match="already exists"):
        await add_contact(
            db_shim, owner_did=owner_did, contact_address="example.com/bob", label=""
        )


@pytest.mark.asyncio
async def test_remove_contact(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-carol"

    result = await add_contact(
        db_shim, owner_did=owner_did, contact_address="example.com/carol", label=""
    )
    contact_id = result["contact_id"]

    await remove_contact(db_shim, owner_did=owner_did, contact_id=contact_id)

    contacts = await list_contacts(db_shim, owner_did=owner_did)
    assert len(contacts) == 0


@pytest.mark.asyncio
async def test_get_contact_addresses(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-dave"

    await add_contact(
        db_shim, owner_did=owner_did, contact_address="example.com", label=""
    )
    await add_contact(
        db_shim, owner_did=owner_did, contact_address="other.org/dave", label=""
    )

    addrs = await get_contact_addresses(db_shim, owner_did=owner_did)
    assert addrs == {"example.com", "other.org/dave"}


@pytest.mark.asyncio
async def test_existing_contacts_backfill_identity_active_and_remain_queryable(
    aweb_cloud_db,
):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-existing"

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ($1, 'example.com/existing', 'Existing')
        """,
        owner_did,
    )

    contacts = await list_contacts(db_shim, owner_did=owner_did)
    assert contacts == [
        {
            "contact_id": contacts[0]["contact_id"],
            "contact_address": "example.com/existing",
            "contact_did_aw": None,
            "binding_controller_did": None,
            "binding_accepted_at": None,
            "label": "Existing",
            "created_at": contacts[0]["created_at"],
            "reference_type": "identity",
            "status": "active",
            "handle_namespace": None,
            "target_agent_name": None,
        }
    ]
    assert await get_contact_addresses(db_shim, owner_did=owner_did) == {
        "example.com/existing"
    }


@pytest.mark.asyncio
async def test_add_and_list_handle_contact(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-handle"

    result = await add_handle_contact(
        db_shim,
        owner_did=owner_did,
        handle_namespace="@acme.com",
        target_agent_name="alice",
        label="Alice handle",
    )

    assert result["reference_type"] == "handle"
    assert result["status"] == "pending"
    assert result["contact_address"] is None
    assert result["handle_namespace"] == "acme.com"
    assert result["target_agent_name"] == "alice"

    contacts = await list_contacts(db_shim, owner_did=owner_did)
    assert len(contacts) == 1
    assert contacts[0]["handle_namespace"] == "acme.com"
    assert contacts[0]["target_agent_name"] == "alice"


@pytest.mark.asyncio
async def test_add_handle_contact_normalizes_hosted_handle_namespace(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-hosted-handle-contact"

    result = await add_handle_contact(
        db_shim,
        owner_did=owner_did,
        handle_namespace="@jane",
        target_agent_name="c3po",
        label="C-3PO",
    )

    assert result["reference_type"] == "handle"
    assert result["handle_namespace"] == "jane.aweb.ai"
    assert result["target_agent_name"] == "c3po"


@pytest.mark.asyncio
async def test_add_handle_contact_rejects_bad_hosted_handle_namespace(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-bad-hosted-handle"

    with pytest.raises(ValidationError, match="Invalid handle_namespace format"):
        await add_handle_contact(
            db_shim,
            owner_did=owner_did,
            handle_namespace="@jane..aweb.ai",
            target_agent_name="c3po",
            label="Broken",
        )


@pytest.mark.asyncio
async def test_handle_and_identity_contacts_coexist(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-mixed"

    await add_contact(
        db_shim, owner_did=owner_did, contact_address="acme.com/alice", label="Alice"
    )
    await add_handle_contact(
        db_shim, owner_did=owner_did, handle_namespace="acme.com", label="Acme"
    )

    contacts = await list_contacts(db_shim, owner_did=owner_did)
    assert {
        (c["reference_type"], c["contact_address"], c["handle_namespace"])
        for c in contacts
    } == {
        ("identity", "acme.com/alice", None),
        ("handle", None, "acme.com"),
    }


@pytest.mark.asyncio
async def test_pending_contact_does_not_satisfy_contacts_policy_until_active(
    aweb_cloud_db,
):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-policy"

    await add_contact(
        db_shim,
        owner_did=owner_did,
        contact_address="acme.com/alice",
        label="Alice",
        status="pending",
    )
    assert await get_contact_addresses(db_shim, owner_did=owner_did) == set()

    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.contacts}}
        SET status = 'active'
        WHERE owner_did = $1
        """,
        owner_did,
    )
    assert await get_contact_addresses(db_shim, owner_did=owner_did) == {
        "acme.com/alice"
    }


async def _handle_team(db):
    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('default:acme.com', 'acme.com', 'default', 'did:key:team')
        """
    )


async def _handle_agent(db, alias, created_at, last_seen_at=None):
    row = await db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, identity_scope, role, created_at, inbound_mode
        )
        VALUES ('default:acme.com', $1, $2, $3, $4, 'global', 'developer', $5, 'open')
        RETURNING agent_id
        """,
        f"did:key:{alias}",
        f"did:aw:{alias}",
        f"acme.com/{alias}",
        alias,
        created_at,
    )
    await db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE agent_id=$1",
        row["agent_id"],
    )
    if last_seen_at is not None:
        await db.execute(
            "INSERT INTO {{tables.workspaces}} (team_id, agent_id, alias, last_seen_at) "
            "VALUES ('default:acme.com', $1, $2, $3)",
            row["agent_id"],
            alias,
            last_seen_at,
        )


@pytest.mark.asyncio
async def test_handle_contact_default_agent_resolution_uses_recent_activity(
    aweb_cloud_db,
):
    db = aweb_cloud_db.aweb_db
    await _handle_team(db)
    await _handle_agent(
        db,
        "older",
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    await _handle_agent(
        db,
        "recent",
        datetime(2026, 1, 2, tzinfo=timezone.utc),
        datetime(2026, 5, 2, tzinfo=timezone.utc),
    )

    db_shim = _DbShim(db)
    resolved = await resolve_handle_contact_agent(db_shim, handle_namespace="acme.com")
    assert resolved is not None
    assert resolved["address"] == "acme.com/recent"

    named = await resolve_handle_contact_agent(
        db_shim,
        handle_namespace="acme.com",
        target_agent_name="older",
    )
    assert named is not None
    assert named["address"] == "acme.com/older"


@pytest.mark.asyncio
async def test_handle_contact_default_agent_puts_inactive_last_and_breaks_ties_by_age(
    aweb_cloud_db,
):
    db = aweb_cloud_db.aweb_db
    await _handle_team(db)
    seen = datetime(2026, 5, 1, tzinfo=timezone.utc)
    await _handle_agent(db, "inactive", datetime(2026, 1, 1, tzinfo=timezone.utc))
    await _handle_agent(db, "younger", datetime(2026, 1, 3, tzinfo=timezone.utc), seen)
    await _handle_agent(db, "elder", datetime(2026, 1, 2, tzinfo=timezone.utc), seen)

    resolved = await resolve_handle_contact_agent(
        _DbShim(db), handle_namespace="acme.com"
    )

    assert resolved is not None
    assert resolved["address"] == "acme.com/elder"


def test_is_address_in_contacts_exact():
    contacts = {"example.com/alice", "other.org"}
    assert is_address_in_contacts("example.com/alice", contacts) is True
    assert is_address_in_contacts("example.com/bob", contacts) is False


def test_is_address_in_contacts_domain_match():
    contacts = {"example.com"}
    assert is_address_in_contacts("example.com/alice", contacts) is True
    assert is_address_in_contacts("other.org/alice", contacts) is False

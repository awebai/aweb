"""Tests for the contacts service layer against the identity-owned schema."""

from __future__ import annotations

import inspect

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
async def test_add_duplicate_contact_raises(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-bob"

    await add_contact(db_shim, owner_did=owner_did, contact_address="example.com/bob", label="")

    with pytest.raises(ConflictError, match="already exists"):
        await add_contact(db_shim, owner_did=owner_did, contact_address="example.com/bob", label="")


@pytest.mark.asyncio
async def test_remove_contact(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-carol"

    result = await add_contact(db_shim, owner_did=owner_did, contact_address="example.com/carol", label="")
    contact_id = result["contact_id"]

    await remove_contact(db_shim, owner_did=owner_did, contact_id=contact_id)

    contacts = await list_contacts(db_shim, owner_did=owner_did)
    assert len(contacts) == 0


@pytest.mark.asyncio
async def test_get_contact_addresses(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-dave"

    await add_contact(db_shim, owner_did=owner_did, contact_address="example.com", label="")
    await add_contact(db_shim, owner_did=owner_did, contact_address="other.org/dave", label="")

    addrs = await get_contact_addresses(db_shim, owner_did=owner_did)
    assert addrs == {"example.com", "other.org/dave"}


@pytest.mark.asyncio
async def test_existing_contacts_backfill_identity_active_and_remain_queryable(aweb_cloud_db):
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
            "label": "Existing",
            "created_at": contacts[0]["created_at"],
            "reference_type": "identity",
            "status": "active",
            "handle_namespace": None,
            "target_agent_name": None,
        }
    ]
    assert await get_contact_addresses(db_shim, owner_did=owner_did) == {"example.com/existing"}


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
async def test_handle_and_identity_contacts_coexist(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    owner_did = "did:aw:owner-mixed"

    await add_contact(db_shim, owner_did=owner_did, contact_address="acme.com/alice", label="Alice")
    await add_handle_contact(db_shim, owner_did=owner_did, handle_namespace="acme.com", label="Acme")

    contacts = await list_contacts(db_shim, owner_did=owner_did)
    assert {(c["reference_type"], c["contact_address"], c["handle_namespace"]) for c in contacts} == {
        ("identity", "acme.com/alice", None),
        ("handle", None, "acme.com"),
    }


@pytest.mark.asyncio
async def test_pending_contact_does_not_satisfy_contacts_policy_until_active(aweb_cloud_db):
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
    assert await get_contact_addresses(db_shim, owner_did=owner_did) == {"acme.com/alice"}


@pytest.mark.asyncio
async def test_handle_contact_default_agent_resolution_uses_recent_activity(aweb_cloud_db):
    assert "ORDER BY last_seen_at DESC NULLS LAST, a.created_at ASC" in inspect.getsource(
        resolve_handle_contact_agent
    )
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('default:acme.com', 'acme.com', 'default', 'did:key:team')
        """
    )
    older = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, created_at
        )
        VALUES (
            'default:acme.com', 'did:key:older', 'did:aw:older',
            'acme.com/older', 'older', 'persistent', 'developer',
            '2026-01-01T00:00:00Z'
        )
        RETURNING agent_id
        """
    )
    recent = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, created_at
        )
        VALUES (
            'default:acme.com', 'did:key:recent', 'did:aw:recent',
            'acme.com/recent', 'recent', 'persistent', 'developer',
            '2026-01-02T00:00:00Z'
        )
        RETURNING agent_id
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (team_id, agent_id, alias, last_seen_at)
        VALUES
            ('default:acme.com', $1, 'older', '2026-05-01T00:00:00Z'),
            ('default:acme.com', $2, 'recent', '2026-05-02T00:00:00Z')
        """,
        older["agent_id"],
        recent["agent_id"],
    )

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


def test_is_address_in_contacts_exact():
    contacts = {"example.com/alice", "other.org"}
    assert is_address_in_contacts("example.com/alice", contacts) is True
    assert is_address_in_contacts("example.com/bob", contacts) is False


def test_is_address_in_contacts_domain_match():
    contacts = {"example.com"}
    assert is_address_in_contacts("example.com/alice", contacts) is True
    assert is_address_in_contacts("other.org/alice", contacts) is False

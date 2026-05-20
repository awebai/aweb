"""Tests for identity-scoped message delivery authorization."""

from __future__ import annotations

import pytest
from pgdbm.errors import QueryError

from nacl.signing import SigningKey

from awid.did import did_from_public_key
from aweb.messaging.contacts import has_exact_active_identity_contact
from aweb.messaging.messages import (
    deliver_message,
    get_agent_by_alias,
    get_agent_by_id,
    resolve_agent_by_did,
)
from aweb.service_errors import ForbiddenError, NotFoundError


def _make_did_key():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    return did_from_public_key(pk)


class _DbShim:
    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


async def _insert_team(aweb_db, team_id: str):
    name, domain = team_id.split(":", 1)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        team_id,
        domain,
        name,
    )


async def _insert_agent(
    aweb_db,
    *,
    team_id: str,
    alias: str,
    did_key: str,
    did_aw: str,
    address: str,
    inbound_mode: str | None = "open",
):
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ($1, $2, $3, $4, $5, 'persistent', 'developer', $6)
        RETURNING agent_id
        """,
        team_id,
        did_key,
        did_aw,
        address,
        alias,
        inbound_mode,
    )
    return str(row["agent_id"])


@pytest.mark.asyncio
async def test_agents_inbound_mode_schema_nullable_no_default_and_constraint(aweb_cloud_db):
    await _insert_team(aweb_cloud_db.aweb_db, "default:example.com")
    agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="default:example.com",
        alias="alice",
        did_key=_make_did_key(),
        did_aw="did:aw:alice-schema",
        address="example.com/alice",
        inbound_mode=None,
    )
    inbound_mode = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT inbound_mode FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    assert inbound_mode is None

    with pytest.raises(QueryError) as invalid_mode:
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.agents}} SET inbound_mode = 'team' WHERE agent_id = $1",
            agent_id,
        )
    assert "agents_inbound_mode_valid" in str(invalid_mode.value)


@pytest.mark.asyncio
async def test_deliver_message_cross_identity_to_contact(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")

    alice_did_key = _make_did_key()
    bob_did_key = _make_did_key()
    alice_did_aw = "did:aw:alice"
    bob_did_aw = "did:aw:bob"

    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw=alice_did_aw,
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        inbound_mode="contacts_only",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ($1, $2, 'Alice')
        """,
        bob_did_aw,
        "acme.com/alice",
    )

    msg_id, created_at = await deliver_message(
        db_shim,
        from_did=alice_did_aw,
        to_did=bob_did_aw,
        from_alias="alice",
        to_alias="bob",
        sender_address="acme.com/alice",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )

    assert msg_id is not None
    assert created_at is not None
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT * FROM {{tables.messages}} WHERE message_id = $1",
        msg_id,
    )
    assert row["from_did"] == alice_did_aw
    assert row["to_did"] == bob_did_aw
    assert row["from_alias"] == "alice"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_deliver_message_rejects_non_contact_sender(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")

    alice_did_aw = "did:aw:alice"
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=_make_did_key(),
        did_aw=alice_did_aw,
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        inbound_mode="contacts_only",
    )

    with pytest.raises(ForbiddenError, match="contacts"):
        await deliver_message(
            db_shim,
            from_did=alice_did_aw,
            to_did=bob_did_aw,
            from_alias="alice",
            to_alias="bob",
            sender_address="acme.com/alice",
            subject="Hello",
            body="Hi Bob!",
            priority="normal",
        )


@pytest.mark.asyncio
async def test_exact_active_identity_contact_helper_is_narrow(aweb_cloud_db):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, label, reference_type, status, handle_namespace, target_agent_name
        )
        VALUES
          ('did:aw:bob', 'acme.com/alice', 'Alice', 'identity', 'active', NULL, NULL),
          ('did:aw:bob', 'example.com', 'Domain', 'identity', 'active', NULL, NULL),
          ('did:aw:bob', 'acme.com/pending', 'Pending', 'identity', 'pending', NULL, NULL),
          ('did:aw:bob', NULL, 'Handle', 'handle', 'active', 'acme.com', 'handle')
        """
    )

    assert await has_exact_active_identity_contact(
        _DbShim(aweb_cloud_db.aweb_db),
        owner_did="did:aw:bob",
        contact_address="acme.com/alice",
    )
    assert not await has_exact_active_identity_contact(
        _DbShim(aweb_cloud_db.aweb_db),
        owner_did="did:aw:bob",
        contact_address="example.com/alice",
    )
    assert not await has_exact_active_identity_contact(
        _DbShim(aweb_cloud_db.aweb_db),
        owner_did="did:aw:bob",
        contact_address="acme.com/pending",
    )
    assert not await has_exact_active_identity_contact(
        _DbShim(aweb_cloud_db.aweb_db),
        owner_did="did:aw:bob",
        contact_address="acme.com/handle",
    )


@pytest.mark.asyncio
async def test_deliver_message_inbound_mode_open_allows_unconnected_sender(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="otherco.com/bob",
    )

    msg_id, _ = await deliver_message(
        db_shim,
        from_did="did:aw:alice",
        to_did=bob_did_aw,
        from_alias="acme.com/alice",
        to_alias="bob",
        sender_address="acme.com/alice",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_agent_id, to_agent_id FROM {{tables.messages}} WHERE message_id = $1",
        msg_id,
    )
    assert row["from_agent_id"] is None
    assert row["to_agent_id"] is not None


@pytest.mark.asyncio
async def test_deliver_message_null_inbound_mode_fails_migration_required(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        inbound_mode=None,
    )

    with pytest.raises(ForbiddenError, match="inbound_mode migration required"):
        await deliver_message(
            db_shim,
            from_did="did:aw:alice",
            to_did=bob_did_aw,
            from_alias="acme.com/alice",
            to_alias="bob",
            sender_address="acme.com/alice",
            subject="Hello",
            body="Hi Bob!",
            priority="normal",
        )


@pytest.mark.asyncio
async def test_resolve_agent_helpers(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_did_aw = "did:aw:alice"
    alice_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=_make_did_key(),
        did_aw=alice_did_aw,
        address="acme.com/alice",
    )

    by_alias = await get_agent_by_alias(db_shim, team_id="backend:acme.com", alias="alice")
    assert by_alias is not None
    assert str(by_alias["agent_id"]) == alice_id

    by_id = await get_agent_by_id(db_shim, team_id="backend:acme.com", agent_id=alice_id)
    assert by_id is not None
    assert by_id["alias"] == "alice"

    by_did = await resolve_agent_by_did(db_shim, alice_did_aw)
    assert by_did is not None
    assert by_did["alias"] == "alice"

    missing = await resolve_agent_by_did(db_shim, "did:aw:missing")
    assert missing is None


@pytest.mark.asyncio
async def test_deliver_message_recipient_not_found(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    with pytest.raises(NotFoundError, match="Recipient"):
        await deliver_message(
            db_shim,
            from_did="did:aw:alice",
            to_did="did:aw:missing",
            from_alias="alice",
            to_alias="missing",
            sender_address="acme.com/alice",
            subject="test",
            body="test",
            priority="normal",
        )

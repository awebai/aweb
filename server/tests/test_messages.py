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
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ($1, $2, $3, $4, $5, 'global', 'developer', $6)
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

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET inbound_mode = 'team_and_contacts' WHERE agent_id = $1",
        agent_id,
    )
    inbound_mode = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT inbound_mode FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    assert inbound_mode == "team_and_contacts"

    # aapl.4: the withdrawn third value must be rejected by the CHECK.
    with pytest.raises(QueryError) as withdrawn_mode:
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.agents}} SET inbound_mode = 'contacts_or_teammates' WHERE agent_id = $1",
            agent_id,
        )
    assert "agents_inbound_mode_valid" in str(withdrawn_mode.value)

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
        inbound_mode="team_and_contacts",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at, label
        ) VALUES ($1, $2, $3, 'did:key:z6Mkcontroller', clock_timestamp(), 'Alice')
        """,
        bob_did_aw,
        "acme.com/alice",
        alice_did_aw,
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
        inbound_mode="team_and_contacts",
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
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at,
            label, reference_type, status, handle_namespace, target_agent_name
        )
        VALUES
          ('did:aw:bob', 'acme.com/alice', 'did:aw:alice', 'did:key:z6Mkcontroller', clock_timestamp(), 'Alice', 'identity', 'active', NULL, NULL),
          ('did:aw:bob', 'example.com', 'did:aw:domain', 'did:key:z6Mkcontroller', clock_timestamp(), 'Domain', 'identity', 'active', NULL, NULL),
          ('did:aw:bob', 'acme.com/pending', 'did:aw:pending', 'did:key:z6Mkcontroller', clock_timestamp(), 'Pending', 'identity', 'pending', NULL, NULL),
          ('did:aw:bob', NULL, NULL, NULL, NULL, 'Handle', 'handle', 'active', 'acme.com', 'handle')
        """
    )

    assert await has_exact_active_identity_contact(
        _DbShim(aweb_cloud_db.aweb_db),
        owner_did="did:aw:bob",
        contact_address="acme.com/alice",
        contact_did_aw="did:aw:alice",
    )
    assert not await has_exact_active_identity_contact(
        _DbShim(aweb_cloud_db.aweb_db),
        owner_did="did:aw:bob",
        contact_address="example.com/alice",
        contact_did_aw="did:aw:alice",
    )
    assert not await has_exact_active_identity_contact(
        _DbShim(aweb_cloud_db.aweb_db),
        owner_did="did:aw:bob",
        contact_address="acme.com/pending",
        contact_did_aw="did:aw:pending",
    )
    assert not await has_exact_active_identity_contact(
        _DbShim(aweb_cloud_db.aweb_db),
        owner_did="did:aw:bob",
        contact_address="acme.com/handle",
        contact_did_aw="did:aw:handle",
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
async def test_deliver_message_team_and_contacts_allows_exact_active_contact(aweb_cloud_db):
    """team_and_contacts allows exact saved contacts."""
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    bob_did_aw = "did:aw:bob-team-contact"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        inbound_mode="team_and_contacts",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at, label
        ) VALUES (
            $1, 'acme.com/alice', 'did:aw:alice-team-contact',
            'did:key:z6Mkcontroller', clock_timestamp(), 'Alice'
        )
        """,
        bob_did_aw,
    )

    msg_id, _ = await deliver_message(
        db_shim,
        from_did="did:aw:alice-team-contact",
        to_did=bob_did_aw,
        from_alias="alice",
        to_alias="bob",
        sender_address="acme.com/alice",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )
    assert msg_id is not None


@pytest.mark.asyncio
async def test_agents_inbound_mode_check_rejects_stale_values(aweb_cloud_db):
    """contacts_only and contacts_or_teammates are no longer canonical
    schema values after aapq."""
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="schema-third-mode-reject",
        did_key=_make_did_key(),
        did_aw="did:aw:bob-third-mode-reject",
        address="acme.com/bob-third-mode-reject",
        inbound_mode="team_and_contacts",
    )
    with pytest.raises(QueryError) as stale_contacts_only:
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.agents}} SET inbound_mode = 'contacts_only' WHERE agent_id = $1",
            agent_id,
        )
    assert "agents_inbound_mode_valid" in str(stale_contacts_only.value)
    with pytest.raises(QueryError) as withdrawn_mode:
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.agents}} SET inbound_mode = 'contacts_or_teammates' WHERE agent_id = $1",
            agent_id,
        )
    assert "agents_inbound_mode_valid" in str(withdrawn_mode.value)


@pytest.mark.asyncio
async def test_deliver_message_team_and_contacts_allows_verified_same_team_non_contact(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    bob_did_aw = "did:aw:bob-team-and-contacts"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="acme.com/bob",
        inbound_mode="team_and_contacts",
    )

    msg_id, _ = await deliver_message(
        db_shim,
        from_did="did:aw:alice-team-and-contacts",
        to_did=bob_did_aw,
        from_alias="alice",
        to_alias="bob",
        sender_address="acme.com/alice",
        sender_verified_team_id="backend:acme.com",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )
    assert msg_id is not None


@pytest.mark.asyncio
async def test_deliver_message_team_and_contacts_rejects_declared_team_without_proof(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    bob_did_aw = "did:aw:bob-team-claim"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob-claim",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="acme.com/bob-claim",
        inbound_mode="team_and_contacts",
    )

    with pytest.raises(ForbiddenError, match="verified team members"):
        await deliver_message(
            db_shim,
            from_did="did:aw:alice-unverified-claim",
            to_did=bob_did_aw,
            from_alias="alice",
            to_alias="bob",
            sender_address="acme.com/alice",
            team_id="backend:acme.com",
            subject="Hello",
            body="Hi Bob!",
            priority="normal",
        )


@pytest.mark.asyncio
async def test_deliver_message_team_and_contacts_checks_multi_team_identity_memberships(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "alpha:example.com")
    await _insert_team(aweb_cloud_db.aweb_db, "beta:example.com")

    alice_did_aw = "did:aw:alice-multiteam"
    alice_did_key = _make_did_key()
    bob_did_aw = "did:aw:bob-multiteam"
    bob_did_key = _make_did_key()
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="alpha:example.com",
        alias="alice-alpha",
        did_key=alice_did_key,
        did_aw=alice_did_aw,
        address="example.com/alice-alpha",
        inbound_mode="open",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="alpha:example.com",
        alias="bob-alpha",
        did_key=bob_did_key,
        did_aw=bob_did_aw,
        address="example.com/bob-alpha",
        inbound_mode="team_and_contacts",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="beta:example.com",
        alias="bob-beta",
        did_key=bob_did_key,
        did_aw=bob_did_aw,
        address="example.com/bob-beta",
        inbound_mode="team_and_contacts",
    )

    msg_id, _ = await deliver_message(
        db_shim,
        from_did=alice_did_aw,
        to_did=bob_did_aw,
        from_alias="alice",
        to_alias="bob",
        sender_address="example.com/alice-alpha",
        sender_verified_dids=[alice_did_aw, alice_did_key],
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )
    assert msg_id is not None


@pytest.mark.asyncio
async def test_deliver_message_local_recipient_same_team_behavior_unchanged(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "default:local")
    alice_did_key = _make_did_key()
    bob_did_key = _make_did_key()
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, role, inbound_mode)
        VALUES ('default:local', $1, NULL, NULL, 'bob', 'local', 'developer', 'open')
        RETURNING agent_id
        """,
        bob_did_key,
    )

    msg_id, _ = await deliver_message(
        db_shim,
        from_did=alice_did_key,
        to_did=bob_did_key,
        from_alias="alice",
        to_alias="bob",
        sender_address=None,
        team_id="default:local",
        subject="Local hello",
        body="Hi Bob!",
        priority="normal",
    )
    stored = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT to_agent_id FROM {{tables.messages}} WHERE message_id = $1",
        msg_id,
    )
    assert str(stored["to_agent_id"]) == str(row["agent_id"])


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

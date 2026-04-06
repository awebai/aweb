"""Tests for the messages service layer against the team-based schema."""

from __future__ import annotations

import pytest

from nacl.signing import SigningKey

from aweb.awid.did import did_from_public_key
from aweb.messaging.messages import (
    deliver_message,
    get_agent_by_alias,
    get_agent_by_id,
)
from aweb.service_errors import NotFoundError


def _make_did_key():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    return did_from_public_key(pk)


class _DbShim:
    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


async def _setup_team_and_agents(aweb_db, team_address="acme.com/backend"):
    """Insert team + two agents. Returns (alice_agent_id, bob_agent_id, alice_did, bob_did)."""
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        team_address,
        team_address.split("/")[0],
        team_address.split("/")[1],
    )

    alice_did = _make_did_key()
    bob_did = _make_did_key()

    alice = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_address, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'alice', 'permanent', 'developer')
        RETURNING agent_id
        """,
        team_address, alice_did,
    )

    bob = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_address, did_key, alias, lifetime, role)
        VALUES ($1, $2, 'bob', 'permanent', 'developer')
        RETURNING agent_id
        """,
        team_address, bob_did,
    )

    return str(alice["agent_id"]), str(bob["agent_id"]), alice_did, bob_did


@pytest.mark.asyncio
async def test_deliver_message(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice_id, bob_id, _, _ = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    msg_id, created_at = await deliver_message(
        db_shim,
        team_address="acme.com/backend",
        from_agent_id=alice_id,
        from_alias="alice",
        to_agent_id=bob_id,
        to_alias="bob",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )

    assert msg_id is not None
    assert created_at is not None

    # Verify the message was stored
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT * FROM {{tables.messages}} WHERE message_id = $1",
        msg_id,
    )
    assert row["from_alias"] == "alice"
    assert row["to_alias"] == "bob"
    assert row["subject"] == "Hello"
    assert row["body"] == "Hi Bob!"
    assert row["team_address"] == "acme.com/backend"


@pytest.mark.asyncio
async def test_deliver_message_sender_not_found(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    _, bob_id, _, _ = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    import uuid
    with pytest.raises(NotFoundError, match="Sender"):
        await deliver_message(
            db_shim,
            team_address="acme.com/backend",
            from_agent_id=str(uuid.uuid4()),
            from_alias="unknown",
            to_agent_id=bob_id,
            to_alias="bob",
            subject="test",
            body="test",
            priority="normal",
        )


@pytest.mark.asyncio
async def test_get_agent_by_alias(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice_id, _, _, _ = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    agent = await get_agent_by_alias(db_shim, team_address="acme.com/backend", alias="alice")
    assert agent is not None
    assert str(agent["agent_id"]) == alice_id

    missing = await get_agent_by_alias(db_shim, team_address="acme.com/backend", alias="unknown")
    assert missing is None


@pytest.mark.asyncio
async def test_get_agent_by_id(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice_id, _, _, _ = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    agent = await get_agent_by_id(db_shim, team_address="acme.com/backend", agent_id=alice_id)
    assert agent is not None
    assert agent["alias"] == "alice"

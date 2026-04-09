"""Tests for the chat service layer against the team-based schema."""

from __future__ import annotations

import pytest

from nacl.signing import SigningKey
from uuid import UUID

from awid.did import did_from_public_key
from aweb.messaging.chat import (
    ensure_session,
    get_agent_by_alias,
    send_in_session,
    get_message_history,
)


def _make_did_key():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    return did_from_public_key(pk)


class _DbShim:
    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


async def _setup_team_and_agents(aweb_db, team_id="acme.com/backend"):
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        team_id,
        team_id.split("/")[0],
        team_id.split("/")[1],
    )

    alice_did = _make_did_key()
    bob_did = _make_did_key()

    alice = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime)
        VALUES ($1, $2, 'alice', 'persistent')
        RETURNING agent_id
        """,
        team_id, alice_did,
    )
    bob = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime)
        VALUES ($1, $2, 'bob', 'persistent')
        RETURNING agent_id
        """,
        team_id, bob_did,
    )

    return (
        {"agent_id": alice["agent_id"], "team_id": team_id, "alias": "alice"},
        {"agent_id": bob["agent_id"], "team_id": team_id, "alias": "bob"},
    )


@pytest.mark.asyncio
async def test_ensure_session_creates_session(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    session_id = await ensure_session(
        db_shim,
        team_id="acme.com/backend",
        agent_rows=[alice, bob],
        created_by_alias="alice",
    )

    assert isinstance(session_id, UUID)


@pytest.mark.asyncio
async def test_ensure_session_idempotent(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    s1 = await ensure_session(
        db_shim, team_id="acme.com/backend",
        agent_rows=[alice, bob], created_by_alias="alice",
    )
    s2 = await ensure_session(
        db_shim, team_id="acme.com/backend",
        agent_rows=[alice, bob], created_by_alias="alice",
    )

    assert s1 == s2


@pytest.mark.asyncio
async def test_send_and_read_message(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    session_id = await ensure_session(
        db_shim, team_id="acme.com/backend",
        agent_rows=[alice, bob], created_by_alias="alice",
    )

    msg = await send_in_session(
        db_shim,
        session_id=session_id,
        agent_id=str(alice["agent_id"]),
        body="Hello Bob!",
    )

    assert msg is not None
    assert msg["message_id"] is not None

    history = await get_message_history(
        db_shim, session_id=session_id,
        agent_id=str(bob["agent_id"]),
    )

    assert len(history) == 1
    assert history[0]["from_alias"] == "alice"
    assert history[0]["body"] == "Hello Bob!"


@pytest.mark.asyncio
async def test_send_non_participant_returns_none(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    session_id = await ensure_session(
        db_shim, team_id="acme.com/backend",
        agent_rows=[alice, bob], created_by_alias="alice",
    )

    # Create a third agent not in the session
    charlie_did = _make_did_key()
    charlie = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, alias, lifetime)
        VALUES ('acme.com/backend', $1, 'charlie', 'ephemeral')
        RETURNING agent_id
        """,
        charlie_did,
    )

    result = await send_in_session(
        db_shim,
        session_id=session_id,
        agent_id=str(charlie["agent_id"]),
        body="I shouldn't be here",
    )

    assert result is None

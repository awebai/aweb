"""Tests for the chat service layer against the identity-scoped schema."""

from __future__ import annotations

import pytest

from nacl.signing import SigningKey
from uuid import UUID

from awid.did import did_from_public_key
from aweb.messaging.chat import (
    ensure_session,
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


async def _setup_team_and_agents(aweb_db, team_id="backend:acme.com"):
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        team_id,
        "acme.com",
        "backend",
    )

    alice_did = _make_did_key()
    bob_did = _make_did_key()

    alice = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, lifetime)
        VALUES ($1, $2, 'did:aw:alice', 'alice', 'persistent')
        RETURNING agent_id
        """,
        team_id, alice_did,
    )
    bob = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, lifetime)
        VALUES ($1, $2, 'did:aw:bob', 'bob', 'persistent')
        RETURNING agent_id
        """,
        team_id, bob_did,
    )

    return (
        {
            "agent_id": alice["agent_id"],
            "team_id": team_id,
            "alias": "alice",
            "did_key": alice_did,
            "did_aw": "did:aw:alice",
        },
        {
            "agent_id": bob["agent_id"],
            "team_id": team_id,
            "alias": "bob",
            "did_key": bob_did,
            "did_aw": "did:aw:bob",
        },
    )


@pytest.mark.asyncio
async def test_ensure_session_creates_session(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    session_id = await ensure_session(
        db_shim,
        team_id="backend:acme.com",
        participant_rows=[alice, bob],
        created_by="alice",
    )

    assert isinstance(session_id, UUID)
    conversation = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT conversation_id, conversation_type, team_id, created_by_did, status
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        """,
        session_id,
    )
    participants = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT did, agent_id, alias, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
        ORDER BY alias
        """,
        session_id,
    )
    assert conversation["conversation_type"] == "chat"
    assert conversation["team_id"] == "backend:acme.com"
    assert conversation["created_by_did"] == "did:aw:alice"
    assert conversation["status"] == "active"
    assert {row["did"] for row in participants} == {"did:aw:alice", "did:aw:bob"}
    assert {row["transport_hint"] for row in participants} == {"chat"}


@pytest.mark.asyncio
async def test_ensure_session_idempotent(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    s1 = await ensure_session(
        db_shim, team_id="backend:acme.com",
        participant_rows=[alice, bob], created_by="alice",
    )
    s2 = await ensure_session(
        db_shim, team_id="backend:acme.com",
        participant_rows=[alice, bob], created_by="alice",
    )

    assert s1 == s2
    count = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        """,
        s1,
    )
    assert count["count"] == 1


@pytest.mark.asyncio
async def test_ensure_session_backfills_conversation_for_existing_chat_session(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    session = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_sessions}} (team_id, created_by)
        VALUES ('backend:acme.com', 'alice')
        RETURNING session_id
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', NULL),
            ($1, 'did:aw:bob', $3, 'bob', NULL)
        """,
        session["session_id"],
        alice["agent_id"],
        bob["agent_id"],
    )

    reused = await ensure_session(
        db_shim,
        team_id="backend:acme.com",
        participant_rows=[alice, bob],
        created_by="alice",
    )

    assert reused == session["session_id"]
    conversation = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT conversation_id, conversation_type
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        """,
        reused,
    )
    participants = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT did, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
        """,
        reused,
    )
    assert conversation["conversation_type"] == "chat"
    assert {row["did"] for row in participants} == {"did:aw:alice", "did:aw:bob"}
    assert {row["transport_hint"] for row in participants} == {"chat"}


@pytest.mark.asyncio
async def test_send_and_read_message(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    session_id = await ensure_session(
        db_shim, team_id="backend:acme.com",
        participant_rows=[alice, bob], created_by="alice",
    )

    msg = await send_in_session(
        db_shim,
        session_id=session_id,
        sender_did="did:aw:alice",
        sender_agent_id=str(alice["agent_id"]),
        body="Hello Bob!",
    )

    assert msg is not None
    assert msg["message_id"] is not None

    history = await get_message_history(
        db_shim, session_id=session_id,
        participant_did="did:aw:bob",
    )

    assert len(history) == 1
    assert history[0]["from_alias"] == "alice"
    assert history[0]["body"] == "Hello Bob!"


@pytest.mark.asyncio
async def test_send_non_participant_returns_none(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    session_id = await ensure_session(
        db_shim, team_id="backend:acme.com",
        participant_rows=[alice, bob], created_by="alice",
    )

    # Create a third agent not in the session
    charlie_did = _make_did_key()
    charlie = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, lifetime)
        VALUES ('backend:acme.com', $1, 'did:aw:charlie', 'charlie', 'ephemeral')
        RETURNING agent_id
        """,
        charlie_did,
    )

    result = await send_in_session(
        db_shim,
        session_id=session_id,
        sender_did="did:aw:charlie",
        sender_agent_id=str(charlie["agent_id"]),
        body="I shouldn't be here",
    )

    assert result is None


@pytest.mark.asyncio
async def test_ensure_session_reuses_identity_pair_across_teams(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, _ = await _setup_team_and_agents(aweb_cloud_db.aweb_db, team_id="backend:acme.com")
    await _setup_team_and_agents(aweb_cloud_db.aweb_db, team_id="ops:acme.com")
    bob_other = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT agent_id, did_key
        FROM {{tables.agents}}
        WHERE team_id = 'ops:acme.com' AND alias = 'bob'
        """
    )
    bob = {
        "agent_id": bob_other["agent_id"],
        "team_id": "ops:acme.com",
        "alias": "bob",
        "did_key": bob_other["did_key"],
        "did_aw": "did:aw:bob",
    }

    s1 = await ensure_session(
        db_shim,
        team_id="backend:acme.com",
        participant_rows=[alice, bob],
        created_by="alice",
    )
    s2 = await ensure_session(
        db_shim,
        team_id="ops:acme.com",
        participant_rows=[alice, bob],
        created_by="alice",
    )

    assert s1 == s2


@pytest.mark.asyncio
async def test_ensure_session_reuses_identity_pair_across_stable_and_current_dids(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)

    session_from_current = await ensure_session(
        db_shim,
        team_id="backend:acme.com",
        participant_rows=[
            {
                "agent_id": alice["agent_id"],
                "team_id": alice["team_id"],
                "alias": alice["alias"],
                "did_key": alice["did_key"],
            },
            bob,
        ],
        created_by="alice",
    )
    session_from_stable = await ensure_session(
        db_shim,
        team_id="backend:acme.com",
        participant_rows=[
            {
                "agent_id": alice["agent_id"],
                "team_id": alice["team_id"],
                "alias": alice["alias"],
                "did_aw": alice["did_aw"],
                "did_key": alice["did_key"],
            },
            bob,
        ],
        created_by="alice",
    )

    assert session_from_current == session_from_stable


@pytest.mark.asyncio
async def test_ensure_session_does_not_merge_different_agents_sharing_did_aw(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    _, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db, team_id="backend:acme.com")
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:acme.com', 'acme.com', 'ops', 'did:key:z6Mkteam-ops')
        ON CONFLICT DO NOTHING
        """
    )

    shared_did_aw = "did:aw:alice"
    alice_old_did_key = _make_did_key()
    alice_new_did_key = _make_did_key()
    old_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, lifetime)
        VALUES ('backend:acme.com', $1, $2, 'alice-old', 'persistent')
        RETURNING agent_id
        """,
        alice_old_did_key,
        shared_did_aw,
    )
    new_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, lifetime)
        VALUES ('ops:acme.com', $1, $2, 'alice-new', 'persistent')
        RETURNING agent_id
        """,
        alice_new_did_key,
        shared_did_aw,
    )

    old_session = await ensure_session(
        db_shim,
        team_id="backend:acme.com",
        participant_rows=[
            {
                "agent_id": old_row["agent_id"],
                "team_id": "backend:acme.com",
                "alias": "alice-old",
                "did_aw": shared_did_aw,
                "did_key": alice_old_did_key,
            },
            bob,
        ],
        created_by="alice-old",
    )
    new_session = await ensure_session(
        db_shim,
        team_id="ops:acme.com",
        participant_rows=[
            {
                "agent_id": new_row["agent_id"],
                "team_id": "ops:acme.com",
                "alias": "alice-new",
                "did_aw": shared_did_aw,
                "did_key": alice_new_did_key,
            },
            bob,
        ],
        created_by="alice-new",
    )

    assert new_session != old_session

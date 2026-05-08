from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from aweb.messaging.chat import find_session_between
from aweb.messaging.conversations import (
    add_conversation_participant,
    close_conversation,
    create_conversation,
    expire_conversation,
    find_active_one_to_one_conversation_between,
    get_conversation,
    list_conversation_participants,
    require_active_conversation_participant,
    touch_conversation_activity,
)
from aweb.service_errors import ForbiddenError, NotFoundError, ValidationError


class _DbShim:
    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


async def _insert_team(aweb_db, team_id: str = "backend:acme.com"):
    team_name, namespace = team_id.split(":", 1)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        """,
        team_id,
        namespace,
        team_name,
    )


async def _insert_agent(aweb_db, *, team_id: str, alias: str, did_aw: str, address: str):
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES ($1, $2, $3, $4, $5, 'persistent', 'developer', 'everyone')
        RETURNING agent_id
        """,
        team_id,
        f"did:key:z6Mk{alias}",
        did_aw,
        address,
        alias,
    )
    return row["agent_id"]


async def _create_two_party_conversation(aweb_cloud_db, *, expires_at=None):
    await _insert_team(aweb_cloud_db.aweb_db)
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )
    conversation = await create_conversation(
        _DbShim(aweb_cloud_db.aweb_db),
        conversation_type="mail",
        created_by_did="did:aw:alice",
        initiator={
            "did": "did:aw:alice",
            "agent_id": alice_agent_id,
            "alias": "alice",
            "address": "acme.com/alice",
            "transport_hint": "mail",
        },
        recipients=[
            {
                "did": "did:aw:bob",
                "agent_id": bob_agent_id,
                "alias": "bob",
                "address": "acme.com/bob",
                "transport_hint": "mail",
            }
        ],
        team_id="backend:acme.com",
        expires_at=expires_at,
    )
    return conversation


@pytest.mark.asyncio
async def test_create_conversation_records_sender_and_recipients(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)

    assert conversation["conversation_type"] == "mail"
    assert conversation["status"] == "active"
    assert conversation["team_id"] == "backend:acme.com"
    assert conversation["created_by_did"] == "did:aw:alice"
    assert conversation["expires_at"] is not None
    assert conversation["expires_at"] > datetime.now(timezone.utc) + timedelta(days=29)

    participants = await list_conversation_participants(
        db,
        conversation_id=conversation["conversation_id"],
    )
    by_did = {participant["did"]: participant for participant in participants}

    assert set(by_did) == {"did:aw:alice", "did:aw:bob"}
    assert by_did["did:aw:alice"]["role"] == "initiator"
    assert by_did["did:aw:bob"]["role"] == "participant"
    assert by_did["did:aw:bob"]["address"] == "acme.com/bob"
    assert by_did["did:aw:bob"]["transport_hint"] == "mail"


@pytest.mark.asyncio
async def test_require_active_participant_uses_stored_membership_not_discovery(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)

    auth = await require_active_conversation_participant(
        db,
        conversation_id=conversation["conversation_id"],
        authenticated_did="did:aw:bob",
    )

    assert auth["conversation"]["conversation_id"] == conversation["conversation_id"]
    assert auth["participant"]["did"] == "did:aw:bob"
    assert auth["participant"]["alias"] == "bob"


@pytest.mark.asyncio
async def test_require_active_participant_accepts_verified_equivalent_did(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)

    auth = await require_active_conversation_participant(
        db,
        conversation_id=conversation["conversation_id"],
        authenticated_did="did:key:z6Mkbob",
        equivalent_dids=["did:aw:bob"],
    )

    assert auth["participant"]["did"] == "did:aw:bob"


@pytest.mark.asyncio
async def test_non_participant_with_leaked_conversation_id_gets_forbidden(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)

    with pytest.raises(ForbiddenError, match="not a participant"):
        await require_active_conversation_participant(
            db,
            conversation_id=conversation["conversation_id"],
            authenticated_did="did:aw:mallory",
        )


@pytest.mark.asyncio
async def test_missing_conversation_is_not_found(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)

    with pytest.raises(NotFoundError):
        await require_active_conversation_participant(
            db,
            conversation_id="11111111-1111-1111-1111-111111111111",
            authenticated_did="did:aw:alice",
        )


@pytest.mark.asyncio
async def test_closed_conversation_rejects_continuation_and_new_participants(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)

    closed = await close_conversation(
        db,
        conversation_id=conversation["conversation_id"],
        closed_by_did="did:aw:bob",
    )

    assert closed["status"] == "closed"
    assert closed["closed_at"] is not None
    with pytest.raises(ForbiddenError, match="closed"):
        await require_active_conversation_participant(
            db,
            conversation_id=conversation["conversation_id"],
            authenticated_did="did:aw:alice",
        )
    with pytest.raises(ForbiddenError, match="closed"):
        await add_conversation_participant(
            db,
            conversation_id=conversation["conversation_id"],
            participant={"did": "did:aw:carol", "alias": "carol"},
        )
    with pytest.raises(ForbiddenError, match="closed"):
        await touch_conversation_activity(
            db,
            conversation_id=conversation["conversation_id"],
        )


@pytest.mark.asyncio
async def test_past_expires_at_lazily_expires_conversation(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(
        aweb_cloud_db,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    with pytest.raises(ForbiddenError, match="expired"):
        await require_active_conversation_participant(
            db,
            conversation_id=conversation["conversation_id"],
            authenticated_did="did:aw:bob",
        )

    expired = await get_conversation(db, conversation_id=conversation["conversation_id"])
    assert expired is not None
    assert expired["status"] == "expired"

    with pytest.raises(ForbiddenError, match="expired"):
        await touch_conversation_activity(db, conversation_id=conversation["conversation_id"])


@pytest.mark.asyncio
async def test_touch_conversation_activity_updates_activity_and_slides_expiry(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)
    now = datetime.now(timezone.utc).replace(microsecond=0)

    touched = await touch_conversation_activity(
        db,
        conversation_id=conversation["conversation_id"],
        now=now,
    )

    assert touched["updated_at"] == now
    assert touched["expires_at"] == now + timedelta(days=30)


@pytest.mark.asyncio
async def test_create_conversation_allows_self_conversation(aweb_cloud_db):
    await _insert_team(aweb_cloud_db.aweb_db)

    conversation = await create_conversation(
        _DbShim(aweb_cloud_db.aweb_db),
        conversation_type="mail",
        created_by_did="did:aw:alice",
        initiator={"did": "did:aw:alice", "alias": "alice", "address": "acme.com/alice"},
        recipients=[{"did": "did:aw:alice", "alias": "alice", "address": "acme.com/alice"}],
        team_id="backend:acme.com",
    )
    participants = await list_conversation_participants(
        _DbShim(aweb_cloud_db.aweb_db),
        conversation_id=conversation["conversation_id"],
    )

    assert len(participants) == 1
    assert participants[0]["did"] == "did:aw:alice"


@pytest.mark.asyncio
async def test_create_conversation_rolls_back_when_participant_insert_fails(aweb_cloud_db):
    await _insert_team(aweb_cloud_db.aweb_db)
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await create_conversation(
            _DbShim(aweb_cloud_db.aweb_db),
            conversation_type="mail",
            created_by_did="did:aw:alice",
            initiator={
                "did": "did:aw:alice",
                "agent_id": alice_agent_id,
                "alias": "alice",
                "address": "acme.com/alice",
                "transport_hint": "mail",
            },
            recipients=[
                {
                    "did": "did:aw:bob",
                    "agent_id": "11111111-1111-1111-1111-111111111111",
                    "alias": "bob",
                    "address": "acme.com/bob",
                    "transport_hint": "mail",
                }
            ],
            team_id="backend:acme.com",
        )

    count = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM {{tables.conversations}}
        WHERE created_by_did = 'did:aw:alice'
        """
    )
    assert count["count"] == 0


@pytest.mark.asyncio
async def test_close_conversation_requires_participant_or_system_close(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)

    with pytest.raises(ValidationError, match="closed_by_did"):
        await close_conversation(db, conversation_id=conversation["conversation_id"])
    with pytest.raises(ForbiddenError, match="not a participant"):
        await close_conversation(
            db,
            conversation_id=conversation["conversation_id"],
            closed_by_did="did:aw:mallory",
        )

    closed = await close_conversation(
        db,
        conversation_id=conversation["conversation_id"],
        system_close=True,
    )
    assert closed["status"] == "closed"


@pytest.mark.asyncio
async def test_touch_conversation_activity_preserves_expiry_when_ttl_is_none(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)

    touched = await touch_conversation_activity(
        db,
        conversation_id=conversation["conversation_id"],
        ttl=None,
    )
    assert touched["status"] == "active"
    assert touched["expires_at"] == conversation["expires_at"]


@pytest.mark.asyncio
async def test_explicitly_expired_conversation_rejects_continuation_idempotently(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    conversation = await _create_two_party_conversation(aweb_cloud_db)
    await expire_conversation(db, conversation_id=conversation["conversation_id"])

    results = await asyncio.gather(
        require_active_conversation_participant(
            db,
            conversation_id=conversation["conversation_id"],
            authenticated_did="did:aw:alice",
        ),
        require_active_conversation_participant(
            db,
            conversation_id=conversation["conversation_id"],
            authenticated_did="did:aw:bob",
        ),
        return_exceptions=True,
    )

    assert all(isinstance(result, ForbiddenError) for result in results)
    expired = await get_conversation(db, conversation_id=conversation["conversation_id"])
    assert expired is not None
    assert expired["status"] == "expired"
    expired_updated_at = expired["updated_at"]

    with pytest.raises(ForbiddenError, match="expired"):
        await require_active_conversation_participant(
            db,
            conversation_id=conversation["conversation_id"],
            authenticated_did="did:aw:alice",
        )
    expired_after_second_check = await get_conversation(
        db,
        conversation_id=conversation["conversation_id"],
    )
    assert expired_after_second_check["updated_at"] == expired_updated_at


# ---------------------------------------------------------------------------
# Multi-team agent participant lookup regression - aweb-aam? (Athena follow-on
# to 1.20.2 routes/conversations.py:117 fix). Four sibling SQL spots had:
#   ($X::uuid IS NOT NULL AND p.agent_id = $X)
#   OR ($X::uuid IS NULL AND p.did = ANY($Y::text[]))
# The did fallback only fires when agent_id IS NULL, so a multi-team agent
# whose participation row carries a different team's agent_id is never matched.
# Fix: expand equivalent agent_ids by shared did_key, not by did_aw collision.
# ---------------------------------------------------------------------------


async def _multi_team_alice_setup(aweb_cloud_db):
    """Set up alice as a multi-team agent: same did_aw across two team rows.

    Returns (alice_team_a_agent_id, alice_team_b_agent_id, bob_team_b_agent_id).
    """
    aweb_db = aweb_cloud_db.aweb_db
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('team-a:acme.com', 'acme.com', 'team-a', 'did:key:z6Mkteama')
        ON CONFLICT DO NOTHING
        """
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('team-b:acme.com', 'acme.com', 'team-b', 'did:key:z6Mkteamb')
        ON CONFLICT DO NOTHING
        """
    )
    alice_a = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES ('team-a:acme.com', 'did:key:z6Mkalice', 'did:aw:alice',
                'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone')
        RETURNING agent_id
        """
    )
    alice_b = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES ('team-b:acme.com', 'did:key:z6Mkalice', 'did:aw:alice',
                'acme.com/alice', 'alice', 'persistent', 'developer', 'everyone')
        RETURNING agent_id
        """
    )
    bob_b = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES ('team-b:acme.com', 'did:key:z6Mkbob', 'did:aw:bob',
                'acme.com/bob', 'bob', 'persistent', 'developer', 'everyone')
        RETURNING agent_id
        """
    )
    return alice_a["agent_id"], alice_b["agent_id"], bob_b["agent_id"]


@pytest.mark.asyncio
async def test_find_active_conversation_matches_multi_team_agent_via_did_fallback(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    alice_a, alice_b, bob_b = await _multi_team_alice_setup(aweb_cloud_db)

    conversation = await create_conversation(
        db,
        conversation_type="mail",
        created_by_did="did:aw:alice",
        initiator={
            "did": "did:aw:alice",
            "agent_id": alice_b,
            "alias": "alice",
            "address": "acme.com/alice",
            "transport_hint": "mail",
        },
        recipients=[{
            "did": "did:aw:bob",
            "agent_id": bob_b,
            "alias": "bob",
            "address": "acme.com/bob",
            "transport_hint": "mail",
        }],
        team_id="team-b:acme.com",
    )

    # Caller is alice acting from team-A's identity (team-A agent_id), but the
    # participation row carries team-B's agent_id. Address is intentionally
    # NOT passed so the address branch can't bypass the buggy did fallback.
    # Pre-fix: agent_id mismatches team-B AND the did fallback is gated on
    # agent_id IS NULL (which fails because the row has team-B's agent_id).
    # Post-fix: did matches via the un-gated OR, lookup finds the conversation.
    found = await find_active_one_to_one_conversation_between(
        db,
        conversation_type="mail",
        did_a="did:aw:alice",
        did_key_a="did:key:z6Mkalice",
        agent_id_a=alice_a,
        did_b="did:aw:bob",
        did_key_b="did:key:z6Mkbob",
        agent_id_b=bob_b,
    )
    assert found is not None, (
        "find_active_one_to_one_conversation_between should match via did when "
        "the caller's agent_id differs from the participation row's agent_id "
        "(multi-team agent fallback)."
    )
    assert str(found["conversation_id"]) == str(conversation["conversation_id"])


@pytest.mark.asyncio
async def test_find_session_between_matches_multi_team_agent_via_did_fallback(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    alice_a, alice_b, bob_b = await _multi_team_alice_setup(aweb_cloud_db)
    aweb_db = aweb_cloud_db.aweb_db

    # Seed a chat_sessions row + chat_participants directly (no conversations
    # row) so that find_session_between's conversations-table lookup returns
    # None and the chat_participants-direct fallback at chat.py:145 fires.
    session = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_sessions}} (team_id, created_by)
        VALUES ('team-b:acme.com', 'did:aw:alice')
        RETURNING session_id
        """
    )
    session_id = session["session_id"]
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}}
            (session_id, did, agent_id, alias, address)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob')
        """,
        session_id,
        alice_b,
        bob_b,
    )

    # Same multi-team scenario as the conversation test above, on the chat
    # fallback path. Address omitted to isolate the did-fallback branch.
    found_session_id = await find_session_between(
        db,
        did_a="did:aw:alice",
        did_b="did:aw:bob",
        did_key_a="did:key:z6Mkalice",
        did_key_b="did:key:z6Mkbob",
        agent_id_a=alice_a,
        agent_id_b=bob_b,
    )
    assert found_session_id is not None, (
        "find_session_between should match via did when the caller's agent_id "
        "differs from the participation row's agent_id."
    )
    assert str(found_session_id) == str(session_id)

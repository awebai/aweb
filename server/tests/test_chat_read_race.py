from datetime import datetime, timezone

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key
import aweb.messaging.chat as chat_service
from aweb.messaging.chat import (
    ensure_session,
    get_message_history,
    mark_messages_read,
    send_in_session,
)


class _DbShim:
    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


async def _setup_team_and_agents(aweb_db):
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:read-race.example', 'read-race.example', 'backend', 'did:key:z6Mkteam')
        """
    )

    agents = []
    for alias in ("alice", "bob"):
        signing_key = SigningKey.generate()
        did_key = did_from_public_key(bytes(signing_key.verify_key))
        row = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, identity_scope)
            VALUES ('backend:read-race.example', $1, $2, $3, 'global')
            RETURNING agent_id
            """,
            did_key,
            f"did:aw:{alias}",
            alias,
        )
        agents.append(
            {
                "agent_id": row["agent_id"],
                "team_id": "backend:read-race.example",
                "alias": alias,
                "did_key": did_key,
                "did_aw": f"did:aw:{alias}",
            }
        )
    return agents


class _FrozenDateTime(datetime):
    instant = datetime(2026, 7, 26, 20, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return cls.instant.replace(tzinfo=None)
        return cls.instant.astimezone(tz)


@pytest.mark.asyncio
async def test_message_inserted_during_presented_snapshot_remains_unread(
    aweb_cloud_db, monkeypatch
):
    db = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)
    session_id = await ensure_session(
        db,
        team_id="backend:read-race.example",
        participant_rows=[alice, bob],
        created_by="alice",
    )
    monkeypatch.setattr(chat_service, "datetime", _FrozenDateTime)

    presented = await send_in_session(
        db,
        session_id=session_id,
        sender_did=alice["did_aw"],
        sender_agent_id=str(alice["agent_id"]),
        body="presented before provider run",
    )
    assert presented is not None

    snapshot = await get_message_history(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        unread_only=True,
    )
    presented_ids = [row["message_id"] for row in snapshot]
    assert presented_ids == [str(presented["message_id"])]

    concurrent = await send_in_session(
        db,
        session_id=session_id,
        sender_did=alice["did_aw"],
        sender_agent_id=str(alice["agent_id"]),
        body="committed while recipient is mid-run",
    )
    assert concurrent is not None
    assert presented["created_at"] == concurrent["created_at"] == _FrozenDateTime.instant
    assert str(concurrent["message_id"]) not in presented_ids

    await mark_messages_read(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        participant_agent_id=str(bob["agent_id"]),
        up_to_message_id=presented_ids[-1],
    )

    unread = await get_message_history(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        unread_only=True,
    )
    assert [row["message_id"] for row in unread] == [str(concurrent["message_id"])]

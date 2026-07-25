import asyncio
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
        VALUES ('backend:race.example', 'race.example', 'backend', 'did:key:z6Mkteam')
        """
    )

    agents = []
    for alias in ("alice", "bob"):
        signing_key = SigningKey.generate()
        did_key = did_from_public_key(bytes(signing_key.verify_key))
        row = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, identity_scope)
            VALUES ('backend:race.example', $1, $2, $3, 'global')
            RETURNING agent_id
            """,
            did_key,
            f"did:aw:{alias}",
            alias,
        )
        agents.append(
            {
                "agent_id": row["agent_id"],
                "team_id": "backend:race.example",
                "alias": alias,
                "did_key": did_key,
                "did_aw": f"did:aw:{alias}",
            }
        )
    return agents


class _FrozenDateTime(datetime):
    instant = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return cls.instant.replace(tzinfo=None)
        return cls.instant.astimezone(tz)


class _MarkReadBarrier:
    def __init__(self, database, target_loaded, concurrent_inserted):
        self._database = database
        self._target_loaded = target_loaded
        self._concurrent_inserted = concurrent_inserted
        self._blocked = False

    def __getattr__(self, name):
        return getattr(self._database, name)

    async def fetch_one(self, query, *args):
        result = await self._database.fetch_one(query, *args)
        if not self._blocked and "SELECT created_at" in query and "message_id = $2" in query:
            self._blocked = True
            self._target_loaded.set()
            await self._concurrent_inserted.wait()
        return result


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="default-aamm step 2 needs a server-assigned monotonic cursor before a concurrent equal-time insert stays unread",
)
async def test_concurrent_equal_server_time_insert_stays_unread(aweb_cloud_db, monkeypatch):
    real_db = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)
    session_id = await ensure_session(
        real_db,
        team_id="backend:race.example",
        participant_rows=[alice, bob],
        created_by="alice",
    )
    monkeypatch.setattr(chat_service, "datetime", _FrozenDateTime)

    presented = await send_in_session(
        real_db,
        session_id=session_id,
        sender_did=alice["did_aw"],
        sender_agent_id=str(alice["agent_id"]),
        body="presented before mark-read",
    )
    assert presented is not None

    target_loaded = asyncio.Event()
    concurrent_inserted = asyncio.Event()
    barrier_db = _DbShim(
        _MarkReadBarrier(aweb_cloud_db.aweb_db, target_loaded, concurrent_inserted)
    )
    mark_task = asyncio.create_task(
        mark_messages_read(
            barrier_db,
            session_id=session_id,
            participant_did=bob["did_aw"],
            participant_agent_id=str(bob["agent_id"]),
            up_to_message_id=str(presented["message_id"]),
        )
    )
    await target_loaded.wait()

    concurrent = await send_in_session(
        real_db,
        session_id=session_id,
        sender_did=alice["did_aw"],
        sender_agent_id=str(alice["agent_id"]),
        body="inserted while mark-read is paused",
    )
    assert concurrent is not None
    concurrent_inserted.set()
    await mark_task

    unread = await get_message_history(
        real_db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        unread_only=True,
    )
    assert [row["message_id"] for row in unread] == [concurrent["message_id"]]

"""Probe: does the MCP chat wait return a hang-on (extend-wait) reply it consumed?"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aweb.mcp.tools.chat import _wait_for_replies


@dataclass
class _Auth:
    trusted_proxy: bool = False


class _FakeRedis:
    def __init__(self):
        self.zsets = {}

    def pipeline(self, transaction=True):
        return self

    def zadd(self, key, mapping):
        self.zsets.setdefault(key, {}).update(mapping)
        return self

    def expire(self, key, ttl):
        return self

    async def execute(self):
        return []

    async def zrem(self, key, member):
        self.zsets.get(key, {}).pop(member, None)
        return 1


@pytest.mark.asyncio
async def test_probe_hangon_wait(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    session_id = uuid4()
    now = datetime.now(timezone.utc)

    await aweb_db.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id, created_by) VALUES ($1, $2)",
        session_id,
        "did:key:zSelf",
    )
    # A peer message that says "give me more time" (hang_on=true), i.e. what
    # `aw chat extend-wait` sends.
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, hang_on, created_at)
        VALUES ($1, $2, 'did:key:zPeer', 'peer', 'still working, need 5 more minutes', true, $3)
        """,
        uuid4(),
        session_id,
        now + timedelta(seconds=1),
    )

    replies, timed_out = await _wait_for_replies(
        aweb_db,
        _FakeRedis(),
        auth=_Auth(),
        hosted_decryptor=None,
        session_id=session_id,
        participant_did="did:key:zSelf",
        after=now,
        wait_seconds=2,
    )
    print("REPLIES  ", replies)
    print("TIMED_OUT", timed_out)
    assert replies, "wait consumed a hang_on message but reported no replies"

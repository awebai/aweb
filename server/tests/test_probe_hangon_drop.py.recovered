from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import chat as chat_tools


AUTH = AuthContext(
    team_id=None,
    agent_id=None,
    alias="alice",
    did_key="did:key:z6MkAliceCurrent",
    did_aw="did:aw:alice",
    address="acme.com/alice",
)


async def _seed(aweb_db, *, hang_on: bool, body: str = "still working, need 5 more minutes"):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES ($1, 'did:key:z6MkAliceCurrent', 'alice'), ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, hang_on, created_at)
        VALUES ($1, $2, 'did:aw:bob', 'bob', $3, $4, $5)
        """,
        uuid4(),
        session_id,
        body,
        hang_on,
        created_at + timedelta(minutes=1),
    )
    return session_id, created_at


@pytest.mark.asyncio
async def test_probe_hang_on_only(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(chat_tools, "HANG_ON_EXTENSION_SECONDS", 4)
    aweb_db = aweb_cloud_db.aweb_db
    session_id, after = await _seed(aweb_db, hang_on=True)
    t0 = time.monotonic()
    replies, timed_out = await chat_tools._wait_for_replies(
        aweb_db,
        None,
        auth=AUTH,
        hosted_decryptor=None,
        session_id=session_id,
        participant_did="did:key:z6MkAliceCurrent",
        after=after,
        wait_seconds=1,
    )
    elapsed = time.monotonic() - t0
    print(f"HANG_ON probe: replies={replies} timed_out={timed_out} elapsed={elapsed:.2f}s")
    assert replies == []
    assert timed_out is True
    assert elapsed > 3.0, "deadline was not extended -> row not consumed as hang_on"


@pytest.mark.asyncio
async def test_probe_control_not_hang_on(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(chat_tools, "HANG_ON_EXTENSION_SECONDS", 4)
    aweb_db = aweb_cloud_db.aweb_db
    session_id, after = await _seed(aweb_db, hang_on=False)
    replies, timed_out = await chat_tools._wait_for_replies(
        aweb_db,
        None,
        auth=AUTH,
        hosted_decryptor=None,
        session_id=session_id,
        participant_did="did:key:z6MkAliceCurrent",
        after=after,
        wait_seconds=1,
    )
    print(f"CONTROL probe: replies={replies} timed_out={timed_out}")
    assert timed_out is False
    assert len(replies) == 1
    assert replies[0]["body"] == "still working, need 5 more minutes"


@pytest.mark.asyncio
async def test_probe_mixed_batch(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(chat_tools, "HANG_ON_EXTENSION_SECONDS", 4)
    aweb_db = aweb_cloud_db.aweb_db
    session_id, after = await _seed(aweb_db, hang_on=True)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, hang_on, created_at)
        VALUES ($1, $2, 'did:aw:bob', 'bob', 'here is the answer', FALSE, $3)
        """,
        uuid4(),
        session_id,
        after + timedelta(minutes=2),
    )
    replies, timed_out = await chat_tools._wait_for_replies(
        aweb_db,
        None,
        auth=AUTH,
        hosted_decryptor=None,
        session_id=session_id,
        participant_did="did:key:z6MkAliceCurrent",
        after=after,
        wait_seconds=1,
    )
    print(f"MIXED probe: bodies={[r['body'] for r in replies]} timed_out={timed_out}")
    assert timed_out is False
    assert len(replies) == 2


@pytest.mark.asyncio
async def test_probe_hang_on_then_late_answer(aweb_cloud_db, monkeypatch):
    """hang_on arrives in one poll batch, the real answer in a later batch."""
    monkeypatch.setattr(chat_tools, "HANG_ON_EXTENSION_SECONDS", 6)
    aweb_db = aweb_cloud_db.aweb_db
    session_id, after = await _seed(aweb_db, hang_on=True)

    import asyncio

    async def late_answer():
        await asyncio.sleep(2)
        await aweb_db.execute(
            """
            INSERT INTO {{tables.chat_messages}}
                (message_id, session_id, from_did, from_alias, body, hang_on, created_at)
            VALUES ($1, $2, 'did:aw:bob', 'bob', 'here is the answer', FALSE, $3)
            """,
            uuid4(),
            session_id,
            datetime.now(timezone.utc),
        )

    task = asyncio.create_task(late_answer())
    replies, timed_out = await chat_tools._wait_for_replies(
        aweb_db,
        None,
        auth=AUTH,
        hosted_decryptor=None,
        session_id=session_id,
        participant_did="did:key:z6MkAliceCurrent",
        after=after,
        wait_seconds=1,
    )
    await task
    print(f"LATE probe: bodies={[r['body'] for r in replies]} timed_out={timed_out}")
    assert timed_out is False
    assert [r["body"] for r in replies] == ["here is the answer"]

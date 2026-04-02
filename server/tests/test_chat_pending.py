from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.db import get_db_infra
from aweb.messaging.chat import (
    ensure_session,
    get_pending_conversations,
    mark_messages_read,
    send_in_session,
)
from aweb.redis_client import get_redis
from aweb.routes.init import bootstrap_router, router as init_router


class _FakeRedis:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._ttl: dict[str, int] = {}

    async def eval(self, _script: str, _num_keys: int, key: str, window_seconds: int) -> int:
        current = self._counts.get(key, 0) + 1
        self._counts[key] = current
        self._ttl[key] = int(window_seconds)
        return current

    async def ttl(self, key: str) -> int:
        return self._ttl.get(key, -1)

    async def delete(self, key: str) -> int:
        self._counts.pop(key, None)
        self._ttl.pop(key, None)
        return 1


class _DbInfra:
    is_initialized = True

    def __init__(self, *, aweb_db, server_db) -> None:
        self.aweb_db = aweb_db
        self.server_db = server_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self.aweb_db
        if name == "server":
            return self.server_db
        raise KeyError(name)


def _build_test_app(*, aweb_db, server_db) -> FastAPI:
    app = FastAPI(title="aweb chat pending test")
    app.include_router(bootstrap_router)
    app.include_router(init_router)
    app.dependency_overrides[get_db_infra] = lambda: _DbInfra(aweb_db=aweb_db, server_db=server_db)
    app.dependency_overrides[get_redis] = lambda: _FakeRedis()
    return app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _bootstrap_two_agents(aweb_cloud_db):
    app = _build_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "chat-pending-project",
                "namespace_slug": "chat-pending-team",
                "alias": "alice",
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text
        alice = bootstrap.json()

        second = await client.post(
            "/v1/workspaces/init",
            headers=_auth_headers(alice["api_key"]),
            json={"alias": "bob"},
        )
        assert second.status_code == 200, second.text
        bob = second.json()

    db = _DbInfra(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)
    return db, alice, bob


async def _create_waiting_session(*, db, project_id: str, alice: dict, bob: dict):
    session_id = await ensure_session(
        db,
        project_id=project_id,
        agent_rows=[
            {"agent_id": alice["agent_id"], "project_id": project_id, "alias": "alice"},
            {"agent_id": bob["agent_id"], "project_id": project_id, "alias": "bob"},
        ],
    )
    first_message = await send_in_session(
        db,
        session_id=session_id,
        agent_id=alice["agent_id"],
        body="can you take a look?",
    )
    assert first_message is not None

    await db.get_manager("aweb").execute(
        """
        UPDATE {{tables.chat_sessions}}
        SET wait_seconds = $2,
            wait_started_at = $3,
            wait_started_by_agent_id = $4
        WHERE session_id = $1
        """,
        session_id,
        300,
        first_message["created_at"],
        alice["agent_id"],
    )

    await mark_messages_read(
        db,
        session_id=session_id,
        agent_id=bob["agent_id"],
        up_to_message_id=str(first_message["message_id"]),
    )

    return session_id


@pytest.mark.asyncio
async def test_get_pending_conversations_ignores_self_authored_reply_after_wait(aweb_cloud_db):
    db, alice, bob = await _bootstrap_two_agents(aweb_cloud_db)
    session_id = await _create_waiting_session(
        db=db,
        project_id=alice["project_id"],
        alice=alice,
        bob=bob,
    )

    reply = await send_in_session(
        db,
        session_id=session_id,
        agent_id=bob["agent_id"],
        body="done",
    )
    assert reply is not None

    pending = await get_pending_conversations(db, agent_id=bob["agent_id"])

    assert pending == []


@pytest.mark.asyncio
async def test_get_pending_conversations_keeps_hang_on_conversation_actionable(aweb_cloud_db):
    db, alice, bob = await _bootstrap_two_agents(aweb_cloud_db)
    session_id = await _create_waiting_session(
        db=db,
        project_id=alice["project_id"],
        alice=alice,
        bob=bob,
    )

    hang_on = await send_in_session(
        db,
        session_id=session_id,
        agent_id=bob["agent_id"],
        body="hang on a minute",
        hang_on=True,
        created_at=datetime.now(timezone.utc),
    )
    assert hang_on is not None

    pending = await get_pending_conversations(db, agent_id=bob["agent_id"])

    assert len(pending) == 1
    assert pending[0]["session_id"] == str(session_id)
    assert pending[0]["last_message"] == "hang on a minute"

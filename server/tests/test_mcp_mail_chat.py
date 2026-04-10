from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from starlette.requests import Request

from aweb.mcp import auth as mcp_auth
from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import chat as chat_tools
from aweb.mcp.tools import mail as mail_tools


class DBInfra:
    def __init__(self, aweb_db):
        self._aweb_db = aweb_db

    def get_manager(self, name: str):
        if name != "aweb":
            raise KeyError(name)
        return self._aweb_db


def _request_with_headers(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/mcp",
            "query_string": b"",
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
            "http_version": "1.1",
        }
    )


@pytest.mark.asyncio
async def test_mcp_auth_prefers_certificate_identity_fields(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    agent_id = uuid4()
    did_key = "did:key:z6MkAlice"

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_id,
        "acme.com",
        "ops",
        "did:key:z6MkTeam",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, lifetime, status)
        VALUES ($1, $2, $3, $4, 'persistent', 'active')
        """,
        agent_id,
        team_id,
        did_key,
        "alice",
    )

    async def _fake_verify_request_certificate(_request, _db_infra):
        return {
            "team_id": team_id,
            "did_key": did_key,
            "alias": "alice",
            "member_did_aw": "did:aw:alice",
            "member_address": "acme.com/alice",
            "lifetime": "persistent",
            "certificate_id": "cert-1",
        }

    monkeypatch.setattr(mcp_auth, "verify_request_certificate", _fake_verify_request_certificate)

    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=DBInfra(aweb_cloud_db.aweb_db))
    ctx = await middleware._resolve_auth(
        _request_with_headers(
            {
                "Authorization": "DIDKey did:key:z6MkAlice signature",
                "X-AWID-Team-Certificate": "certificate",
            }
        )
    )

    assert ctx is not None
    assert ctx.did_aw == "did:aw:alice"
    assert ctx.address == "acme.com/alice"


@pytest.mark.asyncio
async def test_mcp_check_inbox_reads_both_stable_and_current_dids(aweb_cloud_db, monkeypatch):
    now = datetime.now(timezone.utc)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, to_alias, subject, body, priority, created_at)
        VALUES
            ($1, 'did:aw:bob', 'did:aw:alice', 'bob', 'alice', 'stable', 'hello stable', 'normal', $3),
            ($2, 'did:aw:bob', 'did:key:z6MkAliceCurrent', 'bob', 'alice', 'current', 'hello current', 'normal', $3)
        """,
        uuid4(),
        uuid4(),
        now,
    )

    monkeypatch.setattr(
        mail_tools,
        "get_auth",
        lambda: AuthContext(
            team_id="ops:acme.com",
            agent_id=str(uuid4()),
            alias="alice",
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        ),
    )

    data = json.loads(await mail_tools.check_inbox(DBInfra(aweb_cloud_db.aweb_db)))

    assert [item["subject"] for item in data["messages"]] == ["stable", "current"]

    read_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT to_did, read_at
        FROM {{tables.messages}}
        ORDER BY subject ASC
        """
    )
    assert len(read_rows) == 2
    assert all(row["read_at"] is not None for row in read_rows)


@pytest.mark.asyncio
async def test_mcp_chat_pending_aggregates_across_actor_dids(aweb_cloud_db, monkeypatch):
    session_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    bob_message_id = uuid4()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES ($1, $2, 'did:aw:bob', 'bob', 'ping', $3)
        """,
        bob_message_id,
        session_id,
        created_at + timedelta(minutes=1),
    )

    monkeypatch.setattr(
        chat_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=None,
            agent_id=None,
            alias="alice",
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        ),
    )

    data = json.loads(await chat_tools.chat_pending(DBInfra(aweb_cloud_db.aweb_db), None))

    assert len(data["pending"]) == 1
    assert data["pending"][0]["session_id"] == str(session_id)
    assert data["pending"][0]["last_message"] == "ping"


@pytest.mark.asyncio
async def test_mcp_chat_history_and_read_accept_alternate_session_participant_did(aweb_cloud_db, monkeypatch):
    session_id = uuid4()
    message_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=3)

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ($1, 'did:key:z6MkAliceCurrent', 'alice'),
            ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES ($1, $2, 'did:aw:bob', 'bob', 'hello', $3)
        """,
        message_id,
        session_id,
        created_at + timedelta(minutes=1),
    )

    monkeypatch.setattr(
        chat_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=None,
            agent_id=None,
            alias="alice",
            did_key="did:key:z6MkAliceCurrent",
            did_aw="did:aw:alice",
            address="acme.com/alice",
        ),
    )

    history = json.loads(
        await chat_tools.chat_history(
            DBInfra(aweb_cloud_db.aweb_db),
            session_id=str(session_id),
            unread_only=False,
            limit=50,
        )
    )
    assert [item["body"] for item in history["messages"]] == ["hello"]

    read = json.loads(
        await chat_tools.chat_read(
            DBInfra(aweb_cloud_db.aweb_db),
            session_id=str(session_id),
            up_to_message_id=str(message_id),
        )
    )
    assert read["messages_marked"] == 1

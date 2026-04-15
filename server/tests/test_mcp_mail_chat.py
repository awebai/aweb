from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp import auth as mcp_auth
from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import contacts as contacts_tools
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
    workspace_id = uuid4()
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
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, workspace_type)
        VALUES ($1, $2, $3, $4, 'manual')
        """,
        workspace_id,
        team_id,
        agent_id,
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
    assert ctx.workspace_id == str(workspace_id)


@pytest.mark.asyncio
async def test_mcp_auth_accepts_raw_manager(aweb_cloud_db, monkeypatch):
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

    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=aweb_cloud_db.aweb_db)
    ctx = await middleware._resolve_auth(
        _request_with_headers(
            {
                "Authorization": "DIDKey did:key:z6MkAlice signature",
                "X-AWID-Team-Certificate": "certificate",
            }
        )
    )

    assert ctx is not None
    assert ctx.agent_id == str(agent_id)
    assert ctx.did_aw == "did:aw:alice"


@pytest.mark.asyncio
async def test_mcp_auth_accepts_trusted_proxy_headers(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    internal_team_id = str(uuid4())
    agent_id = uuid4()
    workspace_id = uuid4()
    secret = "proxy-secret"

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'ops', 'did:key:z6MkTeam')
        """,
        team_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, address, alias, lifetime, status)
        VALUES ($1, $2, 'did:key:z6MkAlice', 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'active')
        """,
        agent_id,
        team_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}}
            (workspace_id, team_id, agent_id, alias, workspace_type)
        VALUES ($1, $2, $3, 'alice', 'hosted_mcp')
        """,
        workspace_id,
        team_id,
        agent_id,
    )

    async def _fake_resolve_proxy_team_id(_aweb_db, _internal_team_id: str) -> str:
        return team_id

    monkeypatch.setattr(mcp_auth, "_resolve_proxy_team_id", _fake_resolve_proxy_team_id)
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)

    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=DBInfra(aweb_cloud_db.aweb_db))
    ctx = await middleware._resolve_auth(
        _request_with_headers(
            {
                "X-Team-ID": internal_team_id,
                "X-AWEB-Actor-ID": str(agent_id),
                "X-AWEB-Auth": build_internal_auth_header_value(
                    secret=secret,
                    team_id=internal_team_id,
                    principal_type="m",
                    principal_id=str(uuid4()),
                    actor_id=str(agent_id),
                ),
            }
        )
    )

    assert ctx is not None
    assert ctx.team_id == team_id
    assert ctx.agent_id == str(agent_id)
    assert ctx.workspace_id == str(workspace_id)
    assert ctx.alias == "alice"
    assert ctx.did_key == "did:key:z6MkAlice"
    assert ctx.did_aw == "did:aw:alice"
    assert ctx.address == "acme.com/alice"


@pytest.mark.asyncio
async def test_mcp_auth_rejects_bad_trusted_proxy_signature(aweb_cloud_db, monkeypatch):
    secret = "proxy-secret"
    team_id = str(uuid4())
    principal_id = str(uuid4())
    actor_id = str(uuid4())
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)

    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=DBInfra(aweb_cloud_db.aweb_db))
    with pytest.raises(HTTPException) as exc_info:
        await middleware._resolve_auth(
            _request_with_headers(
                {
                    "X-Team-ID": team_id,
                    "X-AWEB-Actor-ID": actor_id,
                    "X-AWEB-Auth": f"v2:{team_id}:m:{principal_id}:{actor_id}:wronghex",
                }
            )
        )

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_mcp_auth_ignores_trusted_proxy_headers_when_not_enabled(aweb_cloud_db, monkeypatch):
    secret = "proxy-secret"
    monkeypatch.delenv("AWEB_TRUST_PROXY_HEADERS", raising=False)
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)

    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=DBInfra(aweb_cloud_db.aweb_db))
    ctx = await middleware._resolve_auth(
        _request_with_headers(
            {
                "X-Team-ID": str(uuid4()),
                "X-AWEB-Actor-ID": str(uuid4()),
                "X-AWEB-Auth": build_internal_auth_header_value(
                    secret=secret,
                    team_id=str(uuid4()),
                    principal_type="m",
                    principal_id=str(uuid4()),
                    actor_id=str(uuid4()),
                ),
            }
        )
    )

    assert ctx is None


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


@pytest.mark.asyncio
async def test_mcp_contacts_accept_equivalent_identity_owner_did(aweb_cloud_db, monkeypatch):
    contact_id = uuid4()
    did_key = "did:key:z6MkAliceCurrent"
    did_aw = "did:aw:alice"

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (contact_id, owner_did, contact_address, label, created_at)
        VALUES ($1, $2, 'acme.com/bob', 'Bob', NOW())
        """,
        contact_id,
        did_key,
    )

    monkeypatch.setattr(
        contacts_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=None,
            agent_id=None,
            alias="alice",
            did_key=did_key,
            did_aw=did_aw,
            address="acme.com/alice",
        ),
    )

    listed = json.loads(await contacts_tools.contacts_list(DBInfra(aweb_cloud_db.aweb_db)))
    assert [item["contact_address"] for item in listed["contacts"]] == ["acme.com/bob"]

    removed = json.loads(await contacts_tools.contacts_remove(DBInfra(aweb_cloud_db.aweb_db), contact_id=str(contact_id)))
    assert removed["status"] == "removed"

    remaining = await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT COUNT(*) FROM {{tables.contacts}} WHERE owner_did = $1",
        did_key,
    )
    assert remaining == 0

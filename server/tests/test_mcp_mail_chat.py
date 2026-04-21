from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from awid.did import did_from_public_key, generate_keypair
from awid.registry import Address
from awid.signing import sign_message
from aweb.internal_auth import build_internal_auth_header_value
from aweb.identity_auth_deps import IdentityAuth
from aweb.mcp import auth as mcp_auth
from aweb.mcp.auth import AuthContext
from aweb.mcp.signing import (
    HostedMessageSigningResult,
    canonical_signed_payload,
)
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


async def _insert_mcp_chat_agents(aweb_db, *, team_id: str, alice_agent_id, bob_agent_id, alice_did: str) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'ops', 'did:key:z6MkTeam')
        """,
        team_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, address, alias, lifetime, status, messaging_policy)
        VALUES
            ($1, $3, $4, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'active', 'everyone'),
            ($2, $3, 'did:key:z6MkBob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'active', 'everyone')
        """,
        alice_agent_id,
        bob_agent_id,
        team_id,
        alice_did,
    )


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
async def test_mcp_auth_enriches_identity_auth_from_agent_row(aweb_cloud_db, monkeypatch):
    team_id = "ops:gsk.aweb.ai"
    agent_id = uuid4()
    did_key = "did:key:z6MkGsk"

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'gsk.aweb.ai', 'ops', 'did:key:z6MkTeam')
        """,
        team_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, lifetime, status)
        VALUES ($1, $2, $3, 'gsk', 'ephemeral', 'active')
        """,
        agent_id,
        team_id,
        did_key,
    )

    async def _fake_resolve_identity_auth(_request):
        return IdentityAuth(did_key=did_key, did_aw=None, address=None)

    monkeypatch.setattr(mcp_auth, "resolve_identity_auth", _fake_resolve_identity_auth)

    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=DBInfra(aweb_cloud_db.aweb_db))
    ctx = await middleware._resolve_auth(
        _request_with_headers({"Authorization": f"DIDKey {did_key} signature"})
    )

    assert ctx is not None
    assert ctx.did_key == did_key
    assert ctx.team_id == team_id
    assert ctx.agent_id == str(agent_id)
    assert ctx.alias == "gsk"


@pytest.mark.asyncio
async def test_mcp_auth_accepts_trusted_proxy_headers(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
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

    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)

    user_id = str(uuid4())
    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=DBInfra(aweb_cloud_db.aweb_db))
    ctx = await middleware._resolve_auth(
        _request_with_headers(
            {
                "X-Team-ID": team_id,
                "X-User-ID": user_id,
                "X-AWEB-Actor-ID": str(agent_id),
                "X-AWEB-Auth": build_internal_auth_header_value(
                    secret=secret,
                    team_id=team_id,
                    principal_type="u",
                    principal_id=user_id,
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
    team_id = "ops:acme.com"
    user_id = str(uuid4())
    actor_id = str(uuid4())
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)

    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=DBInfra(aweb_cloud_db.aweb_db))
    with pytest.raises(HTTPException) as exc_info:
        await middleware._resolve_auth(
            _request_with_headers(
                {
                    "X-Team-ID": team_id,
                    "X-User-ID": user_id,
                    "X-AWEB-Actor-ID": actor_id,
                    "X-AWEB-Auth": build_internal_auth_header_value(
                        secret="wrong-secret",
                        team_id=team_id,
                        principal_type="u",
                        principal_id=user_id,
                        actor_id=actor_id,
                    ),
                }
            )
        )

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_team_id", [
    "ops:acme.com:evil",
    "bad team:acme.com",
    "ops:http://evil",
    "OPS:ACME.COM",
    "ops:acme..com",
    "ops:acme.com.",
    str(uuid4()),
    "",
    "nocolon",
])
async def test_mcp_auth_rejects_invalid_proxy_team_id(aweb_cloud_db, monkeypatch, bad_team_id):
    secret = "proxy-secret"
    actor_id = str(uuid4())
    user_id = str(uuid4())
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", secret)

    middleware = mcp_auth.MCPAuthMiddleware(app=lambda *_args, **_kwargs: None, db_infra=DBInfra(aweb_cloud_db.aweb_db))
    with pytest.raises(HTTPException) as exc_info:
        await middleware._resolve_auth(
            _request_with_headers(
                {
                    "X-Team-ID": bad_team_id,
                    "X-User-ID": user_id,
                    "X-AWEB-Actor-ID": actor_id,
                    "X-AWEB-Auth": build_internal_auth_header_value(
                        secret=secret,
                        team_id=bad_team_id,
                        principal_type="u",
                        principal_id=user_id,
                        actor_id=actor_id,
                    ),
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
async def test_mcp_send_mail_uses_hosted_signer_for_trusted_proxy(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    alice_agent_id = uuid4()
    workspace_id = uuid4()
    bob_agent_id = uuid4()
    alice_sk, alice_pub = generate_keypair()
    alice_did = did_from_public_key(alice_pub)

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
            (agent_id, team_id, did_key, did_aw, address, alias, lifetime, status, messaging_policy)
        VALUES
            ($1, $3, $4, 'did:aw:alice', 'acme.com/alice', 'alice', 'persistent', 'active', 'everyone'),
            ($2, $3, 'did:key:z6MkBob', 'did:aw:bob', 'acme.com/bob', 'bob', 'persistent', 'active', 'everyone')
        """,
        alice_agent_id,
        bob_agent_id,
        team_id,
        alice_did,
    )

    monkeypatch.setattr(
        mail_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            workspace_id=str(workspace_id),
            alias="alice",
            did_key=alice_did,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            trusted_proxy=True,
        ),
    )

    seen: list[dict] = []

    async def _signer(**kwargs) -> HostedMessageSigningResult:
        seen.append(kwargs)
        signed_payload = canonical_signed_payload(kwargs["payload"])
        return HostedMessageSigningResult(
            from_did=alice_did,
            signature=sign_message(alice_sk, signed_payload.encode("utf-8")),
            signed_payload=signed_payload,
            signing_key_id=alice_did,
        )

    result = json.loads(
        await mail_tools.send_mail(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            hosted_signer=_signer,
            to="bob",
            subject="hello",
            body="from mcp",
            priority="urgent",
        )
    )

    assert result["status"] == "delivered"
    assert len(seen) == 1
    assert seen[0]["message_type"] == "mail"
    assert seen[0]["agent_id"] == str(alice_agent_id)
    assert seen[0]["workspace_id"] == str(workspace_id)
    assert seen[0]["payload"]["type"] == "mail"
    assert seen[0]["payload"]["from"] == "alice"
    assert seen[0]["payload"]["from_did"] == alice_did
    assert seen[0]["payload"]["from_stable_id"] == "did:aw:alice"
    assert seen[0]["payload"]["to"] == "bob"
    assert seen[0]["payload"]["to_did"] == "did:key:z6MkBob"
    assert seen[0]["payload"]["to_stable_id"] == "did:aw:bob"
    assert seen[0]["payload"]["priority"] == "urgent"

    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT * FROM {{tables.messages}}")
    assert row["from_did"] == alice_did
    assert row["signature"]
    assert row["signed_payload"] == canonical_signed_payload(seen[0]["payload"])


@pytest.mark.asyncio
async def test_mcp_send_mail_accepts_external_to_address_without_local_agent(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    alice_agent_id = uuid4()
    alice_sk, alice_pub = generate_keypair()
    del alice_sk
    alice_did = did_from_public_key(alice_pub)

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
            (agent_id, team_id, did_key, did_aw, address, alias, lifetime, status, messaging_policy)
        VALUES (
            $1, $2, $3, 'did:aw:alice', 'acme.com/alice',
            'alice', 'persistent', 'active', 'everyone'
        )
        """,
        alice_agent_id,
        team_id,
        alice_did,
    )

    monkeypatch.setattr(
        mail_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            workspace_id="",
            alias="alice",
            did_key=alice_did,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            trusted_proxy=False,
        ),
    )

    class _Registry:
        async def resolve_address(self, domain: str, name: str, *, did_key: str | None = None):
            assert (domain, name, did_key) == ("otherco.com", "bob", alice_did)
            return Address(
                address_id="addr-2",
                domain="otherco.com",
                name="bob",
                did_aw="did:aw:bob",
                current_did_key="did:key:bob",
                reachability="public",
                created_at=datetime.now(timezone.utc).isoformat(),
            )

    result = json.loads(
        await mail_tools.send_mail(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=_Registry(),
            hosted_signer=None,
            to="otherco.com/bob",
            subject="external",
            body="hello external bob",
        )
    )

    assert result["status"] == "delivered"
    assert result["to"] == "bob"
    message = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT from_did, to_did, to_agent_id, to_alias, from_address
        FROM {{tables.messages}}
        WHERE subject = 'external'
        """
    )
    assert message["from_did"] == "did:aw:alice"
    assert message["to_did"] == "did:aw:bob"
    assert message["to_agent_id"] is None
    assert message["to_alias"] == "bob"
    assert message["from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_mcp_send_mail_fails_closed_for_trusted_proxy_without_signer(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    alice_agent_id = uuid4()
    workspace_id = uuid4()
    bob_agent_id = uuid4()

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
            (agent_id, team_id, did_key, alias, lifetime, status, messaging_policy)
        VALUES
            ($1, $3, 'did:key:z6MkAlice', 'alice', 'persistent', 'active', 'everyone'),
            ($2, $3, 'did:key:z6MkBob', 'bob', 'persistent', 'active', 'everyone')
        """,
        alice_agent_id,
        bob_agent_id,
        team_id,
    )

    monkeypatch.setattr(
        mail_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            alias="alice",
            did_key="did:key:z6MkAlice",
            trusted_proxy=True,
        ),
    )

    result = json.loads(
        await mail_tools.send_mail(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            to="bob",
            body="unsigned should not send",
        )
    )

    assert result["error"] == "hosted custodial signer is not configured"
    count = await aweb_cloud_db.aweb_db.fetch_val("SELECT COUNT(*) FROM {{tables.messages}}")
    assert count == 0


@pytest.mark.asyncio
async def test_mcp_send_mail_fails_closed_for_trusted_proxy_without_workspace_id(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    alice_agent_id = uuid4()
    bob_agent_id = uuid4()

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
            (agent_id, team_id, did_key, alias, lifetime, status, messaging_policy)
        VALUES
            ($1, $3, 'did:key:z6MkAlice', 'alice', 'persistent', 'active', 'everyone'),
            ($2, $3, 'did:key:z6MkBob', 'bob', 'persistent', 'active', 'everyone')
        """,
        alice_agent_id,
        bob_agent_id,
        team_id,
    )

    monkeypatch.setattr(
        mail_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            alias="alice",
            did_key="did:key:z6MkAlice",
            trusted_proxy=True,
        ),
    )

    async def _signer(**_kwargs):
        raise AssertionError("signer should not be called without workspace_id")

    result = json.loads(
        await mail_tools.send_mail(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            hosted_signer=_signer,
            to="bob",
            body="unsigned should not send",
        )
    )

    assert result["error"] == "hosted custodial signer requires workspace_id"
    count = await aweb_cloud_db.aweb_db.fetch_val("SELECT COUNT(*) FROM {{tables.messages}}")
    assert count == 0


@pytest.mark.asyncio
async def test_mcp_chat_send_uses_hosted_signer_for_trusted_proxy(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    alice_agent_id = uuid4()
    workspace_id = uuid4()
    bob_agent_id = uuid4()
    alice_sk, alice_pub = generate_keypair()
    alice_did = did_from_public_key(alice_pub)

    await _insert_mcp_chat_agents(
        aweb_cloud_db.aweb_db,
        team_id=team_id,
        alice_agent_id=alice_agent_id,
        bob_agent_id=bob_agent_id,
        alice_did=alice_did,
    )

    monkeypatch.setattr(
        chat_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            workspace_id=str(workspace_id),
            alias="alice",
            did_key=alice_did,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            trusted_proxy=True,
        ),
    )

    seen: list[dict] = []

    async def _signer(**kwargs) -> HostedMessageSigningResult:
        seen.append(kwargs)
        signed_payload = canonical_signed_payload(kwargs["payload"])
        return HostedMessageSigningResult(
            from_did=alice_did,
            signature=sign_message(alice_sk, signed_payload.encode("utf-8")),
            signed_payload=signed_payload,
        )

    result = json.loads(
        await chat_tools.chat_send(
            DBInfra(aweb_cloud_db.aweb_db),
            None,
            registry_client=None,
            hosted_signer=_signer,
            to_alias="bob",
            message="hello chat",
            leaving=True,
        )
    )

    assert result["delivered"] is True
    assert len(seen) == 1
    assert seen[0]["message_type"] == "chat"
    assert seen[0]["workspace_id"] == str(workspace_id)
    assert seen[0]["payload"]["type"] == "chat"
    assert seen[0]["payload"]["from"] == "alice"
    assert seen[0]["payload"]["from_did"] == alice_did
    assert seen[0]["payload"]["to"] == "bob"
    assert seen[0]["payload"]["to_did"] == "did:key:z6MkBob"
    assert seen[0]["payload"]["to_stable_id"] == "did:aw:bob"
    assert seen[0]["payload"]["sender_leaving"] is True

    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT * FROM {{tables.chat_messages}}")
    assert row["from_did"] == alice_did
    assert row["signature"]
    assert row["signed_payload"] == canonical_signed_payload(seen[0]["payload"])


@pytest.mark.asyncio
async def test_mcp_chat_send_accepts_external_to_address_without_local_agent(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    alice_agent_id = uuid4()
    alice_sk, alice_pub = generate_keypair()
    del alice_sk
    alice_did = did_from_public_key(alice_pub)

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
            (agent_id, team_id, did_key, did_aw, address, alias, lifetime, status, messaging_policy)
        VALUES (
            $1, $2, $3, 'did:aw:alice', 'acme.com/alice',
            'alice', 'persistent', 'active', 'everyone'
        )
        """,
        alice_agent_id,
        team_id,
        alice_did,
    )

    monkeypatch.setattr(
        chat_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            workspace_id="",
            alias="alice",
            did_key=alice_did,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            trusted_proxy=False,
        ),
    )

    class _Registry:
        async def resolve_address(self, domain: str, name: str, *, did_key: str | None = None):
            assert (domain, name, did_key) == ("otherco.com", "bob", alice_did)
            return Address(
                address_id="addr-2",
                domain="otherco.com",
                name="bob",
                did_aw="did:aw:bob",
                current_did_key="did:key:bob",
                reachability="public",
                created_at=datetime.now(timezone.utc).isoformat(),
            )

    result = json.loads(
        await chat_tools.chat_send(
            DBInfra(aweb_cloud_db.aweb_db),
            None,
            registry_client=_Registry(),
            hosted_signer=None,
            to_address="otherco.com/bob",
            message="hello external bob",
        )
    )

    assert result["delivered"] is True
    participant = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT did, agent_id, alias, address
        FROM {{tables.chat_participants}}
        WHERE did = 'did:aw:bob'
        """
    )
    assert participant["agent_id"] is None
    assert participant["alias"] == "bob"
    assert participant["address"] == "otherco.com/bob"
    message = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_did, from_address FROM {{tables.chat_messages}}"
    )
    assert message["from_did"] == "did:aw:alice"
    assert message["from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_mcp_chat_send_existing_session_uses_hosted_signer(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    alice_agent_id = uuid4()
    workspace_id = uuid4()
    bob_agent_id = uuid4()
    session_id = uuid4()
    alice_sk, alice_pub = generate_keypair()
    alice_did = did_from_public_key(alice_pub)
    await _insert_mcp_chat_agents(
        aweb_cloud_db.aweb_db,
        team_id=team_id,
        alice_agent_id=alice_agent_id,
        bob_agent_id=bob_agent_id,
        alice_did=alice_did,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, $2, 'alice')
        """,
        session_id,
        team_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias)
        VALUES
            ($1, $2, $3, 'alice'),
            ($1, 'did:key:z6MkBob', $4, 'bob')
        """,
        session_id,
        alice_did,
        alice_agent_id,
        bob_agent_id,
    )

    monkeypatch.setattr(
        chat_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            workspace_id=str(workspace_id),
            alias="alice",
            did_key=alice_did,
            did_aw="did:aw:alice",
            address="acme.com/alice",
            trusted_proxy=True,
        ),
    )
    seen: list[dict] = []

    async def _signer(**kwargs) -> dict:
        seen.append(kwargs)
        signed_payload = canonical_signed_payload(kwargs["payload"])
        return {
            "from_did": alice_did,
            "signature": sign_message(alice_sk, signed_payload.encode("utf-8")),
            "signed_payload": signed_payload,
        }

    result = json.loads(
        await chat_tools.chat_send(
            DBInfra(aweb_cloud_db.aweb_db),
            None,
            registry_client=None,
            hosted_signer=_signer,
            session_id=str(session_id),
            message="existing session",
            wait=True,
            wait_seconds=7,
            hang_on=True,
        )
    )

    assert result["delivered"] is True
    assert len(seen) == 1
    assert seen[0]["message_type"] == "chat"
    assert seen[0]["payload"]["from_did"] == alice_did
    assert seen[0]["payload"]["wait_seconds"] == 7
    assert seen[0]["payload"]["hang_on"] is True
    assert seen[0]["payload"]["to"] == "bob"
    assert seen[0]["payload"]["to_did"] == "did:key:z6MkBob"
    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT * FROM {{tables.chat_messages}}")
    assert row["from_did"] == alice_did
    assert row["signature"]
    assert row["signed_payload"] == canonical_signed_payload(seen[0]["payload"])


@pytest.mark.asyncio
async def test_mcp_chat_send_rejects_forged_hosted_signature(aweb_cloud_db, monkeypatch):
    team_id = "ops:acme.com"
    alice_agent_id = uuid4()
    workspace_id = uuid4()
    bob_agent_id = uuid4()
    alice_sk, alice_pub = generate_keypair()
    alice_did = did_from_public_key(alice_pub)
    other_sk, _ = generate_keypair()
    await _insert_mcp_chat_agents(
        aweb_cloud_db.aweb_db,
        team_id=team_id,
        alice_agent_id=alice_agent_id,
        bob_agent_id=bob_agent_id,
        alice_did=alice_did,
    )

    monkeypatch.setattr(
        chat_tools,
        "get_auth",
        lambda: AuthContext(
            team_id=team_id,
            agent_id=str(alice_agent_id),
            workspace_id=str(workspace_id),
            alias="alice",
            did_key=alice_did,
            trusted_proxy=True,
        ),
    )

    async def _signer(**kwargs) -> dict:
        signed_payload = canonical_signed_payload(kwargs["payload"])
        return {
            "from_did": alice_did,
            "signature": sign_message(other_sk, signed_payload.encode("utf-8")),
            "signed_payload": signed_payload,
        }

    result = json.loads(
        await chat_tools.chat_send(
            DBInfra(aweb_cloud_db.aweb_db),
            None,
            registry_client=None,
            hosted_signer=_signer,
            to_alias="bob",
            message="forged",
        )
    )

    assert result["error"] == "hosted custodial signer returned invalid signature"
    count = await aweb_cloud_db.aweb_db.fetch_val("SELECT COUNT(*) FROM {{tables.chat_messages}}")
    assert count == 0


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

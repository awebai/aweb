"""Sender address policy with real OSS/AWID/DB/Redis and authenticated HTTP."""

from uuid import UUID

from messaging_actor_support import admit_privacy_actor

import pytest
from aweb.messaging.alias_targets import derive_team_address
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401

__all__ = ["privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope,address", [("global", ""), ("local", ""), ("global", "example.test/alice")]
)
async def test_sender_address_preserves_team_context(privacy_app, scope, address):
    env = privacy_app
    actor = await admit_privacy_actor(
        env, "alice", address=address, local=scope == "local"
    )
    await admit_privacy_actor(env, "bob", local=True)
    stable = actor.stable_id or None
    expected = address or (
        derive_team_address(TEAM, "alice") if scope == "local" else None
    )
    mail = await _request(
        env,
        "alice",
        "POST",
        "/v1/messages",
        {
            "to_alias": "bob",
            "subject": "scope",
            "body": "mail control",
        },
    )
    assert mail.status_code == 200, mail.text
    chat = await _request(
        env,
        "alice",
        "POST",
        "/v1/chat/sessions",
        {
            "to_aliases": ["bob"],
            "message": "chat control",
        },
    )
    assert chat.status_code == 200, chat.text
    mail_row = await env.db.fetch_one(
        "SELECT from_address, from_alias, from_did FROM {{tables.messages}} WHERE message_id=$1",
        UUID(mail.json()["message_id"]),
    )
    chat_row = await env.db.fetch_one(
        "SELECT from_address, from_alias, from_did FROM {{tables.chat_messages}} WHERE message_id=$1",
        UUID(chat.json()["message_id"]),
    )
    for row in (mail_row, chat_row):
        assert row["from_address"] == expected
        assert row["from_alias"] == "alice"
        assert row["from_did"] == (stable or actor.did)
    for path in [
        f"/v1/messages/{mail.json()['message_id']}",
        f"/v1/chat/sessions/{chat.json()['session_id']}/messages",
    ]:
        response = await _request(env, "bob", "GET", path)
        assert response.status_code == 200, response.text
        data = response.json()
        item = data["messages"][0] if "messages" in data else data
        assert (item.get("from_address") or None) == expected
        assert item.get("from_alias", item.get("from_agent")) == "alice"
        assert item["sender_membership"]["team_id"] == TEAM
        assert item["sender_membership"]["state"] == "active"
        assert item["sender_membership"]["member_did_aw"] == stable


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope,address", [("global", ""), ("local", ""), ("global", "example.test/alice")]
)
async def test_mcp_sender_scope_from_authenticated_projection(
    privacy_app, scope, address
):
    from starlette.requests import Request
    from aweb.mcp.auth import MCPAuthMiddleware
    from aweb.mcp.tools.federation import mcp_messaging_auth
    from aweb.mcp.tools.mail import _sender_address as mail_address
    from aweb.mcp.tools.chat import _sender_address as chat_address
    from test_messages_http import _signed_identity_headers

    env = privacy_app
    actor = await admit_privacy_actor(
        env, "alice", address=address, local=scope == "local"
    )
    headers = _signed_identity_headers(actor.sk, actor.did, "", b"")
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/mcp",
            "app": env.app,
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )
    # Real signature verification, projection lookup and revocation read; no
    # middleware override or fabricated HTTP response.
    auth = await MCPAuthMiddleware(env.app, env.infra)._resolve_auth(request)
    assert auth.identity_scope == scope
    assert auth.team_id == TEAM
    assert auth.alias == "alice"
    projected = mcp_messaging_auth(auth)
    assert projected.identity_scope == scope
    assert projected.team_id == TEAM
    expected = address or (
        derive_team_address(TEAM, "alice") if scope == "local" else None
    )
    assert mail_address(auth) == chat_address(auth) == expected


def test_sender_address_missing_scope_keeps_legacy_label():
    from aweb.mcp.auth import AuthContext
    from aweb.mcp.tools.federation import mcp_messaging_auth
    from aweb.messaging.sender_address import sender_address
    from aweb.identity_metadata import routable_chat_address

    auth = AuthContext(
        team_id=TEAM,
        agent_id=None,
        alias="alice",
        did_key="did:key:alice",
        did_aw="did:aw:alice",
    )
    assert sender_address(auth) == derive_team_address(TEAM, "alice")
    assert sender_address(mcp_messaging_auth(auth)) == derive_team_address(
        TEAM, "alice"
    )
    assert (
        routable_chat_address(
            {"stable_id": "did:aw:alice", "team_id": TEAM}, TEAM, "alice"
        )
        == "alice"
    )

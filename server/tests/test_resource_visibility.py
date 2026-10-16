"""Hidden resources and absent IDs have one wire response (aweb-acdc).

The real app, authentication, database and registry are used throughout. Thin
embedding routes also exercise service guards that public HTTP prechecks hide.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi import Depends

from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from aweb.messaging import chat, conversations
from awid.signing import sign_message
from test_agent_status_host_http import _team_request
from test_dashboard import _make_jwt
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _make_keypair


def _wire(response):
    return response.status_code, response.content, response.headers.get("content-type")


def _same_not_found(hidden, missing):
    assert _wire(hidden) == _wire(missing)
    assert hidden.status_code == 404
    assert hidden.json() == {"detail": "Not found"}


async def _mail(env):
    response = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": env.actors["bob"].did, "body": "private mail",
    })
    assert response.status_code == 200, response.text
    return response.json()["conversation_id"]


async def _chat(env):
    response = await _request(env, "alice", "POST", "/v1/chat/sessions", {
        "to_dids": [env.actors["bob"].did], "message": "private chat",
    })
    assert response.status_code == 200, response.text
    return response.json()


async def _set_state(env, cid, state):
    await env.db.execute(
        "UPDATE {{tables.conversations}} SET status=$2, expires_at=$3 WHERE conversation_id=$1",
        UUID(cid), state,
        datetime.now(timezone.utc) + timedelta(hours=-1 if state == "expired" else 1),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_mail_conversation_read_hides_nonparticipant_and_wrong_type(privacy_app, kind):
    env = privacy_app
    cid = await _mail(env) if kind == "mail" else (await _chat(env))["session_id"]
    hidden = await _request(env, "carol", "GET", f"/v1/messages/conversations/{cid}")
    missing = await _request(env, "carol", "GET", f"/v1/messages/conversations/{uuid4()}")
    _same_not_found(hidden, missing)
    member = await _request(env, "bob", "GET", f"/v1/messages/conversations/{cid}")
    assert member.status_code == (200 if kind == "mail" else 422)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["active", "closed", "expired"])
async def test_mail_continuation_checks_participation_before_state(privacy_app, state):
    env = privacy_app
    cid = await _mail(env)
    await _set_state(env, cid, state)
    before = await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}")
    async def send(actor, target):
        return await _request(env, actor, "POST", "/v1/messages", {"conversation_id": target, "body": "reply"})
    _same_not_found(await send("carol", cid), await send("carol", str(uuid4())))
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == before
    member = await send("bob", cid)
    assert member.status_code == (200 if state == "active" else 403), member.text
    if state != "active":
        assert member.json()["detail"] == f"Conversation is {state}"


def _embedding_service_route(env, operation, message_id=None):
    # Embedding hosts call these same public service functions directly.
    async def endpoint(resource_id: str, auth: MessagingAuth = Depends(get_messaging_auth)):
        did = auth.did_aw or auth.did_key
        if operation == "continue":
            return await conversations.require_active_conversation_participant(
                env.infra, conversation_id=resource_id, authenticated_did=did)
        if operation == "close":
            return await conversations.close_conversation(
                env.infra, conversation_id=resource_id, closed_by_did=did)
        if operation == "history":
            return await chat.get_message_history(env.infra, session_id=UUID(resource_id), participant_did=did)
        if operation == "read":
            return await chat.mark_messages_read(env.infra, session_id=UUID(resource_id),
                                                 participant_did=did, message_ids=[message_id])
        return await chat.mark_messages_read_up_to(env.infra, session_id=UUID(resource_id),
                                                   participant_did=did, up_to_message_id=message_id)
    env.app.add_api_route("/embedding-service/{resource_id}", endpoint, methods=["POST"])


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["continue", "close"])
@pytest.mark.parametrize("state", ["active", "closed", "expired"])
async def test_conversation_service_hides_nonmember_in_every_state(privacy_app, operation, state):
    env = privacy_app
    cid = await _mail(env)
    await _set_state(env, cid, state)
    _embedding_service_route(env, operation)
    hidden = await _request(env, "carol", "POST", f"/embedding-service/{cid}")
    missing = await _request(env, "carol", "POST", f"/embedding-service/{uuid4()}")
    _same_not_found(hidden, missing)
    member = await _request(env, "bob", "POST", f"/embedding-service/{cid}")
    assert member.status_code == (200 if state == "active" else 403), member.text


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["history", "read", "watermark"])
async def test_chat_service_guards_hide_nonparticipant(privacy_app, operation):
    env = privacy_app
    session = await _chat(env)
    _embedding_service_route(env, operation, session["message_id"])
    _same_not_found(
        await _request(env, "carol", "POST", f"/embedding-service/{session['session_id']}"),
        await _request(env, "carol", "POST", f"/embedding-service/{uuid4()}"),
    )
    member = await _request(env, "bob", "POST", f"/embedding-service/{session['session_id']}")
    assert member.status_code == 200, member.text


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["history", "read", "watermark", "stream"])
async def test_chat_http_hides_nonparticipant(privacy_app, operation):
    env = privacy_app
    session = await _chat(env)
    async def request(actor, sid):
        path = f"/v1/chat/sessions/{sid}"
        if operation == "history":
            return await _request(env, actor, "GET", path + "/messages")
        if operation == "stream":
            deadline = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            return await _request(env, actor, "GET", path + "/stream?deadline=" + deadline.replace("+", "%2B"))
        payload = {"message_ids": [session["message_id"]]} if operation == "read" else {"up_to_message_id": session["message_id"]}
        return await _request(env, actor, "POST", path + "/read", payload)
    _same_not_found(await request("carol", session["session_id"]), await request("carol", str(uuid4())))
    assert (await request("bob", session["session_id"])).status_code == 200


async def _foreign_team(env):
    other = "foreign:example.test"
    _, _, did = _make_keypair()
    await env.db.execute("INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1,'example.test','foreign',$2)", other, did)
    return other


@pytest.mark.asyncio
@pytest.mark.parametrize("credential", ["certificate", "internal"])
async def test_installed_apps_hides_unauthorized_and_unknown_team(privacy_app, monkeypatch, credential):
    env = privacy_app
    other = await _foreign_team(env)
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "true")
    async def request(team):
        path = f"/v1/apps/installed?team_id={team}"
        if credential == "certificate":
            return await _team_request(env, "alice", "GET", path)
        principal = str(uuid4())
        actor = str(env.actors["alice"].id)
        signed = build_internal_auth_header_value(secret=os.environ["AWEB_INTERNAL_AUTH_SECRET"],
            team_id=TEAM, principal_type="u", principal_id=principal, actor_id=actor)
        return await env.client.get(path, headers={"X-AWEB-Auth": signed, "X-Team-ID": TEAM,
            "X-User-ID": principal, "X-AWEB-Actor-ID": actor})
    _same_not_found(await request(other), await request("absent:example.test"))
    assert (await request(TEAM)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("resource,column,payload", [
    ("roles", "team_roles_id", {"bundle": {"roles": {}}}),
    ("instructions", "team_instructions_id", {"document": {"body_md": "private instructions"}}),
])
async def test_activation_hides_other_teams_version(privacy_app, resource, column, payload):
    env = privacy_app
    other = await _foreign_team(env)
    created = await _team_request(env, "alice", "POST", f"/v1/{resource}", payload)
    assert created.status_code == 200, created.text
    rid = created.json()[column]
    table = "team_roles" if resource == "roles" else "team_instructions"
    await env.db.execute(f"UPDATE {{{{tables.{table}}}}} SET team_id=$2 WHERE id=$1", UUID(rid), other)
    before = await env.db.fetch_one(f"SELECT * FROM {{{{tables.{table}}}}} WHERE id=$1", UUID(rid))
    async def activate(target):
        return await _team_request(env, "alice", "POST", f"/v1/{resource}/{target}/activate")
    _same_not_found(await activate(rid), await activate(str(uuid4())))
    assert await env.db.fetch_one(f"SELECT * FROM {{{{tables.{table}}}}} WHERE id=$1", UUID(rid)) == before
    await env.db.execute(f"UPDATE {{{{tables.{table}}}}} SET team_id=$2 WHERE id=$1", UUID(rid), TEAM)
    assert (await activate(rid)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("deleted", [False, True])
async def test_heartbeat_hides_other_teams_workspace_before_state(privacy_app, monkeypatch, deleted):
    env = privacy_app
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    other = await _foreign_team(env)
    target = env.actors["bob"].workspace
    await env.db.execute("UPDATE {{tables.workspaces}} SET team_id=$2, deleted_at=$3 WHERE workspace_id=$1",
        target, other, datetime.now(timezone.utc) if deleted else None)
    async def heartbeat(wid):
        return await _team_request(env, "alice", "POST", "/v1/workspaces/heartbeat", {"workspace_id": str(wid), "alias": "alice"})
    _same_not_found(await heartbeat(target), await heartbeat(uuid4()))
    assert (await heartbeat(env.actors["alice"].workspace)).status_code == 200


@pytest.mark.asyncio
async def test_dashboard_wrong_team_is_generic_without_echo(privacy_app):
    env = privacy_app
    await env.registry_db.execute("UPDATE {{tables.teams}} SET visibility='private'")
    path = f"/v1/teams/{TEAM}/agents"
    response = await env.client.get(path, headers={"X-Dashboard-Token": _make_jwt(["other:example.test"])})
    assert response.status_code == 403
    assert response.json() == {"detail": "Not authorized for this team"}
    assert TEAM.encode() not in response.content
    assert (await env.client.get(path)).status_code == 401
    assert (await env.client.get(path, headers={"X-Dashboard-Token": _make_jwt([TEAM])})).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["initial-check", "revoked-during-signing"])
async def test_mcp_chat_hides_missing_and_nonparticipant_on_both_guards(privacy_app, monkeypatch, phase):
    env = privacy_app
    session = await _chat(env)
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "true")
    actor_name = "carol" if phase == "initial-check" else "alice"
    revoked = False

    async def signer(**kwargs):
        nonlocal revoked
        actor = env.actors[actor_name]
        # Custody is an embedding extension point. Revoke the actual row while
        # this callback runs, after the initial check and before the real send.
        if phase == "revoked-during-signing" and actor_name == "alice":
            await env.db.execute("DELETE FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2",
                                 UUID(session["session_id"]), actor.did)
            revoked = True
        payload = canonical_signed_payload(kwargs["payload"])
        return HostedMessageSigningResult(from_did=actor.did, signing_key_id=actor.did,
                                          signed_payload=payload, signature=sign_message(actor.sk, payload.encode()))

    mcp = create_mcp_app(db_infra=env.infra, redis=env.redis,
        registry_client=env.app.state.awid_registry_client, hosted_signer=signer)
    env.app.mount("/visibility-mcp", mcp)
    await mcp.startup()
    try:
        async def call(sid):
            principal = str(uuid4())
            actor = str(env.actors[actor_name].id)
            signed = build_internal_auth_header_value(secret=os.environ["AWEB_INTERNAL_AUTH_SECRET"],
                team_id=TEAM, principal_type="u", principal_id=principal, actor_id=actor)
            return await env.client.post("/visibility-mcp/", headers={
                "Accept": "application/json, text/event-stream", "X-AWEB-Auth": signed,
                "X-Team-ID": TEAM, "X-User-ID": principal, "X-AWEB-Actor-ID": actor,
            }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "send_chat", "arguments": {"conversation_id": sid, "message": "private reply", "plaintext": True},
            }})
        before = await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}")
        hidden = await call(session["session_id"])
        missing = await call(str(uuid4()))
        assert _wire(hidden) == _wire(missing)
        assert hidden.status_code == 200
        answer = json.loads(hidden.json()["result"]["content"][0]["text"])
        assert answer == {"error": "Session not found"}
        assert revoked == (phase == "revoked-during-signing")
        assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == before
        actor_name = "bob"
        neighbor = await call(session["session_id"])
        assert "error" not in json.loads(neighbor.json()["result"]["content"][0]["text"]), neighbor.text
    finally:
        await mcp.shutdown()

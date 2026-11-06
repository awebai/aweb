"""MCP mail and chat tools fire the same mutation hooks as their REST routes.

Exercised through the real mounted MCP app and the REST app over ASGI, with
real PostgreSQL. The embedding application's ``on_mutation`` callback and the
Redis chat-session publish are recorded at their boundaries.
"""

from identity_binding_support import seed_verified_bindings

import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio

from awid.signing import sign_message
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from test_messages_http import (
    _build_test_app,
    _insert_agent,
    _insert_team,
    _make_keypair,
    _signed_identity_headers,
)

TEAM = "ops:acme.com"
INTERNAL_SECRET = "mutation-parity-test-secret"

MESSAGE_SENT_KEYS = {
    "team_id", "from_agent_id", "from_did", "from_did_aw", "to_agent_id", "from_alias",
    "message_id", "conversation_id", "to_alias", "subject", "priority", "content_mode",
}
CHAT_SENT_KEYS = {
    "team_id", "session_id", "conversation_id", "message_id", "from_agent_id", "from_alias",
    "from_did", "from_did_aw", "to_aliases", "preview", "content_mode",
}
ACKNOWLEDGED_KEYS = {"team_id", "agent_id", "alias", "message_id", "from_alias", "subject", "content_mode"}


class _RecordingRedis:
    def __init__(self):
        self.published = []

    async def publish(self, channel, message):
        self.published.append((channel, json.loads(message)))
        return 0


@pytest_asyncio.fixture
async def server(aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    await _insert_team(db, TEAM)
    keys = {}
    agents = {}
    for alias in ("pilot", "bob"):
        sk, _, did_key = _make_keypair()
        keys[alias] = (sk, did_key)
        agents[alias] = await _insert_agent(
            db, team_id=TEAM, alias=alias, did_key=did_key,
            did_aw=f"did:aw:{alias}", address=f"acme.com/{alias}",
        )
        await db.execute(
            """INSERT INTO {{tables.workspaces}}
               (workspace_id, team_id, agent_id, alias, workspace_type)
               VALUES ($1, $2, $3, $4, 'hosted_mcp')""",
            uuid4(), TEAM, UUID(agents[alias]), alias,
        )
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", INTERNAL_SECRET)

    def signer_for(alias):
        sk, did_key = keys[alias]

        async def signer(**kwargs):
            signed = canonical_signed_payload(dict(kwargs["payload"]))
            return HostedMessageSigningResult(
                from_did=did_key, signing_key_id=did_key, signed_payload=signed,
                signature=sign_message(sk, signed.encode()),
            )

        return signer

    current_actor = {"alias": "pilot"}

    async def signer(**kwargs):
        return await signer_for(current_actor["alias"])(**kwargs)

    mutations = []

    async def record_mutation(event_type, context):
        mutations.append((event_type, dict(context)))

    redis = _RecordingRedis()
    app = _build_test_app(db, object())
    seed_verified_bindings(app, *((f"did:aw:{alias}", did, f"acme.com/{alias}")
                                  for alias, (_, did) in keys.items()))
    app.state.on_mutation = record_mutation
    mcp = create_mcp_app(db_infra=app.state.db, redis=redis, hosted_signer=signer)
    app.mount("/mcp", mcp)
    await mcp.startup()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:

            async def mcp_call(alias, tool, **arguments):
                current_actor["alias"] = alias
                principal = str(uuid4())
                headers = {
                    "Accept": "application/json, text/event-stream", "X-Team-ID": TEAM,
                    "X-User-ID": principal, "X-AWEB-Actor-ID": agents[alias],
                    "X-AWEB-Auth": build_internal_auth_header_value(
                        secret=INTERNAL_SECRET, team_id=TEAM,
                        principal_type="u", principal_id=principal, actor_id=agents[alias],
                    ),
                }
                response = await client.post("/mcp/", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments},
                })
                assert response.status_code == 200, response.text
                result = response.json()
                assert "error" not in result, result
                payload = json.loads(result["result"]["content"][0]["text"])
                assert "error" not in payload, payload
                return payload

            async def rest_mail(alias, *, to_alias, body):
                sk, did_key = keys[alias]
                data = json.dumps({"to_alias": to_alias, "subject": "status", "body": body}).encode()
                response = await client.post(
                    "/v1/messages", content=data,
                    headers={
                        "Content-Type": "application/json",
                        **_signed_identity_headers(sk, did_key, "", data),
                    },
                )
                assert response.status_code == 200, response.text
                return response.json()

            yield SimpleNamespace(
                db=db, agents=agents, mutations=mutations, redis=redis,
                mcp_call=mcp_call, rest_mail=rest_mail,
            )
    finally:
        await mcp.shutdown()


def _events(server, event_type):
    return [context for kind, context in server.mutations if kind == event_type]


@pytest.mark.asyncio
async def test_mcp_send_mail_fires_message_sent_like_rest(server):
    # No pilot/bob mail pair exists yet: the new-conversation path.
    fresh = await server.mcp_call("pilot", "send_mail", to="bob", subject="new", body="fresh", plaintext=True)
    rest = await server.rest_mail("bob", to_alias="pilot", body="from rest")
    # The caller explicitly selects the conversation-continuation path.
    continued = await server.mcp_call("pilot", "send_mail", conversation_id=fresh["conversation_id"], subject="re", body="reply", plaintext=True)
    assert continued["conversation_id"] == fresh["conversation_id"]

    events = _events(server, "message.sent")
    assert [event["message_id"] for event in events] == [
        fresh["message_id"], rest["message_id"], continued["message_id"],
    ]
    mcp_events, rest_event = [events[0], events[2]], events[1]
    assert set(rest_event) == MESSAGE_SENT_KEYS
    for event, sent in zip(mcp_events, (fresh, continued)):
        assert set(event) == set(rest_event)
        assert event["team_id"] == TEAM
        assert event["from_agent_id"] == server.agents["pilot"]
        # A continuation retains canonical identity without inventing membership.
        assert event["to_agent_id"] == (server.agents["bob"] if event is events[0] else None)
        assert event["to_alias"] == "bob"
        assert event["from_alias"] == "pilot"
        assert event["from_did_aw"] == "did:aw:pilot"
        assert event["conversation_id"] == sent["conversation_id"]
        assert event["content_mode"] == "legacy_plaintext_v1"
        assert event["priority"] == "normal"
    assert [event["subject"] for event in mcp_events] == ["new", "re"]


@pytest.mark.asyncio
async def test_mcp_check_mail_fires_message_acknowledged_once_per_message(server):
    first = await server.rest_mail("bob", to_alias="pilot", body="one")
    second = await server.rest_mail("bob", to_alias="pilot", body="two")

    await server.mcp_call("pilot", "check_mail")
    acknowledged = _events(server, "message.acknowledged")
    assert sorted(event["message_id"] for event in acknowledged) == sorted(
        [first["message_id"], second["message_id"]]
    )
    for event in acknowledged:
        assert set(event) == ACKNOWLEDGED_KEYS
        assert event["team_id"] == TEAM
        assert event["agent_id"] == server.agents["pilot"]
        assert event["alias"] == "pilot"
        assert event["from_alias"] == "bob"
        assert event["subject"] == "status"
        assert event["content_mode"] == "legacy_plaintext_v1"

    # Already-read mail is not acknowledged again.
    await server.mcp_call("pilot", "check_mail", unread_only=False)
    assert len(_events(server, "message.acknowledged")) == 2


@pytest.mark.asyncio
async def test_mcp_send_chat_fires_chat_message_sent_like_rest(server):
    opened = await server.mcp_call("pilot", "send_chat", to="bob", message="hello bob", plaintext=True)
    continued = await server.mcp_call(
        "pilot", "send_chat", conversation_id=opened["conversation_id"], message="still there?", plaintext=True,
    )

    sent = _events(server, "chat.message_sent")
    assert [event["message_id"] for event in sent] == [opened["message_id"], continued["message_id"]]
    for event in sent:
        assert set(event) == CHAT_SENT_KEYS
        assert event["team_id"] == TEAM
        assert event["session_id"] == opened["conversation_id"]
        assert event["conversation_id"] == opened["conversation_id"]
        assert event["from_agent_id"] == server.agents["pilot"]
        assert event["from_alias"] == "pilot"
        assert event["from_did_aw"] == "did:aw:pilot"
        assert event["to_aliases"] == ["bob"]
        assert event["content_mode"] == "legacy_plaintext_v1"
    assert [event["preview"] for event in sent] == ["hello bob", "still there?"]


@pytest.mark.asyncio
async def test_mcp_mark_chat_read_publishes_read_receipt_like_rest(server):
    opened = await server.mcp_call("bob", "send_chat", to="pilot", message="ping", plaintext=True)
    session_id = opened["conversation_id"]
    before = len(server.redis.published)

    marked = await server.mcp_call(
        "pilot", "mark_chat_read", conversation_id=session_id, message_ids=[opened["message_id"]],
    )
    assert marked["messages_marked"] == 1
    receipts = [
        payload for channel, payload in server.redis.published[before:]
        if payload.get("signal_type") == "read_receipt"
    ]
    assert len(receipts) == 1
    assert receipts[0]["session_id"] == session_id
    assert receipts[0]["message_id"] == opened["message_id"]
    assert receipts[0]["agent_id"] == "did:aw:pilot"

    # Nothing newly read: no receipt, as on the REST route.
    again = await server.mcp_call("pilot", "mark_chat_read", conversation_id=session_id, up_to_message_id=opened["message_id"])
    assert again["messages_marked"] == 0
    assert [
        payload for channel, payload in server.redis.published[before:]
        if payload.get("signal_type") == "read_receipt"
    ] == receipts

"""Room counts join the existing nudge without changing result or read state."""

import json
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from mcp.types import CallToolResult, TextContent

from aweb.mcp import notifications
from aweb.mcp.auth import AuthContext, MCPAuthMiddleware, _auth_context
from test_mcp_notifications import CountDB, infra
from test_team_room import TEAM, headers, metadata, post, privacy_app  # noqa: F401
from test_room_notice_count import admitted


@pytest.fixture
def room_count(monkeypatch):
    token = _auth_context.set(AuthContext(
        team_id="ops:example.com", agent_id=str(uuid4()), alias="actor", did_key="did:key:actor"))
    count = AsyncMock(return_value=0)
    monkeypatch.setattr(notifications, "room_notice_count", count, raising=False)
    try:
        yield count
    finally:
        _auth_context.reset(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("mail,chat,room,expected", [
    (0, 0, 1, "[aweb] You have 1 new team room post. Read the room with room_read."),
    (0, 0, 2, "[aweb] You have 2 new team room posts. Read the room with room_read."),
    (1, 0, 1, "[aweb] You have 1 unread mail message and 1 new team room post. "
              "Read mail with check_mail. Read the room with room_read."),
    (0, 1, 2, "[aweb] You have 1 unread chat message and 2 new team room posts. "
              "Read chats with check_chats and read_chat, then mark them read with mark_chat_read. "
              "Read the room with room_read."),
    (2, 1, 1, "[aweb] You have 2 unread mail messages, 1 unread chat message, and 1 new team room post. "
              "Read mail with check_mail. Read chats with check_chats and read_chat, "
              "then mark them read with mark_chat_read. Read the room with room_read."),
    (1, 1, 1, "[aweb] You have 1 unread mail message, 1 unread chat message, and 1 new team room post. "
              "Read mail with check_mail. Read chats with check_chats and read_chat, "
              "then mark them read with mark_chat_read. Read the room with room_read."),
])
async def test_room_joins_one_block_preserving_the_complete_result(room_count, mail, chat, room, expected):
    room_count.return_value = room
    original = CallToolResult(
        content=[TextContent(type="text", text="original"), TextContent(type="text", text="second")],
        structuredContent={"original": True}, _meta={"opaque": ["keep"]}, vendor_extra="keep")
    before = original.model_dump(mode="json", by_alias=True)
    db = infra(CountDB({"unread_mail": mail, "unread_chat_messages": chat}))
    result = await notifications.append_pending_nudge(original, db)
    room_count.assert_awaited_once_with(db)
    assert result.content[-1].text == expected
    after = result.model_dump(mode="json", by_alias=True)
    assert len(after["content"]) == len(before["content"]) + 1
    after["content"].pop()
    assert after == before
    assert original.model_dump(mode="json", by_alias=True) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["content", "tuple", "structured"])
async def test_room_only_preserves_sdk_return_shapes(room_count, shape):
    room_count.return_value = 1
    content = [TextContent(type="text", text="original")]
    structured = {"original": True}
    inputs = {"content": content, "tuple": (content, structured), "structured": structured}
    result = await notifications.append_pending_nudge(
        inputs[shape], infra(CountDB({"unread_mail": 0, "unread_chat_messages": 0})))
    assert len(result.content) == 2
    assert result.content[-1].text == "[aweb] You have 1 new team room post. Read the room with room_read."
    assert result.structuredContent == (None if shape == "content" else structured)
    assert result.content[0].text == (json.dumps(structured, indent=2) if shape == "structured" else "original")


@pytest.mark.asyncio
@pytest.mark.parametrize("room", [None, 0, RuntimeError("room count failed"), True, -1, "sender text"])
async def test_unavailable_or_empty_room_preserves_mail_guidance(room_count, room):
    if isinstance(room, Exception):
        room_count.side_effect = room
    else:
        room_count.return_value = room
    original = CallToolResult(content=[TextContent(type="text", text="original")])
    result = await notifications.append_pending_nudge(
        original, infra(CountDB({"unread_mail": 1, "unread_chat_messages": 0})))
    room_count.assert_awaited_once()
    assert result.content[-1].text == "[aweb] You have 1 unread mail message. Read it with check_mail."
    assert result.content[:-1] == original.content


@pytest.mark.asyncio
@pytest.mark.parametrize("room", [None, 0, RuntimeError("room count failed")])
async def test_no_known_work_returns_original_object(room_count, room):
    if isinstance(room, Exception):
        room_count.side_effect = room
    else:
        room_count.return_value = room
    original = CallToolResult(content=[TextContent(type="text", text="original")])
    result = await notifications.append_pending_nudge(
        original, infra(CountDB({"unread_mail": 0, "unread_chat_messages": 0})))
    assert result is original


@pytest.mark.asyncio
@pytest.mark.parametrize("counts", [None, RuntimeError("mail/chat count failed")])
async def test_room_count_survives_unavailable_other_counts(room_count, counts):
    room_count.return_value = 1
    result = await notifications.append_pending_nudge([], infra(CountDB(counts)))
    assert result.content[-1].text == "[aweb] You have 1 new team room post. Read the room with room_read."


@pytest.mark.asyncio
async def test_error_and_unscoped_results_never_query_room(room_count):
    original = CallToolResult(content=[TextContent(type="text", text="error")], isError=True)
    assert await notifications.append_pending_nudge(original, None) is original
    token = _auth_context.set(None)
    try:
        assert await notifications.append_pending_nudge(original.content, None) is original.content
    finally:
        _auth_context.reset(token)
    room_count.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("proxy", [False, True], ids=["certificate", "proxy"])
async def test_mounted_room_hint_is_actor_bound_non_consuming_and_clears_after_read(privacy_app, monkeypatch, proxy):
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from aweb.internal_auth import build_internal_auth_header_value
    from aweb.mcp.tools.room import room_read

    env = privacy_app
    await admitted(env)
    original = CallToolResult(content=[TextContent(type="text", text="original")],
                              structuredContent={"original": True}, _meta={"keep": True})
    before = original.model_dump(mode="json", by_alias=True)

    class Probe:
        async def __call__(self, scope, receive, send):
            query = Request(scope).query_params
            completed = original
            if "read" in query:
                completed = CallToolResult(content=[TextContent(type="text", text=await room_read(
                    env.infra, after=query.get("after"), limit=1))])
            result = await notifications.append_pending_nudge(completed, env.infra)
            await JSONResponse(result.model_dump(mode="json", by_alias=True))(scope, receive, send)

    env.app.mount("/mcp-room-nudge", MCPAuthMiddleware(Probe(), env.infra))
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")

    def auth_for(name):
        if not proxy:
            return headers(env.actors[name])
        principal = str(uuid4())
        return {"X-AWEB-Auth": build_internal_auth_header_value(
                    secret="test-internal-auth-secret", team_id=TEAM,
                    principal_type="k", principal_id=principal, actor_id=str(env.actors[name].id)),
                "X-Team-ID": TEAM, "X-API-Key": principal,
                "X-AWEB-Actor-ID": str(env.actors[name].id)}

    assert (await env.client.get("/mcp-room-nudge/", headers=auth_for("bob"))).json() == before
    room = await metadata(env)
    for _ in range(2):
        response = await post(env, room, text="ROOM CONTENT NEVER IN THE NUDGE")
        assert response.status_code == 200, response.text
    notices = await env.db.fetch_all("SELECT * FROM {{tables.room_post_notices}} ORDER BY message_id,recipient_agent_id")
    nudged = (await env.client.get("/mcp-room-nudge/", headers=auth_for("bob"))).json()
    assert nudged["content"][-1]["text"] == "[aweb] You have 2 new team room posts. Read the room with room_read."
    nudged["content"].pop()
    assert nudged == before
    assert await env.db.fetch_all("SELECT * FROM {{tables.room_post_notices}} ORDER BY message_id,recipient_agent_id") == notices
    assert (await env.client.get("/mcp-room-nudge/", headers=auth_for("alice"))).json() == before
    first = (await env.client.get("/mcp-room-nudge/?read=1", headers=auth_for("bob"))).json()
    assert first["content"][-1]["text"] == "[aweb] You have 1 new team room post. Read the room with room_read."
    cursor = json.loads(first["content"][0]["text"])["next_cursor"]
    last = (await env.client.get("/mcp-room-nudge/", params={"read": "1", "after": cursor}, headers=auth_for("bob"))).json()
    assert len(last["content"]) == 1
    assert (await env.client.get("/mcp-room-nudge/", headers=auth_for("bob"))).json() == before
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_post_notices}} WHERE recipient_agent_id=$1", env.actors["carol"].id) == 2
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.messages}}") == 0
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0

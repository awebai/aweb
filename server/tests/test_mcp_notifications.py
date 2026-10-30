"""Non-consuming next-call nudges preserve the completed MCP result."""

import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from mcp.types import CallToolResult, TextContent

from aweb.mcp.auth import AuthContext, _auth_context
from aweb.mcp.notifications import append_pending_nudge
from test_messages_http import _insert_agent, _insert_team


class CountDB:
    def __init__(self, counts):
        self.counts = counts

    async def fetch_one(self, query, *args):
        if isinstance(self.counts, Exception):
            raise self.counts
        return self.counts


def infra(db):
    return SimpleNamespace(get_manager=lambda name: db)


@pytest.fixture
def actor():
    auth = AuthContext(team_id="ops:example.com", agent_id=str(uuid4()),
                       alias="actor", did_key="did:key:actor")
    token = _auth_context.set(auth)
    try:
        yield auth
    finally:
        _auth_context.reset(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["result", "content", "tuple", "structured"])
async def test_nudge_preserves_original_wire_fields(actor, shape):
    content = [TextContent(type="text", text='{"original": "unchanged"}')]
    structured = {"result": "original"}
    full = CallToolResult(content=content, structuredContent=structured,
                          _meta={"opaque": ["keep"]}, vendor_extra="keep")
    inputs = {"result": full, "content": content,
              "tuple": (content, structured), "structured": structured}
    before = full.model_dump(mode="json", by_alias=True)
    result = await append_pending_nudge(inputs[shape], infra(CountDB(
        {"unread_mail": 2, "unread_chat_messages": 1})))
    assert isinstance(result, CallToolResult)
    expected_text = ("[aweb] You have 2 unread mail and 1 unread chat messages; "
                     "call check_mail / check_chats to read them.")
    assert result.content[-1].text == expected_text
    if shape == "structured":
        assert result.content[0].text == json.dumps(structured, indent=2)
    else:
        assert result.content[:-1] == content
    assert result.structuredContent == (None if shape == "content" else structured)
    if shape == "result":
        after = result.model_dump(mode="json", by_alias=True)
        after["content"] = after["content"][:-1]
        assert after == before
    assert full.model_dump(mode="json", by_alias=True) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("counts", [None, {"unread_mail": 0, "unread_chat_messages": 0},
                                    RuntimeError("database query failed")])
async def test_no_nudge_returns_same_object(actor, counts):
    original = ([TextContent(type="text", text="original")], {"result": "original"})
    assert await append_pending_nudge(original, infra(CountDB(counts))) is original


@pytest.mark.asyncio
async def test_error_and_missing_actor_are_unchanged(actor):
    error = CallToolResult(content=[TextContent(type="text", text="error")], isError=True,
                           _meta={"keep": True})
    # No database is available: errors and unscoped contexts must not query it.
    assert await append_pending_nudge(error, None) is error
    actor.agent_id = None
    assert await append_pending_nudge(error.content, None) is error.content


@pytest_asyncio.fixture
async def mailbox(aweb_cloud_db, actor):
    db = aweb_cloud_db.aweb_db
    await _insert_team(db, actor.team_id)
    actor.agent_id = await _insert_agent(db, team_id=actor.team_id, alias="actor",
                                        did_key=actor.did_key, did_aw="did:aw:actor")
    other = await _insert_agent(db, team_id=actor.team_id, alias="other",
                               did_key="did:key:other")
    await db.execute("UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE agent_id=$1",
                     UUID(actor.agent_id))

    async def mail(to_did, *, read=False):
        await db.execute("""INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, to_alias, subject, body, read_at)
            VALUES ($1, 'did:key:other', $2, 'other', 'actor', 'DO NOT EXPOSE',
                    'DO NOT EXPOSE', CASE WHEN $3 THEN NOW() END)""", uuid4(), to_did, read)

    async def chat(did, *, duplicate=False):
        sid = uuid4()
        await db.execute("INSERT INTO {{tables.chat_sessions}} (session_id, team_id) VALUES ($1,$2)",
                         sid, actor.team_id)
        for participant_did, agent_id in [(did, actor.agent_id), ("did:key:other", other)]:
            await db.execute("""INSERT INTO {{tables.chat_participants}}
                (session_id, did, agent_id, alias) VALUES ($1,$2,$3,'participant')""",
                sid, participant_did, UUID(agent_id))
        if duplicate:
            await db.execute("""INSERT INTO {{tables.chat_participants}}
                (session_id, did, agent_id, alias) VALUES ($1,$2,$3,'participant')""",
                sid, actor.did_key, UUID(actor.agent_id))
        ids = [uuid4() for _ in range(3)]
        for mid, sender in zip(ids, ["did:key:other", "did:key:other", did]):
            await db.execute("""INSERT INTO {{tables.chat_messages}}
                (message_id, session_id, from_did, from_alias, body)
                VALUES ($1,$2,$3,'sender','DO NOT EXPOSE')""", mid, sid, sender)
        # Read one incoming message by the actor, and the other by another actor.
        for reader, mid in [(did, ids[0]), ("did:key:other", ids[1])]:
            await db.execute("""INSERT INTO {{tables.chat_message_reads}}
                (session_id,did,message_id) VALUES ($1,$2,$3)""", sid, reader, mid)

    return SimpleNamespace(db=db, mail=mail, chat=chat)


@pytest.mark.asyncio
async def test_counts_bound_aliases_and_chat_reads_without_consuming(actor, mailbox):
    db = mailbox.db
    await mailbox.mail(actor.did_key)
    await mailbox.mail("did:aw:actor")
    await mailbox.mail(actor.did_key, read=True)
    await mailbox.mail("did:key:other")
    await mailbox.chat("did:aw:actor", duplicate=True)
    await mailbox.chat(actor.did_key)

    class ReadOnlyDB:
        async def fetch_one(self, query, *args):
            async with db.transaction() as tx:
                await tx.execute("SET TRANSACTION READ ONLY")
                return await tx.fetch_one(query, *args)

    original = CallToolResult(content=[TextContent(type="text", text="original")])
    result = await append_pending_nudge(original, infra(ReadOnlyDB()))
    assert len(result.content) == 2
    assert "2 unread mail and 2 unread chat messages" in result.content[-1].text
    assert "DO NOT EXPOSE" not in result.model_dump_json()
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}} WHERE read_at IS NULL") == 3
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_message_reads}}") == 4
    # An unrelated team cannot select the same actor row.
    actor.team_id = "unrelated:example.com"
    assert await append_pending_nudge(original, infra(ReadOnlyDB())) is original


@pytest.mark.asyncio
async def test_unverified_stable_claim_is_not_a_mailbox_alias(actor, mailbox):
    await mailbox.mail("did:aw:actor")
    await mailbox.db.execute("UPDATE {{tables.agents}} SET did_aw_verified_key=NULL")
    original = CallToolResult(content=[TextContent(type="text", text="original")])
    assert await append_pending_nudge(original, infra(mailbox.db)) is original

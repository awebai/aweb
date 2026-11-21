"""MCP mail, chat and task tools fire the same mutation hooks as their REST routes.

Exercised through the real mounted MCP app and the REST app over ASGI, with
real PostgreSQL. The embedding application's ``on_mutation`` callback, the
Redis chat-session publish and the agent wake publisher are recorded at their
boundaries.
"""

import asyncio
from contextlib import AsyncExitStack
import json
import os
from datetime import datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis
from awid.registry import RegistryClient
from aweb.api import create_app
from aweb.db import DatabaseInfra
from tests.real_stack import REGISTRY_URL
from did_key_fixtures import named_did_key, named_signing_key

from awid.signing import sign_message
from aweb.coordination import tasks_service
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from aweb.mutation_hooks import create_mutation_handler
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)

TEAM = "mutation-parity:local"
INTERNAL_SECRET = "mutation-parity-test-secret"

MESSAGE_SENT_KEYS = {
    "team_id",
    "from_agent_id",
    "from_did",
    "from_did_aw",
    "to_agent_id",
    "from_alias",
    "message_id",
    "conversation_id",
    "to_alias",
    "subject",
    "priority",
    "content_mode",
}
CHAT_SENT_KEYS = {
    "team_id",
    "session_id",
    "conversation_id",
    "message_id",
    "from_agent_id",
    "from_alias",
    "from_did",
    "from_did_aw",
    "to_aliases",
    "preview",
    "content_mode",
}
ACKNOWLEDGED_KEYS = {
    "team_id",
    "agent_id",
    "alias",
    "message_id",
    "from_alias",
    "subject",
    "content_mode",
}


class _RecordingWakes:
    def __init__(self, publisher):
        self.publisher = publisher
        self.submitted = []

    def submit(self, wakes):
        self.submitted.append({key: set(kinds) for key, kinds in wakes.items()})
        self.publisher.submit(wakes)

    async def close(self):
        await self.publisher.close()


@pytest_asyncio.fixture
async def server(real_stack, shared_test_database, monkeypatch):
    """Actual registry admission, HTTP/MCP auth and Redis publications."""
    # The VM uses pgdbm's configured fixture, without this local-runner marker.
    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    monkeypatch.setenv("AWID_REGISTRY_URL", REGISTRY_URL)
    monkeypatch.setenv("AWEB_DATABASE_URL", shared_test_database.dsn)
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", INTERNAL_SECRET)
    db = real_stack.aweb_db
    # The named team is stable across fixture instances. Do not model an
    # unrelated controller rotation inside a shared serving-cache lifetime.
    namespace_key = named_signing_key("mutation-parity-namespace")
    namespace_did = named_did_key("mutation-parity-namespace")
    team_key = named_signing_key("mutation-parity-team")
    team_did = named_did_key("mutation-parity-team")
    async with (
        Redis.from_url(os.environ["REDIS_URL"], decode_responses=True) as redis,
        AsyncExitStack() as cleanup,
    ):
        infra = DatabaseInfra()
        await infra.initialize(shared_pool=shared_test_database.pool)
        cleanup.push_async_callback(infra.close)
        app = create_app(
            db_infra=infra,
            redis=redis,
            public_origin="http://test",
            awid_transport=real_stack.awid,
            host_runs_outbox_recovery=True,
        )
        await cleanup.enter_async_context(app.router.lifespan_context(app))
        registry: RegistryClient = app.state.awid_registry_client
        await registry.register_namespace("local", namespace_did, namespace_key)
        await registry.register_team(
            domain="local",
            name="mutation-parity",
            display_name="Mutation parity",
            team_did_key=team_did,
            visibility="public",
            namespace_controller_signing_key=namespace_key,
        )
        keys, agents, workspaces, dids, certificates = {}, {}, {}, {}, {}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as connecting:
            for alias in ("pilot", "bob"):
                sk, _, did = _make_keypair()
                keys[alias] = (sk, did)
                mapping = await registry.register_did(did, sk)
                dids[alias] = mapping.did_aw
                await registry.register_address(
                    "local", alias, mapping.did_aw, namespace_key, current_did_key=did
                )
                certificate = _make_certificate(
                    team_key,
                    team_did,
                    did,
                    team_id=TEAM,
                    certificate_id=f"parity-{alias}",
                    member_did_aw=mapping.did_aw,
                    member_address=f"local/{alias}",
                    alias=alias,
                    identity_scope="global",
                )
                encoded = _encode_certificate(certificate)
                await registry.register_team_certificate(
                    "local",
                    "mutation-parity",
                    team_controller_signing_key=team_key,
                    certificate_id=certificate["certificate_id"],
                    member_did_key=did,
                    member_did_aw=mapping.did_aw,
                    member_address=f"local/{alias}",
                    alias=alias,
                    identity_scope="global",
                    certificate=encoded,
                )
                certificates[alias] = encoded
                body = b"{}"
                response = await connecting.post(
                    "/v1/connect",
                    content=body,
                    headers={
                        **_signed_team_headers(sk, did, TEAM, encoded, body),
                        "Content-Type": "application/json",
                    },
                )
                assert response.status_code == 200, response.text
                connected = response.json()
                agents[alias] = connected["agent_id"]
                workspaces[alias] = UUID(connected["workspace_id"])
        mutations, published = [], []

        async def record_mutation(event_type, context):
            mutations.append((event_type, dict(context)))

        async def signer(**kwargs):
            alias = next(
                alias for alias, agent_id in agents.items() if agent_id == kwargs["agent_id"]
            )
            sk, did_key = keys[alias]
            signed = canonical_signed_payload(dict(kwargs["payload"]))
            return HostedMessageSigningResult(
                from_did=did_key,
                signing_key_id=did_key,
                signed_payload=signed,
                signature=sign_message(sk, signed.encode()),
            )

        # The library app owns its ordinary MCP mount; the host extends it
        # through the released public constructor on the same serving clients.
        mcp = create_mcp_app(
            db_infra=infra,
            redis=redis,
            registry_client=registry,
            hosted_signer=signer,
            public_origin=app.state.public_origin,
        )
        app.mount("/parity-mcp", mcp)
        await mcp.startup()
        cleanup.push_async_callback(mcp.shutdown)
        app.state.on_mutation = record_mutation
        async with redis.pubsub() as stream:
            await stream.psubscribe(
                "events:*", f"team-events:{TEAM}", "chat-session:*", "parity-barrier:*"
            )
            barrier_channel = f"parity-barrier:{uuid4()}"

            async def collect_publications():
                # Same Redis backend, real subscribed frames, bounded by an
                # explicit marker after the HTTP handler's awaited writes.
                marker = uuid4().hex
                await redis.publish(barrier_channel, marker)
                async with asyncio.timeout(5):
                    while True:
                        frame = await stream.get_message(ignore_subscribe_messages=True, timeout=1)
                        if frame is None:
                            continue
                        if frame["channel"] == barrier_channel and frame["data"] == marker:
                            return
                        published.append((frame["channel"], json.loads(frame["data"])))

            await collect_publications()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:

                async def mcp_result(alias, tool, **arguments):
                    principal = str(uuid4())
                    headers = {
                        "Accept": "application/json, text/event-stream",
                        "X-Team-ID": TEAM,
                        "X-User-ID": principal,
                        "X-AWEB-Actor-ID": agents[alias],
                        "X-AWEB-Auth": build_internal_auth_header_value(
                            secret=INTERNAL_SECRET,
                            team_id=TEAM,
                            principal_type="u",
                            principal_id=principal,
                            actor_id=agents[alias],
                        ),
                    }
                    response = await client.post(
                        "/parity-mcp/",
                        headers=headers,
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": tool, "arguments": arguments},
                        },
                    )
                    assert response.status_code == 200, response.text
                    result = response.json()
                    assert "error" not in result, result
                    await collect_publications()
                    return json.loads(result["result"]["content"][0]["text"])

                async def mcp_call(alias, tool, **arguments):
                    result = await mcp_result(alias, tool, **arguments)
                    assert "error" not in result, result
                    return result

                async def rest_task_response(alias, method, path, body=None):
                    sk, did = keys[alias]
                    content = json.dumps(body).encode() if body is not None else b""
                    response = await client.request(
                        method,
                        path,
                        content=content,
                        headers={
                            "Content-Type": "application/json",
                            **_signed_team_headers(sk, did, TEAM, certificates[alias], content),
                        },
                    )
                    await collect_publications()
                    return response

                async def rest_task(alias, method, path, body=None):
                    response = await rest_task_response(alias, method, path, body)
                    assert response.status_code == 200, response.text
                    return response.json()

                async def rest_post(alias, path, body=None):
                    return await rest_task(alias, "POST", path, body)

                async def rest_mail(alias, *, body, to_alias=None, conversation_id=None):
                    target = (
                        {"to_alias": to_alias} if to_alias else {"conversation_id": conversation_id}
                    )
                    return await rest_post(
                        alias, "/v1/messages", {**target, "subject": "status", "body": body}
                    )

                yield SimpleNamespace(
                    db=db,
                    app=app,
                    agents=agents,
                    workspaces=workspaces,
                    dids=dids,
                    keys=keys,
                    mutations=mutations,
                    redis=redis,
                    published=published,
                    mcp_call=mcp_call,
                    mcp_result=mcp_result,
                    rest_post=rest_post,
                    rest_mail=rest_mail,
                    rest_task=rest_task,
                    rest_task_response=rest_task_response,
                )


def _events(server, event_type):
    return [context for kind, context in server.mutations if kind == event_type]


@pytest.mark.asyncio
async def test_mcp_send_mail_fires_message_sent_like_rest(server):
    # No pilot/bob mail pair exists yet: the new-conversation path.
    fresh = await server.mcp_call(
        "pilot", "send_mail", to="bob", subject="new", body="fresh", plaintext=True
    )
    rest = await server.rest_mail("bob", to_alias="pilot", body="from rest")
    # The caller explicitly selects the conversation-continuation path.
    continued = await server.mcp_call(
        "pilot",
        "send_mail",
        conversation_id=fresh["conversation_id"],
        subject="re",
        body="reply",
        plaintext=True,
    )
    assert continued["conversation_id"] == fresh["conversation_id"]
    rest_continued = await server.rest_mail(
        "bob", conversation_id=fresh["conversation_id"], body="rest reply"
    )
    assert rest_continued["conversation_id"] == fresh["conversation_id"]

    events = _events(server, "message.sent")
    assert [event["message_id"] for event in events] == [
        fresh["message_id"],
        rest["message_id"],
        continued["message_id"],
        rest_continued["message_id"],
    ]
    mcp_events, rest_event = [events[0], events[2]], events[1]
    assert set(rest_event) == MESSAGE_SENT_KEYS
    # A continuation names the recipient's member recorded on the conversation,
    # the one whose event stream the delivery is published to.
    assert set(events[3]) == MESSAGE_SENT_KEYS
    assert events[3]["to_agent_id"] == server.agents["pilot"]
    assert events[3]["to_alias"] == "pilot"
    for event, sent in zip(mcp_events, (fresh, continued), strict=True):
        assert set(event) == set(rest_event)
        assert event["team_id"] == TEAM
        assert event["from_agent_id"] == server.agents["pilot"]
        assert event["to_agent_id"] == server.agents["bob"]
        assert event["to_alias"] == "bob"
        assert event["from_alias"] == "pilot"
        assert event["from_did_aw"] == server.dids["pilot"]
        assert event["conversation_id"] == sent["conversation_id"]
        assert event["content_mode"] == "legacy_plaintext_v1"
        assert event["priority"] == "normal"
    assert [event["subject"] for event in mcp_events] == ["new", "re"]


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_a_mail_reply_reaches_the_recipients_event_stream(server, via):
    opened = await server.mcp_call(
        "bob", "send_mail", to="pilot", subject="new", body="open", plaintext=True
    )
    server.app.state.on_mutation = create_mutation_handler(server.redis, server.app.state.db)

    if via == "mcp":
        await server.mcp_call(
            "pilot",
            "send_mail",
            conversation_id=opened["conversation_id"],
            body="reply",
            plaintext=True,
        )
    else:
        await server.rest_mail("pilot", conversation_id=opened["conversation_id"], body="reply")

    assert _published(server, f"events:{server.agents['bob']}") == ["message.delivered"]


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
async def test_check_mail_acknowledges_like_the_ack_route(server):
    by_route = await server.rest_mail("bob", to_alias="pilot", body="one")
    by_tool = await server.rest_mail("bob", to_alias="pilot", body="two")
    wakes = server.app.state.agent_wake_publisher = _RecordingWakes(
        server.app.state.agent_wake_publisher
    )

    async def stored_read_at():
        rows = await server.db.fetch_all(
            "SELECT message_id, read_at FROM {{tables.messages}} WHERE message_id = ANY($1::uuid[])",
            [UUID(by_route["message_id"]), UUID(by_tool["message_id"])],
        )
        return {str(row["message_id"]): row["read_at"] for row in rows}

    acknowledged = await server.rest_post("pilot", f"/v1/messages/{by_route['message_id']}/ack")
    # The tool acknowledges the unread mail it returns: the one the route left.
    await server.mcp_call("pilot", "check_mail")

    events = _events(server, "message.acknowledged")
    assert [event["message_id"] for event in events] == [
        by_route["message_id"],
        by_tool["message_id"],
    ]
    route_event, tool_event = ({**event, "message_id": "<this message>"} for event in events)
    assert tool_event == route_event
    assert route_event == {
        "team_id": TEAM,
        "agent_id": server.agents["pilot"],
        "alias": "pilot",
        "message_id": "<this message>",
        "from_alias": "bob",
        "subject": "status",
        "content_mode": "legacy_plaintext_v1",
    }
    assert wakes.submitted == [{f"did:{server.dids['pilot']}": {"mail"}}] * 2
    read_at = await stored_read_at()
    assert read_at[by_route["message_id"]] == datetime.fromisoformat(
        acknowledged["acknowledged_at"]
    )
    assert read_at[by_tool["message_id"]] is not None

    # Mail that is already read is acknowledged again by neither.
    await server.rest_post("pilot", f"/v1/messages/{by_tool['message_id']}/ack")
    await server.mcp_call("pilot", "check_mail", unread_only=False)
    assert len(_events(server, "message.acknowledged")) == 2
    assert len(wakes.submitted) == 2
    assert await stored_read_at() == read_at


@pytest.mark.asyncio
async def test_mcp_send_chat_fires_chat_message_sent_like_rest(server):
    opened = await server.mcp_call(
        "pilot", "send_chat", to="bob", message="hello bob", plaintext=True
    )
    continued = await server.mcp_call(
        "pilot",
        "send_chat",
        conversation_id=opened["conversation_id"],
        message="still there?",
        plaintext=True,
    )

    sent = _events(server, "chat.message_sent")
    assert [event["message_id"] for event in sent] == [
        opened["message_id"],
        continued["message_id"],
    ]
    for event in sent:
        assert set(event) == CHAT_SENT_KEYS
        assert event["team_id"] == TEAM
        assert event["session_id"] == opened["conversation_id"]
        assert event["conversation_id"] == opened["conversation_id"]
        assert event["from_agent_id"] == server.agents["pilot"]
        assert event["from_alias"] == "pilot"
        assert event["from_did_aw"] == server.dids["pilot"]
        assert event["to_aliases"] == ["bob"]
        assert event["content_mode"] == "legacy_plaintext_v1"
    assert [event["preview"] for event in sent] == ["hello bob", "still there?"]


@pytest.mark.asyncio
async def test_mcp_mark_chat_read_publishes_read_receipt_like_rest(server):
    opened = await server.mcp_call("bob", "send_chat", to="pilot", message="ping", plaintext=True)
    session_id = opened["conversation_id"]
    before = len(server.published)

    marked = await server.mcp_call(
        "pilot",
        "mark_chat_read",
        conversation_id=session_id,
        message_ids=[opened["message_id"]],
    )
    assert marked["messages_marked"] == 1
    receipts = [
        payload
        for channel, payload in server.published[before:]
        if payload.get("signal_type") == "read_receipt"
    ]
    assert len(receipts) == 1
    assert receipts[0]["session_id"] == session_id
    assert receipts[0]["message_id"] == opened["message_id"]
    assert receipts[0]["agent_id"] == server.dids["pilot"]

    # Nothing newly read: no receipt, as on the REST route.
    again = await server.mcp_call(
        "pilot",
        "mark_chat_read",
        conversation_id=session_id,
        up_to_message_id=opened["message_id"],
    )
    assert again["messages_marked"] == 0
    assert [
        payload
        for channel, payload in server.published[before:]
        if payload.get("signal_type") == "read_receipt"
    ] == receipts


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["message_ids", "up_to_message_id"])
async def test_mark_chat_read_marks_like_the_read_route(server, shape):
    server.app.state.redis = server.redis
    wakes = server.app.state.agent_wake_publisher = _RecordingWakes(
        server.app.state.agent_wake_publisher
    )

    opened = await server.mcp_call("bob", "send_chat", to="pilot", message="ping", plaintext=True)
    session_id = opened["conversation_id"]
    continued = await server.mcp_call(
        "bob",
        "send_chat",
        conversation_id=session_id,
        message="ping again",
        plaintext=True,
    )

    observed = {}
    for via, message_id in (
        ("mcp", opened["message_id"]),
        ("rest", continued["message_id"]),
    ):
        arguments = (
            {"message_ids": [message_id]}
            if shape == "message_ids"
            else {"up_to_message_id": message_id}
        )
        published, woken = len(server.published), len(wakes.submitted)

        marked = []
        # The second call finds nothing left to mark.
        for _ in range(2):
            if via == "mcp":
                result = await server.mcp_call(
                    "pilot", "mark_chat_read", conversation_id=session_id, **arguments
                )
            else:
                result = await server.rest_post(
                    "pilot", f"/v1/chat/sessions/{session_id}/read", arguments
                )
            marked.append(result["messages_marked"])

        read_by = await server.db.fetch_all(
            """SELECT agent_id FROM {{tables.chat_message_reads}}
               WHERE session_id = $1 AND did = $3 AND message_id = $2""",
            UUID(session_id),
            UUID(message_id),
            server.dids["pilot"],
        )
        receipt = await server.db.fetch_one(
            """SELECT agent_id, last_read_message_id FROM {{tables.chat_read_receipts}}
               WHERE session_id = $1 AND did = $2""",
            UUID(session_id),
            server.dids["pilot"],
        )
        observed[via] = {
            "marked": marked,
            "read_by": [str(row["agent_id"]) for row in read_by],
            "receipt_by": str(receipt["agent_id"]),
            "receipt_names_the_message": receipt["last_read_message_id"] == UUID(message_id),
            "signals": [
                (
                    payload["agent_id"],
                    payload["session_id"] == session_id,
                    payload["message_id"] == message_id,
                )
                for _, payload in server.published[published:]
                if payload.get("signal_type") == "read_receipt"
            ],
            "wakes": wakes.submitted[woken:],
        }

    assert observed["mcp"] == observed["rest"]
    assert observed["rest"] == {
        "marked": [1, 0],
        "read_by": [server.agents["pilot"]],
        "receipt_by": server.agents["pilot"],
        "receipt_names_the_message": True,
        "signals": [(server.dids["pilot"], True, True)],
        "wakes": [{f"did:{server.dids['pilot']}": {"chat"}}] * 2,
    }


# Identifiers that necessarily differ between two separate tasks.
TASK_SPECIFIC_KEYS = {"task_id", "task_ref", "comment_id"}

# (tool, MCP arguments, HTTP method, path after the task, HTTP body, statuses the task passes through first)
TASK_CHANGES = [
    ("task_update", {"title": "Renamed"}, "PATCH", "", {"title": "Renamed"}, ()),
    ("task_update", {"assignee": "bob"}, "PATCH", "", {"assignee_alias": "bob"}, ()),
    (
        "task_update",
        {"status": "closed", "notes": "done", "assignee": "bob"},
        "PATCH",
        "",
        {"status": "closed", "notes": "done", "assignee_alias": "bob"},
        ("in_progress",),
    ),
    ("task_claim", {}, "PATCH", "", {"status": "in_progress"}, ()),
    ("task_close", {}, "PATCH", "", {"status": "closed"}, ("in_progress",)),
    ("task_close", {}, "PATCH", "", {"status": "closed"}, ()),
    ("task_reopen", {}, "PATCH", "", {"status": "open"}, ("in_progress", "closed")),
    ("task_reopen", {}, "PATCH", "", {"status": "open"}, ("in_progress",)),
    (
        "task_comment_add",
        {"body": "a note"},
        "POST",
        "/comments",
        {"body": "a note"},
        (),
    ),
]


def _fired_since(server, start, task):
    """Events fired after `start`, each checked to name `task`, with its identifiers masked."""
    fired = []
    for kind, context in server.mutations[start:]:
        assert context["task_id"] == task["task_id"]
        if "task_ref" in context:
            assert context["task_ref"] == task["task_ref"]
        fired.append(
            (
                kind,
                {
                    key: "<this task>" if key in TASK_SPECIFIC_KEYS else value
                    for key, value in context.items()
                },
            )
        )
    return fired


@pytest.mark.asyncio
async def test_mcp_task_create_fires_the_events_of_its_rest_route(server):
    start = len(server.mutations)
    by_tool = await server.mcp_call(
        "pilot",
        "task_create",
        title="Ship it",
        description="details",
        priority=1,
        task_type="bug",
        labels=["release"],
        assignee="bob",
    )
    tool_events = _fired_since(server, start, by_tool)

    start = len(server.mutations)
    by_route = await server.rest_task(
        "pilot",
        "POST",
        "/v1/tasks",
        {
            "title": "Ship it",
            "description": "details",
            "priority": 1,
            "task_type": "bug",
            "labels": ["release"],
            "assignee_alias": "bob",
        },
    )
    route_events = _fired_since(server, start, by_route)

    assert [kind for kind, _ in route_events] == ["task.created"]
    assert tool_events == route_events
    assert route_events[0][1]["actor_agent_id"] == server.agents["pilot"]
    assert route_events[0][1]["actor_did_aw"] == server.dids["pilot"]
    stored = await server.db.fetch_all(
        "SELECT created_by_alias, created_by_did, assignee_did FROM {{tables.tasks}} WHERE task_id = ANY($1::uuid[])",
        [UUID(by_tool["task_id"]), UUID(by_route["task_id"])],
    )
    assert [dict(row) for row in stored] == [
        {
            "created_by_alias": "pilot",
            "created_by_did": server.dids["pilot"],
            "assignee_did": server.dids["bob"],
        },
    ] * 2


@pytest.mark.asyncio
@pytest.mark.parametrize("tool, arguments, method, suffix, body, earlier_statuses", TASK_CHANGES)
async def test_mcp_task_tool_fires_the_events_of_its_rest_route(
    server,
    tool,
    arguments,
    method,
    suffix,
    body,
    earlier_statuses,
):
    fired = {}
    for via in ("mcp", "rest"):
        task = await server.rest_task("pilot", "POST", "/v1/tasks", {"title": "Same change"})
        for status in earlier_statuses:
            await server.rest_task(
                "pilot", "PATCH", f"/v1/tasks/{task['task_ref']}", {"status": status}
            )
        start = len(server.mutations)
        if via == "mcp":
            await server.mcp_call("pilot", tool, ref=task["task_ref"], **arguments)
        else:
            await server.rest_task("pilot", method, f"/v1/tasks/{task['task_ref']}{suffix}", body)
        fired[via] = _fired_since(server, start, task)

    assert fired["rest"], "the route fired nothing to compare with"
    assert fired["mcp"] == fired["rest"]
    for _, context in fired["rest"]:
        assert context["actor_agent_id"] == server.agents["pilot"]


async def _create_task(server, via, alias, title):
    if via == "mcp":
        return await server.mcp_call(alias, "task_create", title=title)
    return await server.rest_task(alias, "POST", "/v1/tasks", {"title": title})


async def _set_status(server, via, alias, ref, status):
    if via == "mcp":
        tool = {
            "in_progress": "task_claim",
            "closed": "task_close",
            "open": "task_reopen",
        }[status]
        return await server.mcp_call(alias, tool, ref=ref)
    return await server.rest_task(alias, "PATCH", f"/v1/tasks/{ref}", {"status": status})


async def _claims(server, task_ref):
    rows = await server.db.fetch_all(
        "SELECT workspace_id FROM {{tables.task_claims}} WHERE team_id = $1 AND task_ref = $2",
        TEAM,
        task_ref,
    )
    return [row["workspace_id"] for row in rows]


async def _focus(server, alias):
    return await server.db.fetch_value(
        "SELECT focus_task_ref FROM {{tables.workspaces}} WHERE workspace_id = $1",
        server.workspaces[alias],
    )


def _published(server, channel):
    return [payload["type"] for name, payload in server.published if name == channel]


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_claim_then_close_releases_the_claim_and_reaches_the_streams(server, via):
    server.app.state.on_mutation = create_mutation_handler(server.redis, server.app.state.db)
    task = await _create_task(server, via, "pilot", "Stream me")
    ref = task["task_ref"]

    await _set_status(server, via, "pilot", ref, "in_progress")
    assert await _claims(server, ref) == [server.workspaces["pilot"]]
    assert await _focus(server, "pilot") == ref

    await _set_status(server, via, "pilot", ref, "closed")
    assert await _claims(server, ref) == []
    assert await _focus(server, "pilot") is None

    # What the dashboard's team stream and the member's own stream carry.
    assert _published(server, f"team-events:{TEAM}") == [
        "task.created",
        "task.claimed",
        "task.status_changed",
        "task.assignee_changed",
        "task.unclaimed",
        "task.status_changed",
    ]
    assert _published(server, f"events:{server.workspaces['pilot']}") == [
        "task.created",
        "task.claimed",
        "task.status_changed",
        "task.unclaimed",
        "task.status_changed",
    ]
    unclaimed = [
        payload for name, payload in server.published if payload["type"] == "task.unclaimed"
    ]
    assert [(payload["task_ref"], payload["alias"]) for payload in unclaimed] == [
        (ref, "pilot")
    ] * 2

    await _set_status(server, via, "pilot", ref, "open")
    await _set_status(server, via, "bob", ref, "in_progress")
    assert await _claims(server, ref) == [server.workspaces["bob"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
@pytest.mark.parametrize("status", ["closed", "open"])
async def test_leaving_in_progress_releases_every_claim_without_a_mutation_handler(
    server, via, status
):
    server.app.state.on_mutation = None
    task = await _create_task(server, via, "pilot", "No handler")
    ref = task["task_ref"]
    await _set_status(server, via, "pilot", ref, "in_progress")
    await server.db.execute(
        """INSERT INTO {{tables.task_claims}} (team_id, workspace_id, alias, task_ref)
           VALUES ($1, $2, 'bob', $3)""",
        TEAM,
        server.workspaces["bob"],
        ref,
    )

    await _set_status(server, via, "pilot", ref, status)

    assert await _claims(server, ref) == []
    # An open task stays its former claimant's focus; a closed one does not.
    assert await _focus(server, "pilot") == (ref if status == "open" else None)


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_a_refused_close_keeps_the_claim_and_fires_nothing(server, via):
    task = await _create_task(server, via, "pilot", "Refused")
    ref = task["task_ref"]
    await _set_status(server, via, "pilot", ref, "in_progress")
    start = len(server.mutations)

    if via == "mcp":
        refused = await server.mcp_result(
            "pilot", "task_update", ref=ref, status="closed", assignee="nobody"
        )
        assert refused == {"error": "Assignee agent not found in this team"}
    else:
        refused = await server.rest_task_response(
            "pilot",
            "PATCH",
            f"/v1/tasks/{ref}",
            {"status": "closed", "assignee_alias": "nobody"},
        )
        assert refused.status_code == 422, refused.text
        assert refused.json() == {"detail": "Assignee agent not found in this team"}

    assert server.mutations[start:] == []
    assert await _claims(server, ref) == [server.workspaces["pilot"]]
    assert (
        await server.db.fetch_value(
            "SELECT status FROM {{tables.tasks}} WHERE task_id = $1",
            UUID(task["task_id"]),
        )
        == "in_progress"
    )


@pytest.mark.asyncio
async def test_a_close_that_rolls_back_restores_the_claim_and_fires_nothing(server, monkeypatch):
    task = await server.rest_task("pilot", "POST", "/v1/tasks", {"title": "Rolled back"})
    ref = task["task_ref"]
    await server.rest_task("pilot", "PATCH", f"/v1/tasks/{ref}", {"status": "in_progress"})
    start = len(server.mutations)
    release = tasks_service.release_task_claims_on
    released = []

    async def release_then_fail(tx, **kwargs):
        released.extend(await release(tx, **kwargs))
        raise RuntimeError("the status transaction fails after the release")

    monkeypatch.setattr(tasks_service, "release_task_claims_on", release_then_fail)
    with pytest.raises(RuntimeError, match="fails after the release"):
        await server.rest_task("pilot", "PATCH", f"/v1/tasks/{ref}", {"status": "closed"})

    assert released == [str(server.workspaces["pilot"])]
    assert server.mutations[start:] == []
    assert await _claims(server, ref) == [server.workspaces["pilot"]]
    assert await _focus(server, "pilot") == ref
    assert (
        await server.db.fetch_value(
            "SELECT status FROM {{tables.tasks}} WHERE task_id = $1",
            UUID(task["task_id"]),
        )
        == "in_progress"
    )


@pytest.mark.asyncio
async def test_mcp_task_tools_answer_a_conflict_or_refusal_as_an_error(server):
    task = await server.rest_task("pilot", "POST", "/v1/tasks", {"title": "Taken"})
    await server.mcp_call("pilot", "task_claim", ref=task["task_ref"])
    start = len(server.mutations)
    assert await server.mcp_result("bob", "task_claim", ref=task["task_ref"]) == {
        "error": "Task is already in progress by another agent",
    }

    # An app request may only be taken or reassigned to the member it names.
    request_id = uuid4()
    await server.db.execute(
        """INSERT INTO {{tables.tasks}}
           (task_id, team_id, task_number, root_task_seq, task_ref_suffix, title,
            assignee_alias, assignee_did, created_by_alias, app_request)
           VALUES ($1, $2, 900, 900, 'zzzz', 'App request', 'bob', $3, 'pilot', '{}'::jsonb)""",
        request_id,
        TEAM,
        server.dids["bob"],
    )
    for tool, arguments in (
        ("task_claim", {}),
        ("task_update", {"assignee": "pilot"}),
        ("task_update", {"status": "closed", "assignee": "pilot"}),
    ):
        assert await server.mcp_result("pilot", tool, ref=str(request_id), **arguments) == {
            "error": "target_mismatch"
        }

    assert server.mutations[start:] == []
    assert dict(
        await server.db.fetch_one(
            "SELECT status, assignee_alias FROM {{tables.tasks}} WHERE task_id = $1",
            request_id,
        )
    ) == {"status": "open", "assignee_alias": "bob"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool, arguments",
    [
        ("task_create", {"title": ""}),
        ("task_create", {"title": "x" * 4097}),
        ("task_create", {"title": "Bad priority", "priority": 9}),
        ("task_create", {"title": "Bad type", "task_type": "nonsense"}),
        ("task_create", {"title": "Long", "description": "x" * 65537}),
        ("task_update", {"status": "finished"}),
        ("task_update", {"priority": 9}),
        ("task_update", {"task_type": "nonsense"}),
        ("task_update", {"title": "x" * 4097}),
        ("task_comment_add", {"body": ""}),
        ("task_comment_add", {"body": "x" * 65537}),
    ],
)
async def test_mcp_task_tools_refuse_what_their_rest_routes_refuse(server, tool, arguments):
    task = await server.rest_task("pilot", "POST", "/v1/tasks", {"title": "Bounds"})
    before = await server.db.fetch_one(
        "SELECT * FROM {{tables.tasks}} WHERE task_id = $1", UUID(task["task_id"])
    )
    start = len(server.mutations)
    if tool != "task_create":
        arguments = {"ref": task["task_ref"], **arguments}

    refused = await server.mcp_result("pilot", tool, **arguments)

    assert set(refused) == {"error"}
    assert isinstance(refused["error"], str) and refused["error"]
    assert server.mutations[start:] == []
    assert (
        await server.db.fetch_value(
            "SELECT count(*) FROM {{tables.tasks}} WHERE team_id = $1", TEAM
        )
        == 1
    )
    assert (
        await server.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_comments}} WHERE team_id = $1", TEAM
        )
        == 0
    )
    assert (
        await server.db.fetch_one(
            "SELECT * FROM {{tables.tasks}} WHERE task_id = $1", UUID(task["task_id"])
        )
        == before
    )

    # The route refuses the same input before it reaches the service.
    if tool == "task_create":
        method, path, body = "POST", "/v1/tasks", arguments
    elif tool == "task_update":
        method, path, body = (
            "PATCH",
            f"/v1/tasks/{task['task_ref']}",
            {k: v for k, v in arguments.items() if k != "ref"},
        )
    else:
        method, path, body = (
            "POST",
            f"/v1/tasks/{task['task_ref']}/comments",
            {"body": arguments["body"]},
        )
    assert (await server.rest_task_response("pilot", method, path, body)).status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
async def test_a_claim_response_carries_only_the_task(server, via):
    task = await _create_task(server, via, "pilot", "Claimed twice")
    claimed = await _set_status(server, via, "pilot", task["task_ref"], "in_progress")
    again = await _set_status(server, via, "pilot", task["task_ref"], "in_progress")
    closed = await _set_status(server, via, "pilot", task["task_ref"], "closed")

    if via == "mcp":
        read = await server.mcp_call("pilot", "task_get", ref=task["task_ref"])
    else:
        read = await server.rest_task("pilot", "GET", f"/v1/tasks/{task['task_ref']}")
    for response in (claimed, again, closed):
        assert set(response) == set(read)
    assert (claimed["status"], again["status"], closed["status"]) == (
        "in_progress",
        "in_progress",
        "closed",
    )

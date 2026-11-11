"""MCP mail, chat and task tools fire the same mutation hooks as their REST routes.

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
from fastapi import Request

from awid.signing import sign_message
from aweb.coordination import tasks_service
from aweb.coordination.routes.tasks import router as tasks_router
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from aweb.mutation_hooks import create_mutation_handler
from aweb.service_errors import ValidationError
from aweb.team_auth_deps import TeamIdentity, get_team_identity
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
    workspaces = {}
    for alias in ("pilot", "bob"):
        sk, _, did_key = _make_keypair()
        keys[alias] = (sk, did_key)
        agents[alias] = await _insert_agent(
            db, team_id=TEAM, alias=alias, did_key=did_key,
            did_aw=f"did:aw:{alias}", address=f"acme.com/{alias}",
        )
        workspaces[alias] = uuid4()
        await db.execute(
            """INSERT INTO {{tables.workspaces}}
               (workspace_id, team_id, agent_id, alias, workspace_type)
               VALUES ($1, $2, $3, $4, 'hosted_mcp')""",
            workspaces[alias], TEAM, UUID(agents[alias]), alias,
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

    # The task routes run as the member named by the request; certificate
    # verification, which the proxied MCP member does not use, is not under test.
    async def task_identity(request: Request) -> TeamIdentity:
        alias = request.headers["X-Test-Actor"]
        return TeamIdentity(
            team_id=TEAM, alias=alias, did_key=keys[alias][1], did_aw=f"did:aw:{alias}",
            address=f"acme.com/{alias}", agent_id=agents[alias], identity_scope="global",
            certificate_id=f"cert-{alias}",
        )

    app.include_router(tasks_router)
    app.dependency_overrides[get_team_identity] = task_identity
    for route in app.routes:
        for dependency in getattr(getattr(route, "dependant", None), "dependencies", []):
            if getattr(dependency.call, "_aweb_grant_scope", None) in {"coord.read", "coord.write"}:
                app.dependency_overrides[dependency.call] = task_identity
    mcp = create_mcp_app(db_infra=app.state.db, redis=redis, hosted_signer=signer)
    app.mount("/mcp", mcp)
    await mcp.startup()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:

            async def mcp_result(alias, tool, **arguments):
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
                return json.loads(result["result"]["content"][0]["text"])

            async def mcp_call(alias, tool, **arguments):
                payload = await mcp_result(alias, tool, **arguments)
                assert "error" not in payload, payload
                return payload

            async def rest_task_response(alias, method, path, body=None):
                return await client.request(method, path, json=body, headers={"X-Test-Actor": alias})

            async def rest_task(alias, method, path, body=None):
                response = await rest_task_response(alias, method, path, body)
                assert response.status_code == 200, response.text
                return response.json()

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
                db=db, app=app, agents=agents, workspaces=workspaces, mutations=mutations, redis=redis,
                mcp_call=mcp_call, mcp_result=mcp_result, rest_mail=rest_mail, rest_task=rest_task,
                rest_task_response=rest_task_response,
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


# Identifiers that necessarily differ between two separate tasks.
TASK_SPECIFIC_KEYS = {"task_id", "task_ref", "comment_id"}

# (tool, MCP arguments, HTTP method, path after the task, HTTP body, statuses the task passes through first)
TASK_CHANGES = [
    ("task_update", {"title": "Renamed"}, "PATCH", "", {"title": "Renamed"}, ()),
    ("task_update", {"assignee": "bob"}, "PATCH", "", {"assignee_alias": "bob"}, ()),
    ("task_update", {"status": "closed", "notes": "done", "assignee": "bob"}, "PATCH", "",
     {"status": "closed", "notes": "done", "assignee_alias": "bob"}, ("in_progress",)),
    ("task_claim", {}, "PATCH", "", {"status": "in_progress"}, ()),
    ("task_close", {}, "PATCH", "", {"status": "closed"}, ("in_progress",)),
    ("task_close", {}, "PATCH", "", {"status": "closed"}, ()),
    ("task_reopen", {}, "PATCH", "", {"status": "open"}, ("in_progress", "closed")),
    ("task_reopen", {}, "PATCH", "", {"status": "open"}, ("in_progress",)),
    ("task_comment_add", {"body": "a note"}, "POST", "/comments", {"body": "a note"}, ()),
]


def _fired_since(server, start, task):
    """Events fired after `start`, each checked to name `task`, with its identifiers masked."""
    fired = []
    for kind, context in server.mutations[start:]:
        assert context["task_id"] == task["task_id"]
        if "task_ref" in context:
            assert context["task_ref"] == task["task_ref"]
        fired.append((kind, {key: "<this task>" if key in TASK_SPECIFIC_KEYS else value
                             for key, value in context.items()}))
    return fired


@pytest.mark.asyncio
async def test_mcp_task_create_fires_the_events_of_its_rest_route(server):
    start = len(server.mutations)
    by_tool = await server.mcp_call(
        "pilot", "task_create", title="Ship it", description="details", priority=1,
        task_type="bug", labels=["release"], assignee="bob",
    )
    tool_events = _fired_since(server, start, by_tool)

    start = len(server.mutations)
    by_route = await server.rest_task("pilot", "POST", "/v1/tasks", {
        "title": "Ship it", "description": "details", "priority": 1,
        "task_type": "bug", "labels": ["release"], "assignee_alias": "bob",
    })
    route_events = _fired_since(server, start, by_route)

    assert [kind for kind, _ in route_events] == ["task.created"]
    assert tool_events == route_events
    assert route_events[0][1]["actor_agent_id"] == server.agents["pilot"]
    assert route_events[0][1]["actor_did_aw"] == "did:aw:pilot"
    stored = await server.db.fetch_all(
        "SELECT created_by_alias, created_by_did, assignee_did FROM {{tables.tasks}} WHERE task_id = ANY($1::uuid[])",
        [UUID(by_tool["task_id"]), UUID(by_route["task_id"])],
    )
    assert [dict(row) for row in stored] == [
        {"created_by_alias": "pilot", "created_by_did": "did:aw:pilot", "assignee_did": "did:aw:bob"},
    ] * 2


@pytest.mark.asyncio
@pytest.mark.parametrize("tool, arguments, method, suffix, body, earlier_statuses", TASK_CHANGES)
async def test_mcp_task_tool_fires_the_events_of_its_rest_route(
    server, tool, arguments, method, suffix, body, earlier_statuses,
):
    fired = {}
    for via in ("mcp", "rest"):
        task = await server.rest_task("pilot", "POST", "/v1/tasks", {"title": "Same change"})
        for status in earlier_statuses:
            await server.rest_task("pilot", "PATCH", f"/v1/tasks/{task['task_ref']}", {"status": status})
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
        tool = {"in_progress": "task_claim", "closed": "task_close", "open": "task_reopen"}[status]
        return await server.mcp_call(alias, tool, ref=ref)
    return await server.rest_task(alias, "PATCH", f"/v1/tasks/{ref}", {"status": status})


async def _claims(server, task_ref):
    rows = await server.db.fetch_all(
        "SELECT workspace_id FROM {{tables.task_claims}} WHERE team_id = $1 AND task_ref = $2", TEAM, task_ref,
    )
    return [row["workspace_id"] for row in rows]


async def _focus(server, alias):
    return await server.db.fetch_value(
        "SELECT focus_task_ref FROM {{tables.workspaces}} WHERE workspace_id = $1", server.workspaces[alias],
    )


def _published(server, channel):
    return [payload["type"] for name, payload in server.redis.published if name == channel]


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
        "task.created", "task.claimed", "task.status_changed", "task.assignee_changed",
        "task.unclaimed", "task.status_changed",
    ]
    assert _published(server, f"events:{server.workspaces['pilot']}") == [
        "task.created", "task.claimed", "task.status_changed", "task.unclaimed", "task.status_changed",
    ]
    unclaimed = [payload for name, payload in server.redis.published if payload["type"] == "task.unclaimed"]
    assert [(payload["task_ref"], payload["alias"]) for payload in unclaimed] == [(ref, "pilot")] * 2

    await _set_status(server, via, "pilot", ref, "open")
    await _set_status(server, via, "bob", ref, "in_progress")
    assert await _claims(server, ref) == [server.workspaces["bob"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["mcp", "rest"])
@pytest.mark.parametrize("status", ["closed", "open"])
async def test_leaving_in_progress_releases_every_claim_without_a_mutation_handler(server, via, status):
    server.app.state.on_mutation = None
    task = await _create_task(server, via, "pilot", "No handler")
    ref = task["task_ref"]
    await _set_status(server, via, "pilot", ref, "in_progress")
    await server.db.execute(
        """INSERT INTO {{tables.task_claims}} (team_id, workspace_id, alias, task_ref)
           VALUES ($1, $2, 'bob', $3)""",
        TEAM, server.workspaces["bob"], ref,
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
        refused = await server.mcp_result("pilot", "task_update", ref=ref, status="closed", assignee="nobody")
        assert refused == {"error": "Assignee agent not found in this team"}
    else:
        with pytest.raises(ValidationError, match="Assignee agent not found in this team"):
            await server.rest_task("pilot", "PATCH", f"/v1/tasks/{ref}", {"status": "closed", "assignee_alias": "nobody"})

    assert server.mutations[start:] == []
    assert await _claims(server, ref) == [server.workspaces["pilot"]]
    assert await server.db.fetch_value("SELECT status FROM {{tables.tasks}} WHERE task_id = $1", UUID(task["task_id"])) == "in_progress"


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
    assert await server.db.fetch_value("SELECT status FROM {{tables.tasks}} WHERE task_id = $1", UUID(task["task_id"])) == "in_progress"


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
           VALUES ($1, $2, 900, 900, 'zzzz', 'App request', 'bob', 'did:aw:bob', 'pilot', '{}'::jsonb)""",
        request_id, TEAM,
    )
    for tool, arguments in (
        ("task_claim", {}),
        ("task_update", {"assignee": "pilot"}),
        ("task_update", {"status": "closed", "assignee": "pilot"}),
    ):
        assert await server.mcp_result("pilot", tool, ref=str(request_id), **arguments) == {"error": "target_mismatch"}

    assert server.mutations[start:] == []
    assert dict(await server.db.fetch_one(
        "SELECT status, assignee_alias FROM {{tables.tasks}} WHERE task_id = $1", request_id,
    )) == {"status": "open", "assignee_alias": "bob"}


@pytest.mark.asyncio
@pytest.mark.parametrize("tool, arguments", [
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
])
async def test_mcp_task_tools_refuse_what_their_rest_routes_refuse(server, tool, arguments):
    task = await server.rest_task("pilot", "POST", "/v1/tasks", {"title": "Bounds"})
    before = await server.db.fetch_one("SELECT * FROM {{tables.tasks}} WHERE task_id = $1", UUID(task["task_id"]))
    start = len(server.mutations)
    if tool != "task_create":
        arguments = {"ref": task["task_ref"], **arguments}

    refused = await server.mcp_result("pilot", tool, **arguments)

    assert set(refused) == {"error"}
    assert isinstance(refused["error"], str) and refused["error"]
    assert server.mutations[start:] == []
    assert await server.db.fetch_value("SELECT count(*) FROM {{tables.tasks}} WHERE team_id = $1", TEAM) == 1
    assert await server.db.fetch_value("SELECT count(*) FROM {{tables.task_comments}} WHERE team_id = $1", TEAM) == 0
    assert await server.db.fetch_one("SELECT * FROM {{tables.tasks}} WHERE task_id = $1", UUID(task["task_id"])) == before

    # The route refuses the same input before it reaches the service.
    if tool == "task_create":
        method, path, body = "POST", "/v1/tasks", arguments
    elif tool == "task_update":
        method, path, body = "PATCH", f"/v1/tasks/{task['task_ref']}", {k: v for k, v in arguments.items() if k != "ref"}
    else:
        method, path, body = "POST", f"/v1/tasks/{task['task_ref']}/comments", {"body": arguments["body"]}
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
    assert (claimed["status"], again["status"], closed["status"]) == ("in_progress", "in_progress", "closed")

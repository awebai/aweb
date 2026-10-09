"""Dashboard isolation through the real apps, PostgreSQL, Redis and HTTP.

Only transport and resource setup are supplied here. No auth, routing, mutation,
query or event behavior is mocked. All identities and data are disposable.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import shutil
import socket
import subprocess
import tempfile
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis
import uvicorn

from aweb.api import (
    create_app,
    _shutdown_federation_outbox_replay,
    _shutdown_lifecycle_outbox_replay,
)
from aweb.db import DatabaseInfra
from aweb.events import team_events_channel_name
from aweb.mutation_hooks import create_mutation_handler
from awid.registry import RegistryClient
from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app as create_registry_app
from test_dashboard import _JWT_SECRET, _make_jwt
from test_messages_http import _make_keypair, _signed_identity_headers

TEAM = "privacy:example.test"


@pytest_asyncio.fixture
async def privacy_app(shared_test_pool):
    if not shutil.which("redis-server"):
        pytest.fail("dashboard privacy tests require a local redis-server executable")
    with tempfile.TemporaryDirectory(prefix="abav-") as directory:
        redis_path = f"{directory}/redis.sock"
        process = subprocess.Popen(
            ["redis-server", "--port", "0", "--unixsocket", redis_path,
             "--save", "", "--appendonly", "no"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        redis = Redis(unix_socket_path=redis_path, decode_responses=True)
        try:
            for _ in range(100):
                try:
                    await redis.ping()
                    break
                except ConnectionError:
                    await asyncio.sleep(0.02)
                except OSError:
                    await asyncio.sleep(0.02)
                except Exception:
                    if process.poll() is not None:
                        raise
                    await asyncio.sleep(0.02)
            await redis.ping()
            db = DatabaseInfra()
            await db.initialize(shared_pool=shared_test_pool)
            registry_db = AwidDatabaseInfra(schema="privacy_registry")
            await registry_db.initialize(shared_pool=shared_test_pool)
            registry_app = create_registry_app(db_infra=registry_db, redis=redis)
            async with registry_app.router.lifespan_context(registry_app):
                registry = RegistryClient(
                    registry_url="http://registry.test",
                    transport=httpx.ASGITransport(app=registry_app),
                )
                app = create_app()
                # Externally provisioned resources, exactly as an embedding host
                # supplies them; lifecycle startup would create different ones.
                app.state.db = db
                app.state.redis = redis
                app.state.awid_registry_client = registry
                app.state.dashboard_jwt_secret = _JWT_SECRET
                dispatched = []
                handler = create_mutation_handler(redis, db)

                async def observe_mutation(event_type, context):
                    dispatched.append((event_type, dict(context)))
                    await handler(event_type, context)

                app.state.on_mutation = observe_mutation
                manager = db.get_manager("aweb")
                team_sk, _, team_did = _make_keypair()
                await manager.execute(
                    "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
                    "VALUES ($1, 'example.test', 'privacy', $2)", TEAM, team_did,
                )
                await registry_db.get_manager().execute(
                    "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) "
                    "VALUES ('example.test', 'privacy', $1, 'public')", team_did,
                )
                actors = {}
                for alias in ("alice", "bob", "carol"):
                    sk, _, did = _make_keypair()
                    agent_id, workspace_id = uuid4(), uuid4()
                    await manager.execute(
                        "INSERT INTO {{tables.agents}} "
                        "(agent_id, team_id, did_key, alias, identity_scope, inbound_mode) "
                        "VALUES ($1, $2, $3, $4, 'local', 'open')",
                        agent_id, TEAM, did, alias,
                    )
                    await manager.execute(
                        "INSERT INTO {{tables.workspaces}} (workspace_id, team_id, agent_id, alias) "
                        "VALUES ($1, $2, $3, $4)", workspace_id, TEAM, agent_id, alias,
                    )
                    actors[alias] = SimpleNamespace(sk=sk, did=did, id=agent_id, workspace=workspace_id)
                sock = socket.socket()
                sock.bind(("127.0.0.1", 0))
                server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="error"))
                serving = asyncio.create_task(server.serve(sockets=[sock]))
                try:
                    for _ in range(100):
                        if server.started:
                            break
                        await asyncio.sleep(0.02)
                    assert server.started
                    async with httpx.AsyncClient(
                        base_url=f"http://127.0.0.1:{sock.getsockname()[1]}", timeout=5,
                    ) as client:
                        yield SimpleNamespace(
                            client=client, db=manager, redis=redis, actors=actors,
                            registry_db=registry_db.get_manager(), dispatched=dispatched,
                        )
                finally:
                    server.should_exit = True
                    await asyncio.wait_for(serving, 5)
                    sock.close()
                    await _shutdown_lifecycle_outbox_replay(app)
                    await _shutdown_federation_outbox_replay(app)
                    await registry.aclose()
            await registry_db.close()
            await db.close()
        finally:
            await redis.aclose()
            process.terminate()
            process.wait(timeout=5)


async def _request(env, actor, method, path, body=None):
    identity = env.actors[actor]
    content = json.dumps(body).encode() if body is not None else b""
    headers = _signed_identity_headers(identity.sk, identity.did, "", content)
    headers["Content-Type"] = "application/json"
    return await env.client.request(method, path, content=content, headers=headers)


async def _seed_mail(env):
    response = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": env.actors["bob"].did, "subject": "private subject", "body": "private body",
    })
    assert response.status_code == 200, response.text
    return response.json()["message_id"]


async def _next_event(lines):
    async with asyncio.timeout(5):
        async for line in lines:
            if line.startswith("data: "):
                return json.loads(line[6:])
    raise AssertionError("SSE ended before expected event")


@pytest.mark.asyncio
@pytest.mark.parametrize("visibility", ["public", "private"])
async def test_dashboard_cannot_read_mail_but_participants_can(privacy_app, visibility):
    env = privacy_app
    await env.registry_db.execute("UPDATE {{tables.teams}} SET visibility = $1", visibility)
    message_id = await _seed_mail(env)
    # A persisted v2 row exercises the same read boundary independently of send
    # encryption negotiation (which has its own conformance suite).
    encrypted_id = uuid4()
    await env.db.execute(
        """INSERT INTO {{tables.messages}}
        (message_id, team_id, from_did, to_did, from_alias, to_alias,
         from_agent_id, to_agent_id, subject, body, content_mode, message_version,
         encrypted_envelope, encrypted_ciphertext, encrypted_key_wraps,
         encrypted_ciphertext_hash, encrypted_ciphertext_size, encrypted_key_wraps_hash,
         encrypted_inner_header_hash, encrypted_suite, encrypted_signing_key_id, signed_envelope_hash)
        VALUES ($1, $2, $3, $4, 'alice', 'bob', $5, $6, '', '', 'encrypted_v2', 2,
                '{"ciphertext":"opaque"}', 'opaque', '[]', 'sha256:test', 6,
                'sha256:test', 'sha256:test', 'test', 'test', 'sha256:test')""",
        encrypted_id, TEAM, env.actors["alice"].did, env.actors["bob"].did,
        env.actors["alice"].id, env.actors["bob"].id,
    )
    dashboard = {"X-Dashboard-Token": _make_jwt([TEAM])}
    for headers in ({}, dashboard):
        response = await env.client.get(f"/v1/teams/{TEAM}/messages", headers=headers)
        assert response.status_code == 404, response.text
        for item in (message_id, str(encrypted_id), "alice", "bob", "private subject", "private body"):
            assert item not in response.text
        response = await env.client.get(f"/v1/messages/{message_id}", headers=headers)
        assert response.status_code == 401
    for item in (message_id, str(encrypted_id)):
        for actor in ("alice", "bob"):
            response = await _request(env, actor, "GET", f"/v1/messages/{item}")
            assert response.status_code == 200, response.text
            assert response.json()["message_id"] == item
        denied = await _request(env, "carol", "GET", f"/v1/messages/{item}")
        missing = await _request(env, "carol", "GET", f"/v1/messages/{uuid4()}")
        assert denied.status_code == missing.status_code == 404
        assert denied.json() == missing.json()
    inbox = await _request(env, "carol", "GET", "/v1/messages/inbox")
    assert inbox.status_code == 200
    assert inbox.json()["messages"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("token,status", [(None, 401), ("invalid", 401), ("wrong_team", 403)])
async def test_public_team_activity_requires_verified_dashboard_token(privacy_app, token, status):
    env = privacy_app
    # Prove the real registry exposes this team's directory publicly.
    assert (await env.client.get(f"/v1/teams/{TEAM}/agents")).status_code == 200
    if token == "wrong_team":
        token = _make_jwt(["other:example.test"])
    headers = {"X-Dashboard-Token": token} if token else {}
    async with env.client.stream("GET", f"/v1/teams/{TEAM}/events/stream", headers=headers) as response:
        assert response.status_code == status


@pytest.mark.asyncio
async def test_team_stream_suppresses_old_publishers_and_keeps_task_activity(privacy_app):
    env = privacy_app
    async with env.client.stream("GET", f"/v1/teams/{TEAM}/events/stream", headers={
        "X-Dashboard-Token": _make_jwt([TEAM]),
    }) as response:
        assert response.status_code == 200
        lines = response.aiter_lines()
        assert (await _next_event(lines))["type"] == "connected"
        assert (await _next_event(lines))["type"] == "snapshot"
        for mode in ("legacy_plaintext_v1", "encrypted_v2"):
            for event_type in ("message.delivered", "message.acknowledged", "chat.message_sent"):
                await env.redis.publish(team_events_channel_name(TEAM), json.dumps({
                    "type": event_type, "team_id": TEAM, "content_mode": mode,
                    "from_alias": "alice", "to_alias": "bob", "subject": "private subject",
                    "preview": "private chat", "message_id": str(uuid4()),
                }))
        control = {"type": "task.created", "team_id": TEAM, "task_ref": "privacy-aaaa", "title": "Public work"}
        await env.redis.publish(team_events_channel_name(TEAM), json.dumps(control))
        assert await _next_event(lines) == control


@pytest.mark.asyncio
async def test_real_sends_keep_mutation_callbacks_and_participant_reads(privacy_app):
    env = privacy_app
    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(team_events_channel_name(TEAM))
        await pubsub.get_message(timeout=1)  # subscription acknowledgement
        message_id = await _seed_mail(env)
        chat = await _request(env, "alice", "POST", "/v1/chat/sessions", {
            "to_dids": [env.actors["bob"].did], "message": "private chat",
        })
        assert chat.status_code == 200, chat.text
        session_id = chat.json()["session_id"]
        ack = await _request(env, "bob", "POST", f"/v1/messages/{message_id}/ack")
        assert ack.status_code == 200, ack.text
        events = {kind: context for kind, context in env.dispatched}
        for kind in ("message.sent", "chat.message_sent"):
            assert events[kind]["from_agent_id"] == str(env.actors["alice"].id)
        assert "message.acknowledged" in events
        # A sentinel after the completed sends proves the actual publisher queue
        # has no mail/chat events, rather than relying on a timed empty read.
        await env.redis.publish(team_events_channel_name(TEAM), '{"type":"sentinel"}')
        received = await pubsub.get_message(ignore_subscribe_messages=True, timeout=2)
        assert received is not None
        assert json.loads(received["data"]) == {"type": "sentinel"}
    for actor in ("alice", "bob", "carol"):
        conversations = await _request(env, actor, "GET", "/v1/conversations")
        assert conversations.status_code == 200, conversations.text
        history = await _request(env, actor, "GET", f"/v1/chat/sessions/{session_id}/messages")
        if actor == "carol":
            assert history.status_code in (403, 404)
            assert "private chat" not in history.text
            assert session_id not in conversations.text
        else:
            assert history.status_code == 200, history.text
            assert "private chat" in history.text
            assert session_id in conversations.text

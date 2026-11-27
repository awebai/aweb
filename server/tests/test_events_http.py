"""HTTP-level regression tests for GET /v1/events/stream."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import pytest_asyncio
from aweb.embedding import OutboxRecoveryOwnership
from test_coordination_state_http import request_as
from test_dashboard_privacy import TEAM, privacy_stack
from test_agents_suggest_alias_http import _global_actor
from test_messages_http import (
    _encode_certificate as _encode_certificate,
    _make_certificate as _make_certificate,
    _signed_team_headers,
)


import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import aweb.routes.events as events_module
from aweb.messaging.participant_succession import MailSuccessionScope
from aweb.team_auth_deps import TeamIdentity


@pytest_asyncio.fixture
async def privacy_app(shared_test_pool, monkeypatch):
    async with privacy_stack(
        shared_test_pool,
        monkeypatch,
        outbox_recovery=OutboxRecoveryOwnership.HOST,
    ) as env:
        monkeypatch.setattr(events_module, "EVENTS_RECONCILE_INTERVAL", 0.01)
        monkeypatch.setattr(events_module, "EVENTS_HEARTBEAT_INTERVAL", 0.05)
        yield env


async def _http_frames(lines):
    event = None
    async for line in lines:
        if line.startswith(":"):
            yield "keepalive", None
        elif line.startswith("event: "):
            event = line[7:]
        elif line.startswith("data: "):
            yield event, json.loads(line[6:])
            event = None


async def _next_named(frames, expected):
    async with asyncio.timeout(5):
        async for name, data in frames:
            if name == expected:
                return data
    raise AssertionError(f"stream ended before {expected}")


@asynccontextmanager
async def _http_events(env):
    actor = env.actors["bob"]
    deadline = datetime.now(timezone.utc) + timedelta(seconds=60)
    async with env.client.stream(
        "GET",
        "/v1/events/stream",
        params={"deadline": deadline.isoformat()},
        headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate),
    ) as response:
        assert response.status_code == 200, await response.aread()
        frames = _http_frames(response.aiter_lines())
        connected = await _next_named(frames, "connected")
        try:
            yield frames, connected
        finally:
            await frames.aclose()


async def _send_mail(env, subject):
    # The certified sender reaches the actual writer; notifications are its work.
    bob = env.actors["bob"]
    response = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/messages",
        payload={"to_did": bob.did, "subject": subject, "body": "hello"},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _create_test_event_recipient(aweb_db):
    agent_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkBob', 'bob', 'acme.com/bob', 'open')
        """,
        agent_id,
    )
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE agent_id=$1",
        agent_id,
    )
    return agent_id


async def _open_test_event_stream(
    aweb_db, agent_id, monkeypatch, *, redis=None, identity=None
):
    class _DbShim:
        def get_manager(self, name="aweb"):
            assert name == "aweb"
            return aweb_db

    class _ConnectedRequest:
        async def is_disconnected(self):
            return False

    if identity is None:
        identity = TeamIdentity(
            team_id="backend:acme.com",
            alias="bob",
            did_key="did:key:z6MkBob",
            did_aw="did:aw:bob",
            address="acme.com/bob",
            agent_id=str(agent_id),
            identity_scope="global",
            certificate_id="cert-001",
            grant=None,
        )

    # As in production, a heartbeat is due only after a reconcile had its turn.
    monkeypatch.setattr(events_module, "EVENTS_RECONCILE_INTERVAL", 0.01)
    monkeypatch.setattr(events_module, "EVENTS_HEARTBEAT_INTERVAL", 0.05)
    stream = events_module._sse_agent_events(
        request=_ConnectedRequest(),
        db=_DbShim(),
        redis=redis,
        team_id=identity.team_id,
        agent_id=str(agent_id),
        identity=identity,
        deadline=datetime.now(timezone.utc) + timedelta(seconds=1),
    )
    assert await anext(stream) == ": keepalive\n\n"
    assert (await anext(stream)).startswith("event: connected\n")
    return stream


@pytest.mark.asyncio
async def test_events_stream_includes_existing_unread_mail(privacy_app):
    env = privacy_app
    await _global_actor(env, "alice", address="example.test/alice")
    await _global_actor(env, "bob")
    message_id = uuid4()
    # Historical key-addressed mail remains a supported read shape.
    await env.db.execute(
        "INSERT INTO {{tables.messages}} "
        "(message_id,from_did,to_did,from_alias,to_alias,subject,body,team_id,from_agent_id,to_agent_id) "
        "VALUES ($1,$2,$3,'alice','bob','hello','hello',$4,$5,$6)",
        message_id,
        env.actors["alice"].did,
        env.actors["bob"].did,
        TEAM,
        env.actors["alice"].id,
        env.actors["bob"].id,
    )
    async with _http_events(env) as (frames, connected):
        assert connected["team_id"] == TEAM
        event = await _next_named(frames, "actionable_mail")
    assert event["message_id"] == str(message_id)
    assert event["from_alias"] == "alice"
    assert event["from_did"] == env.actors["alice"].did
    assert event["from_address"] == "example.test/alice"


@pytest.mark.asyncio
async def test_events_stream_sends_idle_heartbeats(privacy_app):
    async with _http_events(privacy_app) as (frames, _):
        for _ in range(2):
            async with asyncio.timeout(5):
                name, data = await anext(frames)
            assert name == "keepalive"
            assert data is None


@pytest.mark.asyncio
async def test_events_stream_matches_unread_mail_across_viewer_dids(privacy_app):
    env = privacy_app
    alice = await _global_actor(env, "alice", address="example.test/alice")
    bob = await _global_actor(env, "bob")
    message_id = uuid4()
    # A retained historical row names the stable recipient, while admission
    # presents its current signing key. The reader must query both identities.
    await env.db.execute(
        "INSERT INTO {{tables.messages}} "
        "(message_id,from_did,to_did,from_alias,to_alias,subject,body,team_id,from_agent_id,to_agent_id) "
        "VALUES ($1,$2,$3,'alice','bob','','hello stable bob',$4,$5,$6)",
        message_id,
        alice,
        bob,
        TEAM,
        env.actors["alice"].id,
        env.actors["bob"].id,
    )
    async with _http_events(env) as (frames, _):
        event = await _next_named(frames, "actionable_mail")
    assert event["message_id"] == str(message_id)
    assert event["from_alias"] == "alice"
    assert event["from_address"] == "example.test/alice"


@pytest.mark.asyncio
async def test_current_actionable_mail_includes_from_stable_id_for_current_sender_key(
    aweb_cloud_db,
):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('backend:acme.com', 'acme.com', 'backend', 'did:key:team'),
            ('frontend:acme.com', 'acme.com', 'frontend', 'did:key:team-frontend')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, subject, body, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, now())
        """,
        uuid4(),
        "did:key:z6MkAliceCurrent",
        "did:aw:bob",
        "",
        "hello",
        "body",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAliceCurrent', 'alice', 'acme.com/alice', 'open')
        """,
        uuid4(),
    )

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE did_aw=ANY($1::text[])",
        ["did:aw:alice", "did:aw:carol"],
    )
    actionable = await events_module._current_actionable_mail(
        aweb_cloud_db.aweb_db,
        inbox_dids=["did:aw:bob", "did:key:z6MkBobCurrent"],
        mail_scope=MailSuccessionScope(),
    )

    assert len(actionable) == 1
    assert actionable[0]["from_did"] == "did:key:z6MkAliceCurrent"
    assert actionable[0]["from_stable_id"] == "did:aw:alice"
    assert actionable[0]["from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_current_actionable_mail_prefers_stored_sender_address_without_local_metadata(
    aweb_cloud_db,
):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, from_address, subject, body, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, now())
        """,
        uuid4(),
        "did:aw:gsk",
        "did:aw:bob",
        "gsk",
        "otherco.com/gsk",
        "external",
        "body",
    )

    actionable = await events_module._current_actionable_mail(
        aweb_cloud_db.aweb_db,
        inbox_dids=["did:aw:bob"],
        mail_scope=MailSuccessionScope(),
    )

    assert len(actionable) == 1
    assert actionable[0]["from_did"] == "did:aw:gsk"
    assert actionable[0]["from_alias"] == "gsk"
    assert actionable[0]["from_address"] == "otherco.com/gsk"


@pytest.mark.asyncio
async def test_current_actionable_mail_redacts_encrypted_subject(aweb_cloud_db):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, subject, body, created_at,
            content_mode, message_version, encrypted_envelope, encrypted_ciphertext,
            encrypted_key_wraps, encrypted_ciphertext_hash, encrypted_ciphertext_size,
            encrypted_key_wraps_hash, encrypted_inner_header_hash, encrypted_suite,
            encrypted_signing_key_id, signed_envelope_hash
        )
        VALUES (
            $1, 'did:aw:alice', 'did:aw:bob', 'alice', '', '', now(),
            'encrypted_v2', 2, '{}'::jsonb, 'ciphertext-bytes',
            '[]'::jsonb, 'sha256:ciphertext', 16,
            'sha256:wraps', 'sha256:inner', 'E2EEv2-X25519-HPKE-AES256GCM-Ed25519',
            'did:key:z6MkAlice', 'sha256:envelope'
        )
        """,
        uuid4(),
    )

    actionable = await events_module._current_actionable_mail(
        aweb_cloud_db.aweb_db,
        inbox_dids=["did:aw:bob"],
        mail_scope=MailSuccessionScope(),
    )

    assert len(actionable) == 1
    assert actionable[0]["subject"] == ""
    assert actionable[0]["content_mode"] == "encrypted_v2"
    assert actionable[0]["message_version"] == 2
    assert actionable[0]["encrypted"] is True
    assert "ciphertext-bytes" not in str(actionable[0])


@pytest.mark.asyncio
async def test_events_stream_matches_pending_chat_across_viewer_dids(privacy_app):
    env = privacy_app
    alice = await _global_actor(env, "alice", address="example.test/alice")
    bob = await _global_actor(env, "bob")
    session_id = uuid4()
    # Retained stable-DID participants are read through current key admission.
    await env.db.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id,team_id,created_by) VALUES ($1,$2,$3)",
        session_id,
        TEAM,
        alice,
    )
    await env.db.execute(
        "INSERT INTO {{tables.chat_participants}} (session_id,did,agent_id,alias) "
        "VALUES ($1,$2,$3,'alice'),($1,$4,$5,'bob')",
        session_id,
        alice,
        env.actors["alice"].id,
        bob,
        env.actors["bob"].id,
    )
    await env.db.execute(
        "INSERT INTO {{tables.chat_messages}} (session_id,from_agent_id,from_did,from_alias,body) "
        "VALUES ($1,$2,$3,'alice','hello stable bob')",
        session_id,
        env.actors["alice"].id,
        alice,
    )
    async with _http_events(env) as (frames, _):
        event = await _next_named(frames, "actionable_chat")
    assert event["conversation_id"] == str(session_id)
    assert event["from_alias"] == "alice"
    assert event["from_did"] == alice
    assert event["from_address"] == "example.test/alice"


@pytest.mark.asyncio
async def test_current_actionable_chat_uses_per_session_participant_lists(
    aweb_cloud_db, monkeypatch
):
    class _DbShim:
        def __init__(self, aweb_db):
            self._aweb_db = aweb_db

        def get_manager(self, name="aweb"):
            assert name == "aweb"
            return self._aweb_db

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('backend:acme.com', 'acme.com', 'backend', 'did:key:team'),
            ('frontend:acme.com', 'acme.com', 'frontend', 'did:key:team-frontend')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES
            ('11111111-1111-4111-8111-111111111111', 'backend:acme.com', 'did:aw:alice'),
            ('22222222-2222-4222-8222-222222222222', 'backend:acme.com', 'did:aw:carol')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ('11111111-1111-4111-8111-111111111111', 'did:aw:bob', 'bob'),
            ('11111111-1111-4111-8111-111111111111', 'did:aw:alice', 'alice'),
            ('22222222-2222-4222-8222-222222222222', 'did:aw:bob', 'bob'),
            ('22222222-2222-4222-8222-222222222222', 'did:aw:carol', 'carol')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}} (session_id, from_did, from_alias, body)
        VALUES
            ('11111111-1111-4111-8111-111111111111', 'did:aw:alice', 'alice', 'hello from alice'),
            ('22222222-2222-4222-8222-222222222222', 'did:aw:carol', 'carol', 'hello from carol')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, inbound_mode)
        VALUES
            ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAlice', 'alice', 'acme.com/alice', 'open'),
            ($2, 'backend:acme.com', 'did:aw:bob', 'did:key:z6MkBob', 'bob', 'acme.com/bob', 'open'),
            ($3, 'frontend:acme.com', 'did:aw:carol', 'did:key:z6MkCarol', 'carol', NULL, 'open')
        """,
        uuid4(),
        uuid4(),
        uuid4(),
    )

    seen: dict[str, list[str]] = {}

    async def _fake_get_waiting_agents(
        _redis, session_id: str, participant_dids: list[str]
    ):
        seen[session_id] = list(participant_dids)
        return list(participant_dids)

    monkeypatch.setattr(events_module, "get_waiting_agents", _fake_get_waiting_agents)

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE did_aw=ANY($1::text[])",
        ["did:aw:alice", "did:aw:carol"],
    )
    actionable = await events_module._current_actionable_chat(
        _DbShim(aweb_cloud_db.aweb_db),
        None,
        participant_dids=["did:aw:bob", "did:key:bob"],
        viewer_team_id="backend:acme.com",
        participant_agent_id=None,
    )

    assert seen["11111111-1111-4111-8111-111111111111"] == ["did:aw:alice"]
    assert seen["22222222-2222-4222-8222-222222222222"] == ["did:aw:carol"]
    assert {item["session_id"] for item in actionable} == {
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    }
    assert {item["conversation_id"] for item in actionable} == {
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    }
    assert all(item["sender_waiting"] is True for item in actionable)
    by_session = {item["session_id"]: item for item in actionable}
    assert (
        by_session["11111111-1111-4111-8111-111111111111"]["from_address"]
        == "acme.com/alice"
    )
    assert by_session["11111111-1111-4111-8111-111111111111"][
        "participant_addresses"
    ] == ["acme.com/alice"]
    assert (
        by_session["22222222-2222-4222-8222-222222222222"]["from_address"]
        == "frontend~carol"
    )
    assert by_session["22222222-2222-4222-8222-222222222222"][
        "participant_addresses"
    ] == ["frontend~carol"]


@pytest.mark.asyncio
async def test_current_actionable_chat_includes_from_stable_id_for_current_sender_key(
    aweb_cloud_db, monkeypatch
):
    class _DbShim:
        def __init__(self, aweb_db):
            self._aweb_db = aweb_db

        def get_manager(self, name="aweb"):
            assert name == "aweb"
            return self._aweb_db

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ('33333333-3333-4333-8333-333333333333', 'backend:acme.com', 'did:key:z6MkAliceCurrent')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES
            ('33333333-3333-4333-8333-333333333333', 'did:aw:bob', 'bob'),
            ('33333333-3333-4333-8333-333333333333', 'did:key:z6MkAliceCurrent', 'alice')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}} (session_id, from_did, from_alias, body)
        VALUES ('33333333-3333-4333-8333-333333333333', 'did:key:z6MkAliceCurrent', '', 'hello from current key')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_aw, did_key, alias, address, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:aw:alice', 'did:key:z6MkAliceCurrent', 'alice', 'acme.com/alice', 'open')
        """,
        uuid4(),
    )

    async def _fake_get_waiting_agents(
        _redis, _session_id: str, participant_dids: list[str]
    ):
        return list(participant_dids)

    monkeypatch.setattr(events_module, "get_waiting_agents", _fake_get_waiting_agents)

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE did_aw=ANY($1::text[])",
        ["did:aw:alice", "did:aw:carol"],
    )
    actionable = await events_module._current_actionable_chat(
        _DbShim(aweb_cloud_db.aweb_db),
        None,
        participant_dids=["did:aw:bob", "did:key:z6MkBobCurrent"],
        viewer_team_id="backend:acme.com",
        participant_agent_id=None,
    )

    assert len(actionable) == 1
    assert actionable[0]["from_did"] == "did:key:z6MkAliceCurrent"
    assert actionable[0]["conversation_id"] == "33333333-3333-4333-8333-333333333333"
    assert actionable[0]["from_stable_id"] == "did:aw:alice"
    assert actionable[0]["from_address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_events_stream_emits_only_new_arrival_for_full_mail_window(privacy_app):
    env = privacy_app
    alice = await _global_actor(env, "alice")
    bob = await _global_actor(env, "bob")
    created_at = datetime.now(timezone.utc) - timedelta(hours=1)
    old_ids = [uuid4() for _ in range(50)]
    for index, message_id in enumerate(old_ids):
        # Historical null-conversation rows remain supported input to reads.
        await env.db.execute(
            "INSERT INTO {{tables.messages}} "
            "(message_id,from_did,to_did,from_alias,to_alias,subject,body,created_at) "
            "VALUES ($1,$2,$3,'alice','bob',$4,'old body',$5)",
            message_id,
            alice,
            bob,
            f"old-{index}",
            created_at + timedelta(seconds=index),
        )
    async with _http_events(env) as (frames, _):
        initial = [await _next_named(frames, "actionable_mail") for _ in range(50)]
        assert all(item["conversation_id"] == item["message_id"] for item in initial)
        # The real writer also advances the recipient change counter/pubsub.
        newest = await _send_mail(env, "newest")
        changed = await _next_named(frames, "actionable_mail")
        async with asyncio.timeout(5):
            assert (await anext(frames))[0] == "keepalive"
    assert changed["message_id"] == newest["message_id"]
    assert changed["unread_count"] == 51
    current = await events_module._current_actionable_mail(
        env.db,
        inbox_dids=[bob],
        mail_scope=MailSuccessionScope(),
    )
    assert (
        next(item for item in current if item["message_id"] == newest["message_id"])[
            "conversation_id"
        ]
        == newest["conversation_id"]
    )
    all_ids = {*(str(value) for value in old_ids), newest["message_id"]}
    presented = {item["message_id"] for item in current}
    omitted = all_ids - presented
    assert len(omitted) == 1
    for message_id in presented:
        response = await request_as(
            env,
            alias="bob",
            method="POST",
            path=f"/v1/messages/{message_id}/ack",
            payload={},
        )
        assert response.status_code == 200, response.text
    after_ack = await events_module._current_actionable_mail(
        env.db,
        inbox_dids=[bob],
        mail_scope=MailSuccessionScope(),
    )
    assert {item["message_id"] for item in after_ack} == omitted


@pytest.mark.asyncio
async def test_events_stream_emits_one_mail_event_when_only_unread_count_changes(
    privacy_app,
):
    env = privacy_app
    await _global_actor(env, "alice")
    await _global_actor(env, "bob")
    messages = [await _send_mail(env, f"message-{index}") for index in range(2)]
    async with _http_events(env) as (frames, _):
        initial = [await _next_named(frames, "actionable_mail") for _ in range(2)]
        assert {item["unread_count"] for item in initial} == {2}
        # Finish the opening snapshot before changing the real inbox.
        async with asyncio.timeout(5):
            assert (await anext(frames))[0] == "keepalive"
        ack = await request_as(
            env,
            alias="bob",
            method="POST",
            path=f"/v1/messages/{messages[0]['message_id']}/ack",
            payload={},
        )
        assert ack.status_code == 200, ack.text
        update = await _next_named(frames, "actionable_mail")
        async with asyncio.timeout(5):
            assert (await anext(frames))[0] == "keepalive"
    assert update["message_id"] == messages[1]["message_id"]
    assert update["unread_count"] == 1


@pytest.mark.asyncio
async def test_events_stream_opening_frames_restart_the_heartbeat_interval(
    privacy_app,
    monkeypatch,
):
    env = privacy_app
    await _global_actor(env, "alice")
    bob_did_aw = await _global_actor(env, "bob")
    messages = [await _send_mail(env, f"message-{index}") for index in range(2)]
    bob = env.actors["bob"]
    # The generator is read directly so the test, not the server, decides when
    # the stream runs: no frame is produced while the test sleeps.
    stream = await _open_test_event_stream(
        env.db,
        bob.id,
        monkeypatch,
        identity=TeamIdentity(
            team_id=TEAM,
            alias="bob",
            did_key=bob.did,
            did_aw=bob_did_aw,
            address="",
            agent_id=str(bob.id),
            identity_scope="global",
            certificate_id="global-bob",
            grant=None,
        ),
    )
    for _ in range(2):
        assert (await anext(stream)).startswith("event: actionable_mail\n")

    # The opening keepalive is now older than the heartbeat interval, but the
    # stream has just delivered frames, so the change is read before any heartbeat.
    await asyncio.sleep(2 * events_module.EVENTS_HEARTBEAT_INTERVAL)
    ack = await request_as(
        env,
        alias="bob",
        method="POST",
        path=f"/v1/messages/{messages[0]['message_id']}/ack",
        payload={},
    )
    assert ack.status_code == 200, ack.text

    next_frame = await anext(stream)
    await stream.aclose()

    assert next_frame.startswith("event: actionable_mail\n")
    count_update = json.loads(next_frame.split("data: ", 1)[1])
    assert count_update["message_id"] == messages[1]["message_id"]
    assert count_update["unread_count"] == 1


@pytest.mark.xfail(
    strict=True,
    reason="aweb-abbr.1: actionable mail has no row event for last-read-to-zero",
)
@pytest.mark.asyncio
async def test_events_stream_signals_last_unread_count_reaching_zero(
    aweb_cloud_db,
    monkeypatch,
):
    recipient_agent_id = await _create_test_event_recipient(aweb_cloud_db.aweb_db)
    message_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}}
            (message_id, from_did, to_did, from_alias, to_alias, subject, body, created_at)
        VALUES ($1, 'did:aw:alice', 'did:aw:bob', 'alice', 'bob', 'subject', 'body', NOW())
        """,
        message_id,
    )
    stream = await _open_test_event_stream(
        aweb_cloud_db.aweb_db,
        recipient_agent_id,
        monkeypatch,
    )
    initial_event = json.loads((await anext(stream)).split("data: ", 1)[1])
    assert initial_event["unread_count"] == 1

    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.messages}}
        SET read_at = NOW()
        WHERE message_id = $1
        """,
        message_id,
    )

    zero_update_frame = await anext(stream)
    await stream.aclose()

    assert zero_update_frame.startswith("event:")
    zero_update = json.loads(zero_update_frame.split("data: ", 1)[1])
    assert zero_update["unread_count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("recipient_did", ["did:aw:bob", "did:key:z6MkBob"])
@pytest.mark.parametrize("sender_waiting", [False, True])
@pytest.mark.parametrize("release_wait", ["unregister", "stale"])
async def test_events_stream_defers_recipient_wait_until_next_poll(
    aweb_cloud_db, monkeypatch, recipient_did, sender_waiting, release_wait
):
    from types import SimpleNamespace
    import aweb.messaging.waiting as waiting_module

    # Exercise the production waiting helpers without a Redis process. The
    # fake stores sorted-set scores; it does not decide who is waiting.
    class WaitingRedis:
        def __init__(self):
            self.scores = {}

        def pipeline(self):
            redis = self

            class Pipeline:
                def __init__(self):
                    self.commands = []

                def zadd(self, key, values):
                    self.commands.append(("zadd", key, values))

                def expire(self, key, ttl):
                    self.commands.append(("expire", key, ttl))

                def zscore(self, key, member):
                    self.commands.append(("zscore", key, member))

                async def execute(self):
                    results = []
                    for command, key, value in self.commands:
                        if command == "zadd":
                            redis.scores.setdefault(key, {}).update(value)
                            results.append(1)
                        elif command == "zscore":
                            results.append(redis.scores.get(key, {}).get(value))
                        else:
                            results.append(True)
                    return results

            return Pipeline()

        async def zrem(self, key, member):
            self.scores.get(key, {}).pop(member, None)

    now = [1000.0]
    monkeypatch.setattr(waiting_module, "time", SimpleNamespace(time=lambda: now[0]))
    redis = WaitingRedis()
    db = aweb_cloud_db.aweb_db
    agent_id = await _create_test_event_recipient(db)
    engaged, other = uuid4(), uuid4()
    for session_id in (engaged, other):
        await db.execute(
            """
            INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
            VALUES ($1, 'backend:acme.com', 'did:aw:alice')
            """,
            session_id,
        )
        await db.execute(
            """
            INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
            VALUES ($1, 'did:aw:bob', 'bob'), ($1, 'did:aw:alice', 'alice')
            """,
            session_id,
        )
        await db.execute(
            """
            INSERT INTO {{tables.chat_messages}} (session_id, from_did, from_alias, body)
            VALUES ($1, 'did:aw:alice', 'alice', 'unread message')
            """,
            session_id,
        )
        if sender_waiting:
            await waiting_module.register_waiting(
                redis, str(session_id), "did:aw:alice"
            )
    await waiting_module.register_waiting(redis, str(engaged), recipient_did)
    stream = await _open_test_event_stream(db, agent_id, monkeypatch, redis=redis)
    try:
        initial_chat = []
        # Drain the snapshot through its first keepalive, proving S is absent
        # regardless of database ordering, while the other session is delivered.
        while True:
            chunk = await anext(stream)
            if chunk.startswith(": keepalive"):
                break
            if chunk.startswith("event: actionable_chat\n"):
                initial_chat.append(json.loads(chunk.split("data: ", 1)[1]))
        assert [e["session_id"] for e in initial_chat] == [str(other)]
        assert initial_chat[0]["sender_waiting"] is sender_waiting
        assert initial_chat[0]["wake_mode"] == (
            "interrupt" if sender_waiting else "prompt"
        )

        if release_wait == "unregister":
            await waiting_module.unregister_waiting(redis, str(engaged), recipient_did)
        else:
            now[0] += 91  # Beyond the real helper's freshness window, no sleep.
            if sender_waiting:
                for session_id in (engaged, other):
                    await waiting_module.register_waiting(
                        redis, str(session_id), "did:aw:alice"
                    )

        resumed = json.loads((await anext(stream)).split("data: ", 1)[1])
        assert resumed["type"] == "actionable_chat"
        assert resumed["session_id"] == str(engaged)
        assert resumed["unread_count"] == 1
        assert resumed["sender_waiting"] is sender_waiting
        assert resumed["wake_mode"] == ("interrupt" if sender_waiting else "prompt")
        # Unchanged other-session state must not be re-emitted on this poll.
        assert (await anext(stream)).startswith(": keepalive")
    finally:
        await stream.aclose()

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _deadline(seconds: int = 5) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


async def _seed_basic_project(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")

    project_id = uuid.uuid4()
    agent_1_id = uuid.uuid4()
    agent_2_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "test-project",
        "Test Project",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_1_id,
        project_id,
        "agent-1",
        "Agent One",
        "agent",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_2_id,
        project_id,
        "agent-2",
        "Agent Two",
        "agent",
    )

    api_key_1 = f"aw_sk_{uuid.uuid4().hex}"
    api_key_2 = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_1_id,
        api_key_1[:12],
        hash_api_key(api_key_1),
        True,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_2_id,
        api_key_2[:12],
        hash_api_key(api_key_2),
        True,
    )

    return {
        "project_id": str(project_id),
        "agent_1_id": str(agent_1_id),
        "agent_2_id": str(agent_2_id),
        "api_key_1": api_key_1,
        "api_key_2": api_key_2,
    }


async def _collect_sse_text(
    *,
    client: AsyncClient,
    url: str,
    params: dict[str, str],
    headers: dict[str, str],
) -> str:
    # Note: httpx ASGITransport may buffer the full response body. For these tests we
    # intentionally set a short deadline so the stream naturally terminates.
    resp = await client.get(url, params=params, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.text


@pytest.mark.asyncio
async def test_aweb_chat_session_uniqueness_pending_read_flow(aweb_db_infra):
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])
            msg1 = "hello"
            msg2 = "reverse"

            r1 = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={
                    "to_aliases": ["agent-2"],
                    "message": msg1,
                    "leaving": False,
                },
            )
            assert r1.status_code == 200, r1.text
            d1 = r1.json()

            # Check pending BEFORE agent-2 replies — agent-2's reply will
            # auto-advance their read receipt, clearing the unread count.
            pending = await client.get(
                "/v1/chat/pending",
                headers=headers_2,
            )
            assert pending.status_code == 200, pending.text
            p = pending.json()
            found = next(
                (c for c in (p.get("pending") or []) if c.get("session_id") == d1["session_id"]),
                None,
            )
            assert found is not None
            assert found["last_from"] == "agent-1"
            assert found["unread_count"] == 1

            # Fetch unread messages and mark-read BEFORE agent-2 replies,
            # since replying auto-advances the read receipt.
            unread = await client.get(
                f"/v1/chat/sessions/{d1['session_id']}/messages",
                headers=headers_2,
                params={"unread_only": True, "limit": 1000},
            )
            assert unread.status_code == 200, unread.text
            msgs = unread.json().get("messages") or []
            assert len(msgs) >= 1

            last_message_id = msgs[-1]["message_id"]
            mark = await client.post(
                f"/v1/chat/sessions/{d1['session_id']}/read",
                headers=headers_2,
                json={"up_to_message_id": last_message_id},
            )
            assert mark.status_code == 200, mark.text
            assert mark.json().get("success") is True

            # Agent-2 replies — session uniqueness check.
            r2 = await client.post(
                "/v1/chat/sessions",
                headers=headers_2,
                json={
                    "to_aliases": ["agent-1"],
                    "message": msg2,
                    "leaving": False,
                },
            )
            assert r2.status_code == 200, r2.text
            d2 = r2.json()
            assert d2["session_id"] == d1["session_id"]


@pytest.mark.asyncio
async def test_aweb_chat_sender_reply_clears_pending(aweb_db_infra):
    """Replying in a chat session advances the sender's read receipt, clearing pending."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Agent-1 sends "hello" to agent-2
            r1 = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r1.status_code == 200, r1.text
            session_id = r1.json()["session_id"]

            # Agent-2 should see 1 unread from agent-1
            pending = await client.get("/v1/chat/pending", headers=headers_2)
            assert pending.status_code == 200, pending.text
            p = pending.json()
            found = next(
                (c for c in p["pending"] if c["session_id"] == session_id),
                None,
            )
            assert found is not None
            assert found["unread_count"] == 1
            assert found["last_from"] == "agent-1"

            # Agent-2 replies via create_or_send
            r2 = await client.post(
                "/v1/chat/sessions",
                headers=headers_2,
                json={"to_aliases": ["agent-1"], "message": "got it", "leaving": False},
            )
            assert r2.status_code == 200, r2.text

            # Agent-2 should now have NO pending (reply advanced read receipt)
            pending2 = await client.get("/v1/chat/pending", headers=headers_2)
            assert pending2.status_code == 200, pending2.text
            p2 = pending2.json()
            found2 = next(
                (c for c in p2["pending"] if c["session_id"] == session_id),
                None,
            )
            assert found2 is None, f"Expected no pending for agent-2, got: {found2}"

            # Also verify via send_message endpoint
            # Agent-1 sends another message
            r3 = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_1,
                json={"body": "follow-up"},
            )
            assert r3.status_code == 200, r3.text

            # Agent-2 sees 1 unread again
            pending3 = await client.get("/v1/chat/pending", headers=headers_2)
            assert pending3.status_code == 200, pending3.text
            p3 = pending3.json()
            found3 = next(
                (c for c in p3["pending"] if c["session_id"] == session_id),
                None,
            )
            assert found3 is not None
            assert found3["unread_count"] == 1

            # Agent-2 replies via send_message
            r4 = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_2,
                json={"body": "got that too"},
            )
            assert r4.status_code == 200, r4.text

            # Agent-2 should again have no pending
            pending4 = await client.get("/v1/chat/pending", headers=headers_2)
            assert pending4.status_code == 200, pending4.text
            p4 = pending4.json()
            found4 = next(
                (c for c in p4["pending"] if c["session_id"] == session_id),
                None,
            )
            assert found4 is None, f"Expected no pending after send_message reply, got: {found4}"


@pytest.mark.asyncio
async def test_aweb_chat_sse_replay_live_and_read_receipt(aweb_db_infra):
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            create = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={
                    "to_aliases": ["agent-2"],
                    "message": "baseline",
                    "leaving": False,
                },
            )
            assert create.status_code == 200, create.text
            session_id = create.json()["session_id"]
            baseline_message_id = create.json()["message_id"]

            sse_path = f"/v1/chat/sessions/{session_id}/stream"
            # Replay should include baseline.
            replay_text = await _collect_sse_text(
                client=client,
                url=sse_path,
                params={"deadline": _deadline(1)},
                headers=headers_2,
            )
            assert baseline_message_id in replay_text

            # Live message after connect: start stream and send while it's open.
            stream_task = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(2)},
                    headers=headers_2,
                )
            )
            await asyncio.sleep(0.25)
            live = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={
                    "to_aliases": ["agent-2"],
                    "message": "live",
                    "leaving": False,
                },
            )
            assert live.status_code == 200, live.text
            live_message_id = live.json()["message_id"]
            stream_text = await stream_task
            assert live_message_id in stream_text

            # Read receipt: start agent1 stream then mark read as agent2.
            rr_stream_task = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(2)},
                    headers=headers_1,
                )
            )
            await asyncio.sleep(0.25)
            mark = await client.post(
                f"/v1/chat/sessions/{session_id}/read",
                headers=headers_2,
                json={"up_to_message_id": live_message_id},
            )
            assert mark.status_code == 200, mark.text
            rr_text = await rr_stream_task
            assert '"type": "read_receipt"' in rr_text
            assert live_message_id in rr_text
            assert "agent-2" in rr_text
            assert '"extends_wait_seconds": 300' in rr_text


@pytest.mark.asyncio
async def test_aweb_chat_send_message_in_existing_session(aweb_db_infra):
    """POST /v1/chat/sessions/{session_id}/messages sends in an existing session."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Create a session first
            r1 = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r1.status_code == 200, r1.text
            session_id = r1.json()["session_id"]

            # Send a follow-up message in the same session
            r2 = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_2,
                json={"body": "hi back"},
            )
            assert r2.status_code == 200, r2.text
            d2 = r2.json()
            assert "message_id" in d2
            assert d2["delivered"] is True
            assert d2["extends_wait_seconds"] == 0

            # Verify message appears in history
            history = await client.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_1,
            )
            assert history.status_code == 200, history.text
            msgs = history.json()["messages"]
            bodies = [m["body"] for m in msgs]
            assert "hello" in bodies
            assert "hi back" in bodies


@pytest.mark.asyncio
async def test_aweb_chat_send_message_hang_on(aweb_db_infra):
    """POST /v1/chat/sessions/{session_id}/messages with hang_on=true returns extends_wait_seconds."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            r1 = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r1.status_code == 200, r1.text
            session_id = r1.json()["session_id"]

            # Start SSE stream, then send hang-on message while it's open
            sse_path = f"/v1/chat/sessions/{session_id}/stream"
            stream_task = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(2)},
                    headers=headers_1,
                )
            )
            await asyncio.sleep(0.25)

            r2 = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_2,
                json={"body": "hang on, thinking...", "hang_on": True},
            )
            assert r2.status_code == 200, r2.text
            d2 = r2.json()
            assert d2["extends_wait_seconds"] == 300
            assert d2["delivered"] is True

            # Verify SSE stream contains hang_on=true and extends_wait_seconds
            stream_text = await stream_task
            assert '"hang_on": true' in stream_text
            assert '"extends_wait_seconds": 300' in stream_text


@pytest.mark.asyncio
async def test_aweb_chat_send_message_non_participant_rejected(aweb_db_infra):
    """POST /v1/chat/sessions/{session_id}/messages rejects non-participants."""
    seeded = await _seed_basic_project(aweb_db_infra)
    aweb_db = aweb_db_infra.get_manager("aweb")

    # Create a third agent that is NOT part of the chat
    agent_3_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_3_id,
        uuid.UUID(seeded["project_id"]),
        "agent-3",
        "Agent Three",
        "agent",
    )
    api_key_3 = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        uuid.UUID(seeded["project_id"]),
        agent_3_id,
        api_key_3[:12],
        hash_api_key(api_key_3),
        True,
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_3 = _auth_headers(api_key_3)

            # Create session between agent-1 and agent-2
            r1 = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r1.status_code == 200, r1.text
            session_id = r1.json()["session_id"]

            # agent-3 tries to send to that session
            r2 = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_3,
                json={"body": "intruder"},
            )
            assert r2.status_code == 403


@pytest.mark.asyncio
async def test_aweb_chat_send_message_nonexistent_session(aweb_db_infra):
    """POST /v1/chat/sessions/{session_id}/messages returns 404 for nonexistent session."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            fake_session = str(uuid.uuid4())

            r = await client.post(
                f"/v1/chat/sessions/{fake_session}/messages",
                headers=headers_1,
                json={"body": "hello"},
            )
            assert r.status_code == 404


@pytest.mark.asyncio
async def test_aweb_chat_send_message_cross_project_rejected(aweb_db_infra):
    """POST /v1/chat/sessions/{session_id}/messages rejects cross-project access."""
    seeded = await _seed_basic_project(aweb_db_infra)
    aweb_db = aweb_db_infra.get_manager("aweb")

    # Create a second project with its own agent
    project_2_id = uuid.uuid4()
    agent_other_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_2_id,
        "other-project",
        "Other Project",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_other_id,
        project_2_id,
        "other-agent",
        "Other Agent",
        "agent",
    )
    api_key_other = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        project_2_id,
        agent_other_id,
        api_key_other[:12],
        hash_api_key(api_key_other),
        True,
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_other = _auth_headers(api_key_other)

            # Create session in project 1
            r1 = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r1.status_code == 200, r1.text
            session_id = r1.json()["session_id"]

            # Agent from project 2 tries to send to project 1's session
            r2 = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_other,
                json={"body": "intruder"},
            )
            assert r2.status_code == 404


@pytest.mark.asyncio
async def test_aweb_chat_list_sessions(aweb_db_infra):
    """GET /v1/chat/sessions lists sessions the agent participates in."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # No sessions yet
            r0 = await client.get("/v1/chat/sessions", headers=headers_1)
            assert r0.status_code == 200, r0.text
            assert r0.json()["sessions"] == []

            # Create a session
            r1 = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r1.status_code == 200, r1.text
            session_id = r1.json()["session_id"]

            # Both agents should see it
            r2 = await client.get("/v1/chat/sessions", headers=headers_1)
            assert r2.status_code == 200, r2.text
            sessions = r2.json()["sessions"]
            assert len(sessions) == 1
            assert sessions[0]["session_id"] == session_id
            assert "agent-1" in sessions[0]["participants"]
            assert "agent-2" in sessions[0]["participants"]
            assert "created_at" in sessions[0]

            r3 = await client.get("/v1/chat/sessions", headers=headers_2)
            assert r3.status_code == 200, r3.text
            assert len(r3.json()["sessions"]) == 1


@pytest.mark.asyncio
async def test_aweb_chat_list_sessions_tenant_isolation(aweb_db_infra):
    """GET /v1/chat/sessions does not return sessions from other projects."""
    seeded = await _seed_basic_project(aweb_db_infra)
    aweb_db = aweb_db_infra.get_manager("aweb")

    # Create a second project with its own agent
    project_2_id = uuid.uuid4()
    agent_other_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_2_id,
        "other-project",
        "Other Project",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
        agent_other_id,
        project_2_id,
        "other-agent",
        "Other Agent",
        "agent",
    )
    api_key_other = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4, $5)",
        project_2_id,
        agent_other_id,
        api_key_other[:12],
        hash_api_key(api_key_other),
        True,
    )

    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_other = _auth_headers(api_key_other)

            # Create a session in project 1
            await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )

            # Agent in project 2 should see no sessions
            r = await client.get("/v1/chat/sessions", headers=headers_other)
            assert r.status_code == 200, r.text
            assert r.json()["sessions"] == []


@pytest.mark.asyncio
async def test_sse_registers_waiting_in_redis(aweb_db_infra, async_redis):
    """SSE stream registers agent in Redis on connect and removes on disconnect."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Create a session.
            r = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            # Start SSE stream for agent-2.
            sse_path = f"/v1/chat/sessions/{session_id}/stream"
            stream_task = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(2)},
                    headers=headers_2,
                )
            )
            await asyncio.sleep(0.3)

            # Mid-stream: agent-2 should be registered in Redis.
            key = f"chat:waiting:{session_id}"
            score = await async_redis.zscore(key, seeded["agent_2_id"])
            assert score is not None, "agent-2 should be registered as waiting in Redis"

            # Wait for stream to end.
            await stream_task

            # After stream ends: agent-2 should be removed.
            score_after = await async_redis.zscore(key, seeded["agent_2_id"])
            assert score_after is None, "agent-2 should be unregistered after SSE ends"


@pytest.mark.asyncio
async def test_sse_message_includes_sender_waiting_true(aweb_db_infra, async_redis):
    """SSE message events include sender_waiting=true when sender has active SSE."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Create a session.
            r = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            # Start SSE for agent-1 (so agent-1 is "waiting").
            sse_path = f"/v1/chat/sessions/{session_id}/stream"
            agent1_stream = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(3)},
                    headers=headers_1,
                )
            )
            await asyncio.sleep(0.3)

            # Start SSE for agent-2 to receive live messages.
            agent2_stream = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(3)},
                    headers=headers_2,
                )
            )
            await asyncio.sleep(0.3)

            # Agent-1 sends a message while both SSE streams are active.
            send = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=headers_1,
                json={"body": "are you there?"},
            )
            assert send.status_code == 200, send.text

            # Wait for both streams to end.
            agent2_text = await agent2_stream
            await agent1_stream

            # Parse message events from agent-2's stream and find the live one.
            for line in agent2_text.split("\n"):
                if line.startswith("data: "):
                    data = json.loads(line[6:])
                    if data.get("type") == "message" and data.get("body") == "are you there?":
                        assert data["sender_waiting"] is True, (
                            f"Expected sender_waiting=true, got {data}"
                        )
                        break
            else:
                raise AssertionError("Did not find 'are you there?' message in SSE stream")


@pytest.mark.asyncio
async def test_sse_message_sender_waiting_false_without_redis(aweb_db_infra):
    """SSE message events include sender_waiting=false when redis is None."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=None)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Create a session.
            r = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            # Collect SSE replay events.
            sse_text = await _collect_sse_text(
                client=client,
                url=f"/v1/chat/sessions/{session_id}/stream",
                params={"deadline": _deadline(1)},
                headers=headers_2,
            )

            # All message events should have sender_waiting=false.
            for line in sse_text.split("\n"):
                if line.startswith("data: "):
                    data = json.loads(line[6:])
                    if data.get("type") == "message":
                        assert data["sender_waiting"] is False, (
                            f"Expected sender_waiting=false without redis, got {data}"
                        )


@pytest.mark.asyncio
async def test_pending_sender_waiting_true(aweb_db_infra, async_redis):
    """GET /v1/chat/pending shows sender_waiting=true when sender has active SSE."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Agent-1 sends.
            r = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            # Agent-1 starts SSE (so they're "waiting").
            sse_path = f"/v1/chat/sessions/{session_id}/stream"
            stream_task = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(3)},
                    headers=headers_1,
                )
            )
            await asyncio.sleep(0.3)

            # Agent-2 checks pending.
            pending = await client.get("/v1/chat/pending", headers=headers_2)
            assert pending.status_code == 200, pending.text
            p = pending.json()
            found = next(
                (c for c in p["pending"] if c["session_id"] == session_id),
                None,
            )
            assert found is not None
            assert found["sender_waiting"] is True

            await stream_task


@pytest.mark.asyncio
async def test_pending_sender_waiting_false_no_sse(aweb_db_infra, async_redis):
    """GET /v1/chat/pending shows sender_waiting=false when sender has no SSE."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Agent-1 sends but does NOT start SSE.
            r = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            # Agent-2 checks pending — sender_waiting should be false.
            pending = await client.get("/v1/chat/pending", headers=headers_2)
            assert pending.status_code == 200, pending.text
            p = pending.json()
            found = next(
                (c for c in p["pending"] if c["session_id"] == session_id),
                None,
            )
            assert found is not None
            assert found["sender_waiting"] is False


@pytest.mark.asyncio
async def test_create_or_send_targets_connected(aweb_db_infra, async_redis):
    """POST /v1/chat/sessions returns connected targets when they have active SSE."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Create a session first.
            r = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "initial", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            # Agent-2 starts SSE.
            sse_path = f"/v1/chat/sessions/{session_id}/stream"
            stream_task = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(3)},
                    headers=headers_2,
                )
            )
            await asyncio.sleep(0.3)

            # Agent-1 sends again — should see agent-2 as connected.
            r2 = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "followup", "leaving": False},
            )
            assert r2.status_code == 200, r2.text
            assert "agent-2" in r2.json()["targets_connected"]

            await stream_task


@pytest.mark.asyncio
async def test_create_or_send_targets_connected_empty(aweb_db_infra, async_redis):
    """POST /v1/chat/sessions returns empty targets_connected when no SSE streams."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])

            r = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r.status_code == 200, r.text
            assert r.json()["targets_connected"] == []


@pytest.mark.asyncio
async def test_list_sessions_sender_waiting(aweb_db_infra, async_redis):
    """GET /v1/chat/sessions includes sender_waiting when other participant has SSE."""
    seeded = await _seed_basic_project(aweb_db_infra)
    app = create_app(db_infra=aweb_db_infra, redis=async_redis)

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", timeout=10.0
        ) as client:
            headers_1 = _auth_headers(seeded["api_key_1"])
            headers_2 = _auth_headers(seeded["api_key_2"])

            # Create a session.
            r = await client.post(
                "/v1/chat/sessions",
                headers=headers_1,
                json={"to_aliases": ["agent-2"], "message": "hello", "leaving": False},
            )
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]

            # Agent-1 starts SSE.
            sse_path = f"/v1/chat/sessions/{session_id}/stream"
            stream_task = asyncio.create_task(
                _collect_sse_text(
                    client=client,
                    url=sse_path,
                    params={"deadline": _deadline(3)},
                    headers=headers_1,
                )
            )
            await asyncio.sleep(0.3)

            # Agent-2 lists sessions — should see sender_waiting=true.
            r2 = await client.get("/v1/chat/sessions", headers=headers_2)
            assert r2.status_code == 200, r2.text
            sessions = r2.json()["sessions"]
            assert len(sessions) == 1
            assert sessions[0]["sender_waiting"] is True

            await stream_task

"""Inject poll-query faults through the actual SSE generator; no live service."""
import asyncio
import json
from collections import deque
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from pgdbm.errors import QueryError

import aweb.routes.events as events
import aweb.grant_streams as grant_streams
from aweb.team_auth_deps import TeamIdentity


class PollHarness:
    def __init__(self, monkeypatch, *, target="mail", actions=(), stop_at=50, deadline=120):
        self.now = 0.0
        self.actions = deque(actions)
        self.attempts = []
        self.frames = []
        self.failures = 0
        self.calls = {"mail": 0, "chat": 0}
        self.block_query = False
        self.block_backoff = False
        self.blocked = asyncio.Event()
        self.never = asyncio.Event()
        self.tick_count = 0
        self.origin = datetime(2026, 10, 7, tzinfo=timezone.utc)
        self.message = UUID("11111111-1111-4111-8111-111111111111")
        self.mail_visible = False
        harness = self

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return harness.origin + timedelta(seconds=harness.now)

        async def sleep(delay):
            assert delay == 1.0  # Backoff must not delay disconnect/grant checks.
            if self.block_backoff and self.failures:
                self.blocked.set()
                await self.never.wait()
            self.now += delay
            self.tick_count += 1
            assert self.tick_count < 150, "poll loop failed to finish"
            await asyncio.sleep(0)

        async def fetch_all(query, *args):
            if "WITH unread AS" in query:
                kind = "mail"
            elif "array_agg(p2.alias" in query:
                kind = "chat"
            else:
                return []  # empty sender metadata for this synthetic fixture
            self.calls[kind] += 1
            initial = self.calls[kind] == 1
            if kind == target and not initial:
                self.attempts.append(self.now)
                if self.block_query:
                    self.blocked.set()
                    await self.never.wait()
                if self.actions:
                    action, duration = self.actions.popleft()
                    self.now += duration
                    if action == "fail":
                        self.failures += 1
                        raise QueryError("canceling statement due to user request")
                    if action == "ok":
                        self.mail_visible = True
            if kind == "mail" and self.mail_visible:
                return [{"message_id": self.message, "conversation_id": self.message,
                         "from_did": "", "from_alias": "alice", "from_address": "",
                         "subject": "later event", "priority": "normal", "content_mode": "legacy_plaintext_v1",
                         "message_version": 1, "created_at": self.origin, "unread_count": 1}]
            return []

        manager = SimpleNamespace(fetch_one=AsyncMock(return_value={"did_key": "did:key:test", "did_aw": ""}),
                                  fetch_all=fetch_all)
        db = SimpleNamespace(get_manager=lambda name="aweb": manager)
        request = SimpleNamespace(is_disconnected=AsyncMock(side_effect=lambda: self.now >= stop_at))
        self.request = request
        monkeypatch.setattr(events, "datetime", Clock)
        monkeypatch.setattr(events, "monotonic", lambda: self.now)
        monkeypatch.setattr(events, "asyncio", SimpleNamespace(sleep=sleep))
        monkeypatch.setattr(events, "_poll_control_signals", AsyncMock(return_value=[]))
        monkeypatch.setattr(events, "current_app_events_for_agent", AsyncMock(return_value=[]))
        self.identity = TeamIdentity(team_id="backend:acme.com", alias="bob", did_key="did:key:test",
                                     did_aw="", address="", agent_id="22222222-2222-4222-8222-222222222222",
                                     identity_scope="local", certificate_id="cert", grant=None)
        self.stream = events._sse_agent_events(request=request, db=db, redis=None,
                            team_id=self.identity.team_id, agent_id=self.identity.agent_id,
                            identity=self.identity, deadline=self.origin + timedelta(seconds=deadline))

    async def collect(self):
        async for frame in self.stream:
            self.frames.append((self.now, frame))
        return [frame for _, frame in self.frames]

    def assert_logged(self, caplog):
        failures = [record for record in caplog.records if "event-stream poll error" in record.message]
        assert len(failures) == self.failures
        assert all(record.exc_info for record in failures)


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["mail", "chat"])
@pytest.mark.parametrize("actions,expected", [
    ([("fail", 0), ("ok", 0)], [1, 2]),
    ([("fail", 0), ("fail", 0), ("fail", 0), ("ok", 0)], [1, 2, 4, 8]),
    ([("fail", 0), ("fail", 26), ("ok", 0)], [1, 2, 30]),
    # Exactly 30 seconds since first failure is still recoverable.
    ([("fail", 0), ("fail", 29), ("ok", 0)], [1, 2, 33]),
])
async def test_poll_failures_recover(monkeypatch, caplog, target, actions, expected):
    h = PollHarness(monkeypatch, target=target, actions=actions)
    frames = await h.collect()
    assert h.attempts[:len(expected)] == expected
    assert not any(frame.startswith("event: error") for frame in frames)
    mail = [frame for frame in frames if frame.startswith("event: actionable_mail")]
    assert len(mail) == 1  # last successful snapshot was retained during failure
    assert json.loads(mail[0].split("data: ")[1])["message_id"] == str(h.message)
    h.assert_logged(caplog)


@pytest.mark.asyncio
async def test_complete_success_resets_failure_window_and_backoff(monkeypatch, caplog):
    h = PollHarness(monkeypatch, target="chat", actions=[("fail", 0), ("ok", 0),
                       ("fail", 0), ("fail", 26), ("ok", 0)])
    frames = await h.collect()
    assert h.attempts[:5] == [1, 2, 3, 4, 32]
    assert not any(frame.startswith("event: error") for frame in frames)
    # Successful mail queries during failed chat polls did not reset the streak.
    h.assert_logged(caplog)


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["mail", "chat"])
async def test_sustained_poll_failure_ends_with_existing_error(monkeypatch, caplog, target):
    h = PollHarness(monkeypatch, target=target, actions=[("fail", 0)] * 20)
    frames = await h.collect()
    assert h.attempts == [1, 2, 4, 8, 13, 18, 23, 28, 33]
    assert frames[-1] == 'event: error\ndata: {"type": "error", "detail": "poll failure"}\n\n'
    assert sum(frame.startswith("event: error") for frame in frames) == 1
    h.assert_logged(caplog)


@pytest.mark.asyncio
async def test_backoff_preserves_heartbeat_then_recovers(monkeypatch, caplog):
    # Healthy until t=10, failures t=10..32 (<25s), recovery t=37. Heartbeat
    # remains due at t=30 even though no complete poll succeeded since t=9.
    h = PollHarness(monkeypatch, actions=[("quiet", 0)] * 9 + [("fail", 0)] * 7 + [("ok", 0)])
    await h.collect()
    heartbeats = [at for at, frame in h.frames if frame == ": keepalive\n\n"]
    assert heartbeats[:2] == [0, 30]
    assert [at for at, frame in h.frames if frame.startswith("event: actionable_mail")] == [37]
    assert h.attempts[9:17] == [10, 11, 13, 17, 22, 27, 32, 37]
    assert not any(frame.startswith("event: error") for _, frame in h.frames)
    h.assert_logged(caplog)


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["disconnect", "deadline", "grant"])
async def test_backoff_checks_stream_boundaries_every_tick(monkeypatch, caplog, boundary):
    h = PollHarness(monkeypatch, actions=[("fail", 0)] * 20,
                    stop_at=3 if boundary == "disconnect" else 50,
                    deadline=3 if boundary == "deadline" else 120)
    if boundary == "grant":
        monkeypatch.setattr(grant_streams, "grant_expiry_reason", lambda identity: "grant_expired" if h.now >= 3 else None)
    frames = await h.collect()
    assert h.attempts == [1, 2]
    assert h.now == 3
    assert not any(frame.startswith("event: error") for frame in frames)
    assert any("grant_expired" in frame for frame in frames) == (boundary == "grant")
    h.assert_logged(caplog)


@pytest.mark.asyncio
@pytest.mark.parametrize("during", ["query", "backoff"])
async def test_real_task_cancellation_is_not_a_poll_failure(monkeypatch, caplog, during):
    h = PollHarness(monkeypatch, actions=[("fail", 0)] * 20)
    h.block_query = during == "query"
    h.block_backoff = during == "backoff"
    task = asyncio.create_task(h.collect())
    await asyncio.wait_for(h.blocked.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1)
    assert not any(frame.startswith("event: error") for _, frame in h.frames)
    assert h.failures == (1 if during == "backoff" else 0)
    h.assert_logged(caplog)

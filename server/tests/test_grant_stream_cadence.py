"""Real stream handlers with simulated time and DB/registry/Redis boundaries."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException

from aweb import grant_streams
from aweb.auth_context import GrantContext
from aweb.routes import chat, events, status
from aweb.team_auth_deps import TeamIdentity


@pytest.fixture
def harness(monkeypatch):
    start = datetime.now(timezone.utc)
    clock = SimpleNamespace(seconds=0.0)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return start + timedelta(seconds=clock.seconds)

    async def sleep(seconds):
        clock.seconds += seconds

    for module in (chat, events, status, grant_streams):
        monkeypatch.setattr(module, "datetime", Clock)
    monkeypatch.setattr(chat, "time", SimpleNamespace(monotonic=lambda: clock.seconds))
    monkeypatch.setattr(grant_streams, "time", SimpleNamespace(monotonic=lambda: clock.seconds))
    monkeypatch.setattr(events.asyncio, "sleep", sleep)
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "0")
    identity = TeamIdentity(
        team_id="default:example.com", alias="alice", did_key="did:key:alice", did_aw="",
        address="example.com/alice", agent_id=str(uuid4()), identity_scope="local", certificate_id="",
        grant=GrantContext(str(uuid4()), "did:key:session", "cert", ("events.read", "chat.read", "mail.read"), start + timedelta(seconds=600)),
    )

    class Registry:
        calls = None
        fail_at = None
        revoke_at = None

        def __init__(self):
            self.calls = []

        async def get_team_revocations(self, *_):
            self.calls.append(clock.seconds)
            if self.fail_at is not None and clock.seconds >= self.fail_at:
                raise httpx.ConnectError("registry unavailable")
            return {"cert"} if self.revoke_at is not None and clock.seconds >= self.revoke_at else set()

    class DB:
        grant_reads = 0
        revoke_at = None
        inactive_at = None

        def get_manager(self, _):
            return self

        async def fetch_one(self, sql, *args):
            if "identity_session_grants" in sql:
                self.grant_reads += 1
                return dict(team_id=identity.team_id, grant_did_key=identity.grant.session_did_key,
                            issued_at=start, expires_at=identity.grant.expires_at, revoked_at=(start if self.revoke_at is not None and clock.seconds >= self.revoke_at else None),
                            issued_by_certificate_id="cert", agent_id=identity.agent_id, status=("inactive" if self.inactive_at is not None and clock.seconds >= self.inactive_at else "active"), deleted_at=None)
            if "chat_participants" in sql:
                return {"did": identity.did_key}
            return {"did_key": identity.did_key, "did_aw": ""}

        async def fetch_all(self, sql, *args):
            if "SELECT p.did, p.alias, p.address" in sql:
                return [dict(did=identity.did_key, alias="alice", address=identity.address)]
            return []

    class Redis:
        closed = False

        def pubsub(self):
            return self

        async def subscribe(self, *_):
            pass

        async def unsubscribe(self, *_):
            pass

        async def aclose(self):
            self.closed = True

        async def ping(self):
            pass

        async def get_message(self, **_):
            clock.seconds += 1
            return {"type": "message", "data": '{"type":"chat.message"}'}

    registry, db, redis = Registry(), DB(), Redis()

    async def disconnected():
        return False

    request = SimpleNamespace(headers={}, app=SimpleNamespace(state=SimpleNamespace(awid_registry_client=registry)), is_disconnected=disconnected)

    async def open_stream(kind, expiry=600, duration=900):
        auth = replace(identity, grant=replace(identity.grant, expires_at=(start.replace(year=start.year+100) if expiry is None else start + timedelta(seconds=expiry)), never_expires=expiry is None))
        deadline = (start + timedelta(seconds=duration)).isoformat()
        if kind == "event":
            return await events.event_stream(request, deadline=deadline, db=db, redis=None, identity=auth)
        if kind == "chat":
            return await chat.stream(request, session_id=str(uuid4()), deadline=deadline, after=None, db=db, redis=None, auth=auth)
        return await status.status_stream(request, workspace_id=str(uuid4()), repo=None, human_name=None,
                                          limit=200, event_types=None, redis=redis, db_infra=db, identity=auth)

    return SimpleNamespace(clock=clock, registry=registry, db=db, redis=redis, open=open_stream)


async def collect(response):
    return "".join([str(part) async for part in response.body_iterator])


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["event", "status"])
async def test_notification_stream_has_no_grant_reads_after_open(harness, kind):
    response = await harness.open(kind)
    assert harness.registry.calls == [0]
    harness.registry.fail_at = 1
    body = await collect(response)
    assert harness.registry.calls == [0]
    assert harness.db.grant_reads == 1
    assert harness.clock.seconds == 300
    assert "verification_unavailable" not in body
    if kind == "status":
        assert harness.redis.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["event", "status", "chat"])
async def test_pre_stream_registry_failure_is_503(harness, kind):
    harness.registry.fail_at = 0
    with pytest.raises(HTTPException) as exc:
        await harness.open(kind)
    assert exc.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["event", "status", "chat"])
async def test_revoked_issuer_cannot_open_stream(harness, kind):
    harness.registry.revoke_at = 0
    with pytest.raises(HTTPException) as exc:
        await harness.open(kind)
    assert exc.value.status_code == 403
    assert exc.value.detail == "identity grant issuer revoked"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["event", "status", "chat"])
async def test_grant_expiry_ends_stream_without_registry_read(harness, kind):
    response = await harness.open(kind, expiry=5)
    body = await collect(response)
    assert "event: grant_expired" in body
    assert harness.registry.calls == [0]
    assert harness.clock.seconds == 5


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["event", "status", "chat"])
async def test_normal_deadline_does_not_report_expiry(harness, kind):
    response = await harness.open(kind, duration=5)
    body = await collect(response)
    assert "grant_expired" not in body


@pytest.mark.asyncio
async def test_chat_grant_reads_only_every_30_seconds(harness):
    body = await collect(await harness.open("chat", duration=95))
    assert harness.registry.calls == [0, 30, 60, 90]
    assert harness.db.grant_reads == 4
    assert "grant_expired" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,terminal", [("fail_at", "verification_unavailable"), ("revoke_at", "grant_issuer_revoked")])
async def test_chat_recheck_failure_ends_cleanly(harness, failure, terminal, caplog):
    response = await harness.open("chat")
    setattr(harness.registry, failure, 1)
    body = await collect(response)
    assert f"event: {terminal}" in body
    assert harness.registry.calls == [0, 30]
    assert harness.clock.seconds == 30
    if failure == "fail_at":
        assert "registry unavailable" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("registry_fails", [False, True])
async def test_chat_checks_again_after_slow_message_fetch_before_emitting_body(harness, registry_fails):
    original_fetch = harness.db.fetch_all
    delivered = False

    async def fetch_all(sql, *args):
        nonlocal delivered
        if "FROM {{tables.chat_messages}}" in sql and not delivered:
            delivered = True
            harness.clock.seconds = 31
            return [dict(
                message_id=uuid4(), from_alias="bob", from_address="example.com/bob",
                from_did="", body="private content", content_mode="legacy_plaintext_v1",
                message_version=1, encrypted_envelope=None, created_at=chat.datetime.now(timezone.utc),
                sender_leaving=False, hang_on=False, reply_to=None, signature=None, signed_payload=None,
            )]
        return await original_fetch(sql, *args)

    harness.db.fetch_all = fetch_all
    response = await harness.open("chat", duration=40)
    if registry_fails:
        harness.registry.fail_at = 1
    body = await collect(response)
    assert harness.registry.calls == [0, 31]
    if registry_fails:
        assert "private content" not in body
        assert "event: verification_unavailable" in body
    else:
        assert "private content" in body
        assert "verification_unavailable" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["event", "status", "chat"])
@pytest.mark.parametrize("cause,terminal", [("revoke", "grant_revoked"), ("inactive", "grant_subject_inactive"), ("issuer", "grant_issuer_revoked"), ("unavailable", "verification_unavailable")])
async def test_never_grant_open_stream_rechecks_and_closes(harness, kind, cause, terminal):
    response = await harness.open(kind, expiry=None)
    if cause == "revoke": harness.db.revoke_at = 1
    elif cause == "inactive": harness.db.inactive_at = 1
    elif cause == "issuer": harness.registry.revoke_at = 1
    else: harness.registry.fail_at = 1
    body = await collect(response)
    assert "event: " + terminal in body
    assert harness.clock.seconds <= 31
    assert harness.db.grant_reads >= 2

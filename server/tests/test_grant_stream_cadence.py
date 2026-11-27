"""Stream cadence with actual grant authority and simulated clock/frame/Redis boundaries."""

import asyncio
import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException, Request

from aweb import grant_streams
from aweb.routes import chat, events, status
from aweb.team_auth_deps import team_identity_with_grant_scope
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import _signed_team_headers

__all__ = ["privacy_app"]


async def authenticated_grant_member(env):
    """Capture the real verifier result after signed registration, connect and mint."""
    actor = env.actors["alice"]
    sdk = env.app.state.awid_registry_client
    certificate = json.loads(base64.b64decode(actor.certificate))
    name, domain = TEAM.split(":", 1)
    await sdk.register_team_certificate(
        domain,
        name,
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate["certificate_id"],
        member_did_key=actor.did,
        member_did_aw=None,
        member_address=None,
        alias="alice",
        identity_scope="local",
        certificate=actor.certificate,
    )
    body = b"{}"
    connected = await env.client.post(
        "/v1/connect",
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
            "Content-Type": "application/json",
        },
    )
    assert connected.status_code == 200, connected.text
    key, did = _session_keypair()
    body = json.dumps(
        {
            "grant_did_key": did,
            "scopes": ["events.read", "chat.read", "mail.read"],
            "ttl_seconds": 600,
        }
    ).encode()
    minted = await env.client.post(
        "/v1/identity-grants",
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
            "Content-Type": "application/json",
        },
    )
    assert minted.status_code == 200, minted.text
    headers = _grant_headers(
        signing_key=key,
        did_key=did,
        grant_id=minted.json()["grant_id"],
        method="GET",
        path="/v1/events/stream",
        aud=env.app.state.public_origin,
    )

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(
        {
            "type": "http",
            "app": env.app,
            "method": "GET",
            "path": "/v1/events/stream",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        },
        receive=receive,
    )
    identity = await team_identity_with_grant_scope("events.read")(request, env.infra)
    assert identity.did_key == actor.did
    assert identity.grant.grant_id == minted.json()["grant_id"]
    assert identity.grant.issuing_certificate_id == certificate["certificate_id"]
    return identity, certificate


@pytest_asyncio.fixture
async def harness(privacy_app, monkeypatch):
    env = privacy_app
    identity, certificate = await authenticated_grant_member(env)

    start = datetime.now(timezone.utc)
    clock = SimpleNamespace(seconds=0.0)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return start + timedelta(seconds=clock.seconds)

    controls = SimpleNamespace(calls=[], fail_at=None, revoke_at=None, revoked=False)
    sdk = env.app.state.awid_registry_client
    read_revocations = type(sdk).get_team_revocations_for_certificates

    async def observed_revocations(
        client, domain, name, certificate_ids, *, fresh=False
    ):
        if client is not sdk:
            return await read_revocations(
                client, domain, name, certificate_ids, fresh=fresh
            )
        controls.calls.append(clock.seconds)
        if controls.fail_at is not None and clock.seconds >= controls.fail_at:
            raise httpx.ConnectError("registry unavailable")
        if (
            controls.revoke_at is not None
            and clock.seconds >= controls.revoke_at
            and not controls.revoked
        ):
            await sdk.revoke_team_certificate(
                domain,
                name,
                team_controller_signing_key=env.team_sk,
                certificate_id=certificate["certificate_id"],
            )
            controls.revoked = True
        return await read_revocations(
            client, domain, name, certificate_ids, fresh=fresh
        )

    class DB:
        grant_reads = 0
        # The chat session's counter; a stream delivers the numbers above the
        # value it read when it opened.
        last_seq = 0

        def get_manager(self, _):
            return self

        async def fetch_one(self, sql, *args):
            if "chat_participants" in sql:
                return {"did": identity.did_key}
            return {"did_key": identity.did_key, "did_aw": ""}

        async def fetch_all(self, sql, *args):
            if "SELECT p.did, p.alias, p.address" in sql:
                return [
                    dict(did=identity.did_key, alias="alice", address=identity.address)
                ]
            return []

        async def fetch_value(self, sql, *args):
            assert "SELECT last_seq FROM {{tables.chat_sessions}}" in sql
            return self.last_seq

        async def fetch_val(self, sql, *args):
            # No room activity adds authority reads to these existing streams.
            assert "SELECT EXISTS" in sql and "{{tables.room_post_notices}}" in sql
            return False

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

    db, redis = DB(), Redis()

    def grant_database(scope):
        # Grant validity reads its actual migrated database. The simulated
        # chat/event readers above only move the stream clock and frames.
        assert scope is db
        db.grant_reads += 1
        return env.db

    async def disconnected():
        return False

    request = SimpleNamespace(
        headers={},
        state=SimpleNamespace(),
        app=env.app,
        is_disconnected=disconnected,
    )

    async def open_stream(kind, expiry=600, duration=900):
        auth = replace(
            identity,
            grant=replace(identity.grant, expires_at=start + timedelta(seconds=expiry)),
        )
        deadline = (start + timedelta(seconds=duration)).isoformat()
        if kind == "event":
            return await events.event_stream(
                request, deadline=deadline, db=db, redis=None, identity=auth
            )
        if kind == "chat":
            return await chat.stream(
                request,
                session_id=str(uuid4()),
                deadline=deadline,
                after=None,
                after_seq=None,
                db=db,
                redis=None,
                auth=auth,
            )
        return await status.status_stream(
            request,
            workspace_id=str(uuid4()),
            repo=None,
            human_name=None,
            limit=200,
            event_types=None,
            redis=redis,
            db_infra=db,
            identity=auth,
        )

    # Restore the event loop's real sleep before the serving fixture closes.
    real_sleep = asyncio.sleep

    async def advancing_sleep(seconds):
        clock.seconds += seconds
        await real_sleep(0)

    class StreamLoop:
        sleep = staticmethod(advancing_sleep)

        def __getattr__(self, name):
            return getattr(asyncio, name)

    with monkeypatch.context() as scoped:
        for module in (chat, events, status, grant_streams):
            scoped.setattr(module, "datetime", Clock)
        scoped.setattr(chat, "time", SimpleNamespace(monotonic=lambda: clock.seconds))
        for module in (chat, events):
            scoped.setattr(module, "asyncio", StreamLoop())
        scoped.setattr(
            type(sdk), "get_team_revocations_for_certificates", observed_revocations
        )
        scoped.setattr(grant_streams, "native_database_manager", grant_database)
        yield SimpleNamespace(
            clock=clock, registry=controls, db=db, redis=redis, open=open_stream
        )


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
    assert harness.clock.seconds == pytest.approx(300)
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
    assert (
        exc.value.detail
        == "identity grant issuer revoked. This grant was issued from a certificate that is no longer current. Ask the issuer for a new grant, or enable renewal on launch and restart the seat if you use OATS."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["event", "status", "chat"])
async def test_grant_expiry_ends_stream_without_registry_read(harness, kind):
    response = await harness.open(kind, expiry=5)
    body = await collect(response)
    assert "event: grant_expired" in body
    assert harness.registry.calls == [0]
    assert harness.clock.seconds == pytest.approx(5)


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
@pytest.mark.parametrize(
    "failure,terminal",
    [("fail_at", "verification_unavailable"), ("revoke_at", "grant_issuer_revoked")],
)
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
async def test_chat_checks_again_after_slow_message_fetch_before_emitting_body(
    harness, registry_fails
):
    original_fetch = harness.db.fetch_all
    delivered = False

    async def fetch_all(sql, *args):
        nonlocal delivered
        if "FROM {{tables.chat_messages}}" in sql and not delivered:
            delivered = True
            harness.clock.seconds = 31
            return [
                dict(
                    message_id=uuid4(),
                    seq=1,
                    from_alias="bob",
                    from_address="example.com/bob",
                    from_did="",
                    body="private content",
                    content_mode="legacy_plaintext_v1",
                    message_version=1,
                    encrypted_envelope=None,
                    created_at=chat.datetime.now(timezone.utc),
                    sender_leaving=False,
                    hang_on=False,
                    reply_to=None,
                    signature=None,
                    signed_payload=None,
                )
            ]
        return await original_fetch(sql, *args)

    harness.db.fetch_all = fetch_all
    response = await harness.open("chat", duration=40)
    harness.db.last_seq = 1
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

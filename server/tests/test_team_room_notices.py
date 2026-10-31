"""Room-only notice receipts through production auth, SSE and real databases."""

from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from test_team_room import privacy_app, TEAM, headers, metadata, post, post_payload


async def pending(env, actor="bob"):
    response = await env.client.get(
        "/v1/room/notices", headers=headers(env.actors[actor])
    )
    assert response.status_code == 200, response.text
    return response.json()


async def snapshot(env, actor="bob", extra_headers=None):
    deadline = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    request = env.client.build_request(
        "GET",
        "/v1/events/stream",
        params={"deadline": deadline},
    )
    request.headers.update(
        extra_headers(request.url.raw_path.decode())
        if extra_headers
        else headers(env.actors[actor])
    )
    response = await env.client.send(request)
    assert response.status_code == 200, response.text
    return [
        json.loads(line[6:])
        for line in response.text.splitlines()
        if line.startswith("data: ")
        and json.loads(line[6:]).get("type") == "actionable_room_post"
    ]


@pytest.mark.asyncio
async def test_room_notices_commit_once_and_ack_only_the_recipient(privacy_app):
    env = privacy_app
    room = await metadata(env)
    payload = post_payload(env, room)
    sent = await post(env, room, payload=payload)
    assert sent.status_code == 200, sent.text
    message_id = sent.json()["message_id"]
    assert (await pending(env, "alice"))["pending_count"] == 0
    assert (await pending(env, "bob"))["pending_count"] == 1
    assert (await pending(env, "carol"))["pending_count"] == 1
    assert (await post(env, room, payload=payload)).json() == sent.json()
    assert (
        await env.db.fetch_val("SELECT count(*) FROM {{tables.room_post_notices}}") == 2
    )
    notices = await snapshot(env)
    assert len(notices) == 1
    assert notices[0]["message_id"] == message_id
    assert notices[0]["room_id"] == room["room_id"]
    assert notices[0]["from_alias"] == "alice"
    assert notices[0]["subject"] == "Update"
    assert "body" not in notices[0]
    # Snapshot/exact verification do not acknowledge before accepted presentation.
    await env.client.get(
        "/v1/room/messages/" + message_id, headers=headers(env.actors["bob"])
    )
    assert len(await snapshot(env)) == 1
    path = "/v1/room/notices/" + message_id + "/ack"
    for _ in range(2):
        result = await env.client.post(
            path, content=b"{}", headers=headers(env.actors["bob"], b"{}")
        )
        assert result.status_code == 200, result.text
    assert await snapshot(env) == []
    assert (await pending(env, "carol"))["pending_count"] == 1
    assert (await post(env, room, payload=payload)).status_code == 200
    assert (await pending(env, "bob"))["pending_count"] == 0
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.messages}}") == 0
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0


@pytest.mark.asyncio
async def test_room_history_clears_only_returned_posts_and_soft_removal_cleans_notices(
    privacy_app,
):
    env = privacy_app
    room = await metadata(env)
    first = await post(env, room)
    await post(env, room, text="second")
    assert (await pending(env))["pending_count"] == 2
    page = await env.client.get(
        "/v1/room/messages?limit=1", headers=headers(env.actors["bob"])
    )
    assert page.status_code == 200
    assert page.json()["messages"][0]["message_id"] == first.json()["message_id"]
    assert (await pending(env))["pending_count"] == 1
    assert (await pending(env, "carol"))["pending_count"] == 2
    await env.db.execute(
        "UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1",
        env.actors["carol"].id,
    )
    assert (
        await env.db.fetch_val(
            "SELECT count(*) FROM {{tables.room_post_notices}} WHERE recipient_agent_id=$1",
            env.actors["carol"].id,
        )
        == 0
    )
    assert await snapshot(env, "carol") == []
    refused = await env.client.get(
        "/v1/room/notices", headers=headers(env.actors["carol"])
    )
    assert refused.status_code == 403
    await env.db.execute(
        "UPDATE {{tables.agents}} SET status='active' WHERE agent_id=$1",
        env.actors["carol"].id,
    )
    assert (await pending(env, "carol"))["pending_count"] == 0


@pytest.mark.asyncio
async def test_room_notice_snapshot_uses_current_certificate_and_chat_scope(
    privacy_app,
):
    from nacl.signing import SigningKey
    from awid.did import did_from_public_key
    from test_identity_grants import _grant_headers

    env = privacy_app
    room = await metadata(env)
    await post(env, room)
    key = SigningKey.generate()
    grant = uuid4()
    await env.db.execute(
        """INSERT INTO {{tables.identity_session_grants}}
    (grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_at,expires_at)
    VALUES ($1,$2,$3,$4,$5,now(),now()+interval '10 minutes')""",
        grant,
        TEAM,
        env.actors["bob"].id,
        did_from_public_key(bytes(key.verify_key)),
        ["events.read", "mail.read"],
    )

    def signed(path):
        return _grant_headers(
            signing_key=bytes(key),
            did_key=did_from_public_key(bytes(key.verify_key)),
            grant_id=str(grant),
            method="GET",
            path=path,
            aud=env.app.state.public_origin,
        )

    assert await snapshot(env, extra_headers=signed) == []
    await env.db.execute(
        "UPDATE {{tables.identity_session_grants}} SET scopes=ARRAY['events.read','chat.read'] WHERE grant_id=$1",
        grant,
    )
    assert len(await snapshot(env, extra_headers=signed)) == 1
    await env.registry_db.execute(
        """INSERT INTO {{tables.team_certificates}}
    (team_uuid,certificate_id,member_did_key,alias,revoked_at)
    SELECT team_uuid,'privacy-bob',$2,'bob',now() FROM {{tables.teams}} WHERE name=$1""",
        TEAM.split(":")[0],
        env.actors["bob"].did,
    )
    # The stream already passed its opening auth in this generator-level case;
    # room-specific snapshot admission must still recheck production revocation.
    from aweb.messaging.room_notices import current_room_events
    from aweb.team_auth_deps import TeamIdentity
    from starlette.requests import Request

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/events/stream",
            "headers": [
                (k.lower().encode(), v.encode())
                for k, v in headers(env.actors["bob"]).items()
            ],
            "app": env.app,
        }
    )
    identity = TeamIdentity(
        team_id=TEAM,
        alias="bob",
        did_key=env.actors["bob"].did,
        did_aw="",
        address="",
        identity_scope="local",
        agent_id=str(env.actors["bob"].id),
        certificate_id="privacy-bob",
    )
    assert await current_room_events(request, env.infra, identity) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "grant_actor, authority",
    [
        (False, "current"),
        (True, "current"),
        (False, "revoked"),
        (True, "revoked"),
        (False, "unavailable"),
        (True, "unavailable"),
        (True, "scope_removed"),
        (True, "grant_revoked"),
    ],
)
async def test_live_room_stream_refreshes_authority_without_replaying_opening_timestamp(
    privacy_app,
    monkeypatch,
    grant_actor,
    authority,
):
    """A -120s opening proof stays admitted at +181s of a 300s stream."""
    import hashlib
    from types import SimpleNamespace
    from nacl.signing import SigningKey
    from awid.did import did_from_public_key
    from awid.signing import canonical_json_bytes, sign_message
    from awid.registry import RegistryClient
    import awid.dns_auth as dns_auth
    import aweb.routes.events as events_routes
    import aweb.grant_streams as grant_streams
    from test_identity_grants import _grant_headers
    from tests.real_stack import ServiceTransport

    env = privacy_app
    room = await metadata(env)
    clock = SimpleNamespace(now=datetime.now(timezone.utc), polls=0)
    start = clock.now
    timestamp = (start - timedelta(seconds=120)).isoformat()
    request = env.client.build_request(
        "GET",
        "/v1/events/stream",
        params={"deadline": (start + timedelta(seconds=300)).isoformat()},
    )
    if grant_actor:
        key = SigningKey.generate()
        grant_id = uuid4()
        await env.db.execute(
            """INSERT INTO {{tables.identity_session_grants}}
            (grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_at,
             expires_at,issued_by_certificate_id)
            VALUES ($1,$2,$3,$4,$5,now(),now()+interval '10 minutes','privacy-bob')""",
            grant_id,
            TEAM,
            env.actors["bob"].id,
            did_from_public_key(bytes(key.verify_key)),
            ["events.read", "chat.read"],
        )
        signed_headers = _grant_headers(
            signing_key=bytes(key),
            did_key=did_from_public_key(bytes(key.verify_key)),
            grant_id=str(grant_id),
            method="GET",
            path=request.url.raw_path.decode(),
            aud=env.app.state.public_origin,
            payload_overrides={"timestamp": timestamp},
        )
        signed_headers["X-AWEB-Timestamp"] = timestamp
    else:
        bob = env.actors["bob"]
        signed = canonical_json_bytes(
            {
                "team_id": TEAM,
                "timestamp": timestamp,
                "body_sha256": hashlib.sha256(b"").hexdigest(),
            }
        )
        signed_headers = {
            "Authorization": f"DIDKey {bob.did} {sign_message(bob.sk, signed)}",
            "X-AWEB-Timestamp": timestamp,
            "X-AWID-Team-Certificate": bob.certificate,
        }
    request.headers.update(signed_headers)

    class StreamClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock.now

    previous_registry = env.app.state.awid_registry_client
    unavailable = None

    async def advance_poll(seconds):
        nonlocal unavailable
        clock.polls += 1
        if clock.polls == 1:
            clock.now = start + timedelta(seconds=181)
            sent = await post(env, room)
            assert sent.status_code == 200, sent.text
            if authority == "revoked":
                await env.registry_db.execute(
                    """INSERT INTO {{tables.team_certificates}}
                    (team_uuid,certificate_id,member_did_key,alias,revoked_at)
                    SELECT team_uuid,'privacy-bob',$2,'bob',now()
                    FROM {{tables.teams}} WHERE name=$1""",
                    TEAM.split(":")[0],
                    env.actors["bob"].did,
                )
            elif authority == "scope_removed":
                await env.db.execute(
                    "UPDATE {{tables.identity_session_grants}} SET scopes=ARRAY['events.read'] WHERE grant_id=$1",
                    grant_id,
                )
            elif authority == "grant_revoked":
                await env.db.execute(
                    "UPDATE {{tables.identity_session_grants}} SET revoked_at=now() WHERE grant_id=$1",
                    grant_id,
                )
            elif authority == "unavailable":
                transport = ServiceTransport(env.registry_app)
                transport.down = True
                unavailable = RegistryClient(
                    registry_url="http://registry.test", transport=transport
                )
                env.app.state.awid_registry_client = unavailable
        else:
            clock.now = start + timedelta(seconds=301)

    monkeypatch.setattr(dns_auth, "datetime", StreamClock)
    monkeypatch.setattr(events_routes, "datetime", StreamClock)
    monkeypatch.setattr(grant_streams, "datetime", StreamClock)
    monkeypatch.setattr(events_routes, "asyncio", SimpleNamespace(sleep=advance_poll))
    try:
        response = await env.client.send(request)
        assert response.status_code == 200, response.text
        assert "event: connected" in response.text
        notices = [
            json.loads(line[6:])
            for line in response.text.splitlines()
            if line.startswith("data: ")
            and json.loads(line[6:]).get("type") == "actionable_room_post"
        ]
        assert len(notices) == (1 if authority == "current" else 0), response.text
        if notices:
            assert notices[0]["agent_id"] == str(env.actors["bob"].id)
            assert notices[0]["room_id"] == room["room_id"]
        assert (
            await env.db.fetch_val("SELECT count(*) FROM {{tables.room_post_notices}}")
        ) == 2
    finally:
        env.app.state.awid_registry_client = previous_registry
        if unavailable:
            await unavailable.aclose()

"""Read-only counts through admitted HTTP/MCP actors and the real notice store."""

from dataclasses import replace
from uuid import UUID, uuid4
import asyncio

import pytest
from fastapi import Depends
from starlette.requests import Request
from starlette.responses import JSONResponse
from awid.did import did_from_public_key
from nacl.signing import SigningKey
from aweb.auth_context import GRANT_SCOPE_ANY
from aweb.mcp.auth import MCPAuthMiddleware
from aweb.team_auth_deps import team_identity_with_grant_scope
from test_team_room import privacy_app, TEAM, headers, metadata, post
from test_identity_grants import _grant_headers


async def admitted(env, name="bob"):
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/count-probe",
            "query_string": b"",
            "app": env.app,
            "headers": [
                (k.lower().encode(), v.encode())
                for k, v in headers(env.actors[name]).items()
            ],
        }
    )
    return await team_identity_with_grant_scope(GRANT_SCOPE_ANY)(request, env.infra)


@pytest.mark.asyncio
async def test_count_is_read_only_non_consuming_and_does_not_lock_the_member(
    privacy_app,
):
    from aweb.messaging.room_notices import count_room_notices, pending_room_notices

    env = privacy_app
    room = await metadata(env)
    await post(env, room)
    await post(env, room, text="second")
    bob, alice = await admitted(env), await admitted(env, "alice")
    before = await env.db.fetch_all(
        "SELECT * FROM {{tables.room_post_notices}} ORDER BY message_id,recipient_agent_id"
    )
    assert await count_room_notices(env.infra, alice) == 0
    assert (
        await count_room_notices(
            env.infra, replace(bob, team_id="foreign:example.test")
        )
        == 0
    )
    assert await count_room_notices(env.infra, replace(bob, did_key=alice.did_key)) == 0
    async with env.db.transaction() as tx:
        await tx.fetch_one(
            "SELECT agent_id FROM {{tables.agents}} WHERE agent_id=$1 FOR UPDATE",
            env.actors["bob"].id,
        )
        # A SELECT-only count completes while another connection owns the row
        # lock; a hidden FOR SHARE path would block until the transaction ends.
        assert await asyncio.wait_for(count_room_notices(env.infra, bob), 3) == 2
    page = await pending_room_notices(env.infra, bob, limit=1)
    assert page["pending_count"] == 2 and len(page["notices"]) == 1 and page["has_more"]
    assert (
        await env.db.fetch_all(
            "SELECT * FROM {{tables.room_post_notices}} ORDER BY message_id,recipient_agent_id"
        )
        == before
    )
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.messages}}") == 0
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "none",
        "mail_only",
        "no_scope",
        "revoked",
        "expired",
        "wrong_subject",
        "wrong_team",
    ],
)
async def test_admitted_grant_count_checks_current_subject_team_and_chat_scope(
    privacy_app, change
):
    from aweb.messaging.room_notices import count_room_notices

    env = privacy_app
    room = await metadata(env)
    await post(env, room)
    key, grant_id = SigningKey.generate(), uuid4()
    await env.db.execute(
        """INSERT INTO {{tables.identity_session_grants}}
        (grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,now(),now()+interval '10 minutes')""",
        grant_id,
        TEAM,
        env.actors["bob"].id,
        did_from_public_key(bytes(key.verify_key)),
        ["mail.read"] if change == "mail_only" else ["chat.read", "mail.read"],
    )

    async def count(identity=Depends(team_identity_with_grant_scope(GRANT_SCOPE_ANY))):
        # Change after real admission, so stale in-memory scope/subject facts
        # cannot satisfy the current grant rule in the count query.
        if change == "no_scope":
            await env.db.execute(
                "UPDATE {{tables.identity_session_grants}} SET scopes=ARRAY['mail.read'] WHERE grant_id=$1",
                grant_id,
            )
        elif change == "revoked":
            await env.db.execute(
                "UPDATE {{tables.identity_session_grants}} SET revoked_at=now() WHERE grant_id=$1",
                grant_id,
            )
        elif change == "expired":
            await env.db.execute(
                "UPDATE {{tables.identity_session_grants}} SET issued_at=now()-interval '1 hour',expires_at=now()-interval '1 second' WHERE grant_id=$1",
                grant_id,
            )
        elif change == "wrong_subject":
            await env.db.execute(
                "UPDATE {{tables.identity_session_grants}} SET subject_agent_id=$2 WHERE grant_id=$1",
                grant_id,
                env.actors["carol"].id,
            )
        elif change == "wrong_team":
            await env.db.execute(
                "UPDATE {{tables.identity_session_grants}} SET team_id='foreign:example.test' WHERE grant_id=$1",
                grant_id,
            )
        return {"count": await count_room_notices(env.infra, identity)}

    env.app.get("/count-probe")(count)
    response = await env.client.get(
        "/count-probe",
        headers=_grant_headers(
            signing_key=bytes(key),
            did_key=did_from_public_key(bytes(key.verify_key)),
            grant_id=str(grant_id),
            method="GET",
            path="/count-probe",
            aud=env.app.state.public_origin,
        ),
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"count": 1 if change == "none" else 0}
    assert (
        await env.db.fetch_val("SELECT count(*) FROM {{tables.room_post_notices}}") == 2
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("proxy", [False, True], ids=["certificate", "proxy"])
@pytest.mark.parametrize(
    "condition", ["positive", "zero", "revoked", "unavailable", "removed"]
)
async def test_mcp_count_uses_current_admitted_actor_and_omits_failed_authority(
    privacy_app, monkeypatch, proxy, condition, caplog
):
    from aweb.mcp.tools.room import room_notice_count
    from aweb.internal_auth import build_internal_auth_header_value
    from awid.registry import RegistryClient
    from tests.real_stack import ServiceTransport

    env = privacy_app
    room = await metadata(env)
    sent = await post(env, room)
    actor = env.actors["alice" if condition == "zero" else "bob"]
    await admitted(env, "alice" if condition == "zero" else "bob")
    previous = env.app.state.awid_registry_client
    unavailable = None

    class Probe:
        async def __call__(self, scope, receive, send):
            nonlocal unavailable
            # The mutation/outage begins AFTER ordinary MCP admission.
            if condition == "revoked":
                await env.registry_db.execute(
                    """INSERT INTO {{tables.team_certificates}}
                    (team_uuid,certificate_id,member_did_key,alias,revoked_at)
                    SELECT team_uuid,'privacy-bob',$2,'bob',now() FROM {{tables.teams}} WHERE name=$1""",
                    TEAM.split(":")[0],
                    actor.did,
                )
            elif condition == "unavailable":
                transport = ServiceTransport(env.registry_app)
                transport.down = True
                unavailable = RegistryClient(
                    registry_url="http://registry.test", transport=transport
                )
                scope["app"].state.awid_registry_client = unavailable
            elif condition == "removed":
                await env.db.execute(
                    "UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1",
                    actor.id,
                )
                # Restore a stale notice after cleanup to prove authorization
                # does not use the cleanup trigger as a membership authority.
                await env.db.execute(
                    "INSERT INTO {{tables.room_post_notices}} (message_id,recipient_agent_id) VALUES ($1,$2)",
                    UUID(sent.json()["message_id"]),
                    actor.id,
                )
            result = await room_notice_count(env.infra)
            await JSONResponse({"room_count": result})(scope, receive, send)

    env.app.mount("/mcp-count", MCPAuthMiddleware(Probe(), env.infra))
    auth = headers(actor)
    if proxy:
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        principal = str(uuid4())
        auth = {
            "X-AWEB-Auth": build_internal_auth_header_value(
                secret="test-internal-auth-secret",
                team_id=TEAM,
                principal_type="k",
                principal_id=principal,
                actor_id=str(actor.id),
            ),
            "X-Team-ID": TEAM,
            "X-API-Key": principal,
            "X-AWEB-Actor-ID": str(actor.id),
        }
    try:
        response = await env.client.get("/mcp-count/", headers=auth)
        assert response.status_code == 200, response.text
        assert response.json() == {
            "room_count": (
                None
                if condition in ("revoked", "unavailable", "removed")
                else (0 if condition == "zero" else 1)
            )
        }
        assert await env.db.fetch_val(
            "SELECT count(*) FROM {{tables.room_post_notices}} WHERE recipient_agent_id=$1",
            actor.id,
        ) == (0 if condition == "zero" else 1)
        if condition in ("revoked", "unavailable", "removed"):
            assert "Room notice count unavailable" in caplog.text
    finally:
        env.app.state.awid_registry_client = previous
        if unavailable:
            await unavailable.aclose()

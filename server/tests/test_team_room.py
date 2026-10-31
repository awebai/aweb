"""Team rooms through real HTTP, PostgreSQL, Redis and certificate auth."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from types import SimpleNamespace

import pytest
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import privacy_app, TEAM  # noqa: F401
from test_messages_http import (
    _signed_team_headers,
    _make_keypair,
    _make_certificate,
    _encode_certificate,
)


def headers(actor, body=b""):
    return {
        **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
        "Content-Type": "application/json",
    }


async def metadata(env, actor="alice"):
    response = await env.client.get("/v1/room", headers=headers(env.actors[actor]))
    assert response.status_code == 200, response.text
    return response.json()


def post_payload(env, room, *, actor="alice", text="Team announcement", **changes):
    sender = env.actors[actor]
    payload = dict(
        type="chat",
        conversation_id=room["room_id"],
        message_id=str(uuid4()),
        from_did=sender.did,
        to="team-room:" + TEAM,
        to_did="",
        subject="Update",
        body=text,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    payload["from"] = actor
    payload.update(changes)
    canonical = canonical_json_bytes(payload).decode()
    return dict(
        room_id=room["room_id"],
        signed_payload=canonical,
        signature=sign_message(sender.sk, canonical.encode()),
        signing_key_id=sender.did,
    )


async def post(env, room, *, actor="alice", payload=None, **changes):
    payload = payload or post_payload(env, room, actor=actor, **changes)
    body = json.dumps(payload).encode()
    return await env.client.post(
        "/v1/room/messages", content=body, headers=headers(env.actors[actor], body)
    )


@pytest.mark.asyncio
async def test_room_is_shared_and_history_includes_posts_before_join(privacy_app):
    env = privacy_app
    room = await metadata(env)
    assert room["team_id"] == TEAM
    assert room["confidentiality"] == "server_readable"
    assert room["history_visibility"] == "current_and_future_members"
    payload = post_payload(env, room)
    sent = await post(env, room, payload=payload)
    assert sent.status_code == 200, sent.text
    item = sent.json()
    assert item["signed_payload"] == payload["signed_payload"]
    # A real newly admitted member, created after the post, reads full history.
    sk, _, did = _make_keypair()
    member = uuid4()
    await env.db.execute(
        "INSERT INTO {{tables.agents}} (agent_id,team_id,did_key,alias,identity_scope,inbound_mode) VALUES ($1,$2,$3,'dave','local','open')",
        member,
        TEAM,
        did,
    )
    certificate = _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            did,
            team_id=TEAM,
            alias="dave",
            identity_scope="local",
            certificate_id="room-dave",
        )
    )
    newcomer = SimpleNamespace(sk=sk, did=did, certificate=certificate)
    read = await env.client.get("/v1/room/messages", headers=headers(newcomer))
    assert read.status_code == 200, read.text
    assert [m["message_id"] for m in read.json()["messages"]] == [item["message_id"]]
    assert read.json()["messages"][0]["body"] == "Team announcement"
    exact = await env.client.get(
        "/v1/room/messages/" + item["message_id"], headers=headers(env.actors["bob"])
    )
    assert exact.json() == item
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.messages}}") == 0
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0
    assert env.dispatched == []  # Room notices use no legacy mutation fan-out.


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("to", "team-room:other:example.test"),
        ("conversation_id", str(uuid4())),
        ("from_did", "did:key:wrong"),
        ("from_stable_id", "did:aw:unverified"),
        ("type", "mail"),
        ("to_did", "did:key:some-recipient"),
        (
            "timestamp",
            (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        ),
    ],
)
async def test_room_refuses_wrong_signed_bindings(privacy_app, field, value):
    room = await metadata(privacy_app)
    response = await post(privacy_app, room, **{field: value})
    assert response.status_code == 422, response.text
    assert (
        await privacy_app.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}")
        == 0
    )


@pytest.mark.asyncio
async def test_room_signature_tampering_and_idempotent_replay(privacy_app):
    env = privacy_app
    room = await metadata(env)
    payload = post_payload(env, room)
    bad = dict(
        payload,
        signed_payload=payload["signed_payload"].replace(
            "Team announcement", "Different content"
        ),
    )
    assert (await post(env, room, payload=bad)).status_code == 403
    first = await post(env, room, payload=payload)
    assert first.status_code == 200, first.text
    assert (await post(env, room, payload=payload)).json() == first.json()
    conflict = post_payload(
        env, room, message_id=first.json()["message_id"], text="Another post"
    )
    assert (await post(env, room, payload=conflict)).status_code == 409
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 1


@pytest.mark.asyncio
async def test_room_paging_and_foreign_cursor_refusal(privacy_app):
    env = privacy_app
    room = await metadata(env)
    ids = []
    for i in range(3):
        response = await post(env, room, text=str(i))
        assert response.status_code == 200, response.text
        ids.append(response.json()["message_id"])
    first = await env.client.get(
        "/v1/room/messages?limit=2", headers=headers(env.actors["bob"])
    )
    page = first.json()
    assert [m["message_id"] for m in page["messages"]] == ids[:2]
    assert page["has_more"]
    second = await env.client.get(
        "/v1/room/messages",
        params={"limit": 2, "after": page["next_cursor"]},
        headers=headers(env.actors["bob"]),
    )
    assert [m["message_id"] for m in second.json()["messages"]] == ids[2:]
    assert second.json()["has_more"] is False
    invalid = await env.client.get(
        "/v1/room/messages?after=not-a-cursor", headers=headers(env.actors["bob"])
    )
    assert invalid.status_code == 422


@pytest.mark.asyncio
async def test_room_removed_member_and_e2ee_refuse(privacy_app):
    env = privacy_app
    room = await metadata(env)
    payload = dict(post_payload(env, room), e2ee=True)
    refused = await post(env, room, payload=payload)
    assert refused.status_code == 422
    assert "room_e2ee_unsupported" in refused.text
    await env.db.execute(
        "UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1",
        env.actors["alice"].id,
    )
    assert (
        await env.client.get("/v1/room/messages", headers=headers(env.actors["alice"]))
    ).status_code == 403
    assert (await post(env, room)).status_code == 403
    assert (await env.client.get("/v1/room/messages")).status_code == 401


@pytest.mark.asyncio
async def test_room_keeps_adjacent_id_chain(privacy_app):
    from test_id_chain_message_metadata import _bundle
    from awid.id_certificates import encode_id_chain_header

    env = privacy_app
    room = await metadata(env)
    payload = post_payload(env, room)
    body = json.dumps(payload).encode()
    chain = _bundle(env.actors["alice"].did)
    signed_headers = headers(env.actors["alice"], body)
    signed_headers["X-AWID-ID-Chain"] = encode_id_chain_header(chain)
    result = await env.client.post(
        "/v1/room/messages", content=body, headers=signed_headers
    )
    assert result.status_code == 200, result.text
    assert result.json()["id_chain"] == chain
    assert result.json()["signed_payload"] == payload["signed_payload"]


@pytest.mark.asyncio
async def test_ordinary_chat_refuses_team_room_target(privacy_app):
    env = privacy_app
    room = await metadata(env)
    room_post = post_payload(env, room)
    signed = json.loads(room_post["signed_payload"])
    payload = dict(
        to_aliases=["bob"],
        message=signed["body"],
        session_id=room["room_id"],
        message_id=signed["message_id"],
        timestamp=signed["timestamp"],
        from_did=signed["from_did"],
        signature=room_post["signature"],
        signed_payload=room_post["signed_payload"],
    )
    body = json.dumps(payload).encode()
    result = await env.client.post(
        "/v1/chat/sessions", content=body, headers=headers(env.actors["alice"], body)
    )
    assert result.status_code == 422, result.text
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0
    # Pin the resolver boundary too: the room selector itself must never
    # acquire an ordinary-chat recipient interpretation.
    payload["to_aliases"] = ["team-room:" + TEAM]
    body = json.dumps(payload).encode()
    refused = await env.client.post(
        "/v1/chat/sessions", content=body, headers=headers(env.actors["alice"], body)
    )
    assert refused.status_code in (404, 422), refused.text
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0
    # A correctly signed neighboring recipient chat still works.
    signed.update(to="bob", to_did=env.actors["bob"].did, conversation_id=str(uuid4()))
    canonical = canonical_json_bytes(signed).decode()
    payload.update(
        to_aliases=["bob"],
        session_id=signed["conversation_id"],
        signed_payload=canonical,
        signature=sign_message(env.actors["alice"].sk, canonical.encode()),
    )
    body = json.dumps(payload).encode()
    neighbor = await env.client.post(
        "/v1/chat/sessions", content=body, headers=headers(env.actors["alice"], body)
    )
    assert neighbor.status_code == 200, neighbor.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scopes,read_status,post_status",
    [
        (["chat.read", "chat.send"], 200, 200),
        (["chat.read"], 200, 403),
        (["mail.read", "mail.send"], 403, 403),
    ],
)
async def test_room_grants_use_chat_scope_and_subject(
    privacy_app, scopes, read_status, post_status
):
    from nacl.signing import SigningKey
    from awid.did import did_from_public_key
    from test_identity_grants import _grant_headers

    env = privacy_app
    room = await metadata(env)
    session = SigningKey.generate()
    session_did = did_from_public_key(bytes(session.verify_key))
    grant = uuid4()
    await env.db.execute(
        """INSERT INTO {{tables.identity_session_grants}}
        (grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,now(),now()+interval '10 minutes')""",
        grant,
        TEAM,
        env.actors["alice"].id,
        session_did,
        scopes,
    )

    def grant_headers(method, path, body=b""):
        return _grant_headers(
            signing_key=bytes(session),
            did_key=session_did,
            grant_id=str(grant),
            method=method,
            path=path,
            body=body,
            aud=env.app.state.public_origin,
        )

    result = await env.client.get(
        "/v1/room/messages", headers=grant_headers("GET", "/v1/room/messages")
    )
    assert result.status_code == read_status, result.text
    payload = post_payload(env, room)
    body = json.dumps(payload).encode()
    result = await env.client.post(
        "/v1/room/messages",
        content=body,
        headers=grant_headers("POST", "/v1/room/messages", body),
    )
    assert result.status_code == post_status, result.text
    if post_status == 200:
        assert result.json()["from_did"] == env.actors["alice"].did
        assert result.json()["from_did"] != session_did


@pytest.mark.asyncio
async def test_room_cross_team_ids_and_cursors_do_not_authorize(privacy_app):
    env = privacy_app
    room = await metadata(env)
    first = await post(env, room)
    await post(env, room, text="second")
    page = (
        await env.client.get(
            "/v1/room/messages?limit=1", headers=headers(env.actors["alice"])
        )
    ).json()
    other = "other-" + TEAM
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,'example.test',$2,$3)",
        other,
        other.split(":")[0],
        env.team_did,
    )
    await env.registry_db.execute(
        "INSERT INTO {{tables.teams}} (domain,name,team_did_key,visibility) VALUES ('example.test',$1,$2,'public')",
        other.split(":")[0],
        env.team_did,
    )
    actor = env.actors["alice"]
    await env.db.execute(
        "INSERT INTO {{tables.agents}} (agent_id,team_id,did_key,alias,identity_scope,inbound_mode) VALUES ($1,$2,$3,'alice','local','open')",
        uuid4(),
        other,
        actor.did,
    )
    cert = _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            actor.did,
            team_id=other,
            alias="alice",
            identity_scope="local",
            certificate_id="other-alice",
        )
    )

    def other_headers(body=b""):
        return {
            **_signed_team_headers(actor.sk, actor.did, other, cert, body),
            "Content-Type": "application/json",
        }

    second_room = (await env.client.get("/v1/room", headers=other_headers())).json()
    assert room["room_id"] != second_room["room_id"]
    exact = await env.client.get(
        "/v1/room/messages/" + first.json()["message_id"], headers=other_headers()
    )
    assert exact.status_code == 404
    cursor = await env.client.get(
        "/v1/room/messages",
        params={"after": page["next_cursor"]},
        headers=other_headers(),
    )
    assert cursor.status_code == 422
    bad = post_payload(env, room)
    body = json.dumps(bad).encode()
    assert (
        await env.client.post(
            "/v1/room/messages", content=body, headers=other_headers(body)
        )
    ).status_code == 422
    collision = post_payload(
        env, second_room, to="team-room:" + other, message_id=first.json()["message_id"]
    )
    body = json.dumps(collision).encode()
    assert (
        await env.client.post(
            "/v1/room/messages", content=body, headers=other_headers(body)
        )
    ).status_code == 409


@pytest.mark.asyncio
async def test_room_revoked_certificate_stops_reads_and_posts(privacy_app):
    env = privacy_app
    room = await metadata(env)
    actor = env.actors["alice"]
    await env.registry_db.execute(
        """INSERT INTO {{tables.team_certificates}}
        (team_uuid,certificate_id,member_did_key,alias,revoked_at)
        SELECT team_uuid,'privacy-alice',$2,'alice',now() FROM {{tables.teams}}
        WHERE domain='example.test' AND name=$1""",
        TEAM.split(":")[0],
        actor.did,
    )
    read = await env.client.get("/v1/room/messages", headers=headers(actor))
    assert read.status_code == 401, read.text
    assert (await post(env, room)).status_code == 401
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("global_actor", [False, True])
async def test_hosted_mcp_room_signs_as_actor_and_reads_shared_history(
    privacy_app, monkeypatch, global_actor
):
    from aweb.mcp.server import create_mcp_app
    from aweb.internal_auth import build_internal_auth_header_value
    from aweb.mcp.signing import HostedMessageSigningResult

    env = privacy_app
    actor = env.actors["alice"]
    cert_id = "privacy-alice"
    if global_actor:
        from identity_binding_support import register_global_identity

        stable = await register_global_identity(env, actor, "example.test/alice")
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw=$1,address='example.test/alice',identity_scope='global' WHERE agent_id=$2",
            stable,
            actor.id,
        )
        cert_id = "hosted-alice"
        actor.certificate = _encode_certificate(
            _make_certificate(
                env.team_sk,
                env.team_did,
                actor.did,
                team_id=TEAM,
                alias="alice",
                identity_scope="global",
                member_did_aw=stable,
                member_address="example.test/alice",
                certificate_id=cert_id,
            )
        )
    await metadata(env)
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    principal = str(uuid4())
    internal = build_internal_auth_header_value(
        secret="test-internal-auth-secret",
        team_id=TEAM,
        principal_type="k",
        principal_id=principal,
        actor_id=str(actor.id),
    )
    proxy = {
        "X-AWEB-Auth": internal,
        "X-Team-ID": TEAM,
        "X-API-Key": principal,
        "X-AWEB-Actor-ID": str(actor.id),
    }
    calls = []
    wrong_actor = False

    async def signer(**kwargs):
        calls.append(kwargs)
        assert kwargs["agent_id"] == str(actor.id)
        assert kwargs["message_type"] == "chat"
        canonical = canonical_json_bytes(kwargs["payload"]).decode()
        subject = env.actors["bob"] if wrong_actor else actor
        return HostedMessageSigningResult(
            from_did=subject.did,
            signing_key_id=subject.did,
            signature=sign_message(subject.sk, canonical.encode()),
            signed_payload=canonical,
        )

    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=str(env.client.base_url).rstrip("/"),
        hosted_signer=signer,
    )
    env.app.mount("/room-mcp", mcp)
    await mcp.startup()

    async def call(tool, **arguments):
        response = await env.client.post(
            "/room-mcp/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            },
            headers={**proxy, "Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 200, response.text
        assert "error" not in response.json(), response.text
        return response.json()["result"]

    try:
        before = await call("check_mail")
        initial = await call("room_pending")
        assert json.loads(initial["content"][0]["text"])["pending_count"] == 0
        result = await call("room_post", subject="Hosted", body="MCP announcement")
        assert not result.get("isError"), result
        stored_post = json.loads(result["content"][0]["text"])
        assert stored_post["from_did"] == actor.did
        assert stored_post["body"] == "MCP announcement"
        assert stored_post["confidentiality"] == "server_readable"
        assert len(calls) == 1
        room = await metadata(env)
        assert (
            await post(env, room, actor="bob", text="Another team update")
        ).status_code == 200
        pending = await call("room_pending")
        assert json.loads(pending["content"][0]["text"])["pending_count"] == 1
        read = await call("room_read")
        assert not read.get("isError"), read
        assert (
            json.loads(read["content"][0]["text"])["messages"][0]["message_id"]
            == stored_post["message_id"]
        )
        assert await call("check_mail") == before
        pending = await call("room_pending")
        assert json.loads(pending["content"][0]["text"])["pending_count"] == 0
        refused = await call("room_post", body="no downgrade", e2ee=True)
        assert (
            refused.get("isError")
            and "room_e2ee_unsupported" in refused["content"][0]["text"]
        )
        assert len(calls) == 1
        wrong_actor = True
        refused = await call("room_post", body="wrong signer")
        assert refused.get("isError"), refused
        assert (
            await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 2
        )
        await env.registry_db.execute(
            """INSERT INTO {{tables.team_certificates}}
            (team_uuid,certificate_id,member_did_key,alias,revoked_at)
            SELECT team_uuid,$2,$3,'alice',now() FROM {{tables.teams}}
            WHERE domain='example.test' AND name=$1""",
            TEAM.split(":")[0],
            cert_id,
            actor.did,
        )
        assert (await call("room_read")).get("isError")
        assert (await call("room_post", body="revoked")).get("isError")
    finally:
        await mcp.shutdown()
    read = await env.client.get("/v1/room/messages", headers=headers(env.actors["bob"]))
    assert read.json()["messages"][0]["message_id"] == stored_post["message_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["", "example.test/alice"])
async def test_global_member_room_uses_real_awid_binding(privacy_app, address):
    from identity_binding_support import register_global_identity

    env = privacy_app
    actor = env.actors["alice"]
    stable = await register_global_identity(env, actor, address)
    await env.db.execute(
        "UPDATE {{tables.agents}} SET did_aw=$1,address=$2,identity_scope='global' WHERE agent_id=$3",
        stable,
        address,
        actor.id,
    )
    actor.certificate = _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            actor.did,
            team_id=TEAM,
            alias="alice",
            identity_scope="global",
            member_did_aw=stable,
            member_address=address,
            certificate_id="global-alice",
        )
    )
    room = await metadata(env)
    response = await post(env, room, from_stable_id=stable)
    assert response.status_code == 200, response.text
    assert response.json()["from_stable_id"] == stable
    assert response.json()["verification_status"] == "verified"
    read = await env.client.get("/v1/room/messages", headers=headers(env.actors["bob"]))
    assert read.json()["messages"][0]["message_id"] == response.json()["message_id"]


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "global_resident,grant",
    [(False, False), (False, True), (True, False), (True, True)],
)
async def test_real_cli_room_post_read_and_who(
    privacy_app, tmp_path, global_resident, grant
):
    import asyncio
    from test_e2ee_local_sender_read_trust import _local_sender_mail

    env = privacy_app
    async with _local_sender_mail(env, tmp_path, global_resident, grant, False) as (
        _,
        _,
        binary,
        cwd,
        command_env,
        _,
    ):

        if grant:
            await env.db.execute(
                "UPDATE {{tables.identity_session_grants}} SET scopes=ARRAY['chat.read','chat.send']"
            )

        async def raw(*args, expected=0):
            proc = await asyncio.create_subprocess_exec(
                str(binary),
                *args,
                cwd=cwd,
                env=command_env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), 30)
            assert proc.returncode == expected, stderr.decode() + stdout.decode()
            return stdout.decode(), stderr.decode()

        async def run(*args):
            stdout, stderr = await raw(*args)
            return json.loads(stdout), stderr

        empty, notice = await raw("room", "read")
        assert empty == (
            "The team room is empty. Post with: "
            "aw room post --subject ... --body-file ...\n"
        )
        assert notice == ""

        body_file = tmp_path / "room-post.txt"
        body_file.write_text("A team update with `backticks` and $(literal text).\n")
        sent, notice = await run(
            "room", "post", "--subject", "CLI", "--body-file", str(body_file), "--json"
        )
        assert notice == ""
        assert sent["body"] == "A team update with `backticks` and $(literal text)."
        assert sent["from_did"] == env.actors["bob"].did
        read, _ = await run("room", "read", "--json")
        assert read["messages"][0]["message_id"] == sent["message_id"]
        assert read["messages"][0]["verification_status"] == "verified"
        who, _ = await run(
            "who",
            *(["--room"] if grant else []),
            "--message-id",
            sent["message_id"],
            "--json",
        )
        assert who["id"] == (sent.get("from_stable_id") or sent["from_did"])
        assert who["reason"] != "subject_mismatch"
        shown, notice = await raw("room", "read")
        assert "[verified]" in shown
        assert "Team room posts are readable" not in shown
        assert notice == ""
        missing_id = str(uuid4())
        stdout, stderr = await raw(
            "room", "read", "--message-id", missing_id, expected=1
        )
        assert stdout == ""
        assert stderr == f"No room post {missing_id} in your team.\n"
        stdout, stderr = await raw(
            "room", "post", "--e2ee", "--body", "must not send", expected=1
        )
        assert stdout == ""
        assert "unknown flag: --e2ee" in stderr
        assert (
            await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 1
        )
        if not grant:
            await env.db.execute(
                "UPDATE {{tables.agents}} SET deleted_at=now(),status='deleted' WHERE agent_id=$1",
                env.actors["bob"].id,
            )
            stdout, stderr = await raw("room", "read", expected=1)
            assert stdout == ""
            assert stderr == (
                f"You are no longer a member of {TEAM}, so you cannot read its room.\n"
            )


@pytest.mark.asyncio
async def test_room_does_not_change_existing_message_surfaces(privacy_app):
    env = privacy_app
    paths = ["/v1/messages/inbox", "/v1/chat/pending", "/v1/conversations"]
    original = [
        (await env.client.get(path, headers=headers(env.actors["bob"]))).content
        for path in paths
    ]
    room = await metadata(env)
    assert (await post(env, room)).status_code == 200
    await env.client.get("/v1/room/messages", headers=headers(env.actors["bob"]))
    after = [
        (await env.client.get(path, headers=headers(env.actors["bob"]))).content
        for path in paths
    ]
    assert after == original


@pytest.mark.asyncio
async def test_room_unavailable_membership_authority_refuses(privacy_app):
    from tests.real_stack import ServiceTransport

    env = privacy_app
    room = await metadata(env)
    # Exercise the real registry transport failing below the ordinary auth path.
    transport = ServiceTransport(env.registry_app)
    transport.down = True
    from awid.registry import RegistryClient

    unavailable = RegistryClient(
        registry_url="http://registry.test", transport=transport
    )
    previous = env.app.state.awid_registry_client
    env.app.state.awid_registry_client = unavailable
    try:
        result = await env.client.get(
            "/v1/room/messages", headers=headers(env.actors["alice"])
        )
        assert result.status_code == 503, result.text
        assert (await post(env, room)).status_code == 503
        assert (
            await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 0
        )
    finally:
        env.app.state.awid_registry_client = previous
        await unavailable.aclose()


@pytest.mark.asyncio
async def test_concurrent_room_posts_page_without_missing_or_duplicate_entries(
    privacy_app,
):
    import asyncio

    env = privacy_app
    room = await metadata(env)
    sent = await asyncio.gather(*(post(env, room, text=str(i)) for i in range(8)))
    assert all(result.status_code == 200 for result in sent)
    expected = {result.json()["message_id"] for result in sent}
    cursor = None
    seen = []
    while True:
        page = await env.client.get(
            "/v1/room/messages",
            params={"limit": 3, **({"after": cursor} if cursor else {})},
            headers=headers(env.actors["bob"]),
        )
        data = page.json()
        seen.extend(m["message_id"] for m in data["messages"])
        if not data["has_more"]:
            break
        cursor = data["next_cursor"]
    assert set(seen) == expected
    assert len(seen) == len(expected)


@pytest.mark.asyncio
async def test_recent_room_activity_prevents_inactive_team_gc(privacy_app):
    from aweb.gc import gc_inactive_scopes

    env = privacy_app
    room = await metadata(env)
    sent = await post(env, room)
    assert sent.status_code == 200
    await env.db.execute(
        "UPDATE {{tables.teams}} SET created_at=now()-interval '60 days' WHERE team_id=$1",
        TEAM,
    )
    assert (await gc_inactive_scopes(env.infra))["scopes_deleted"] == 0
    # Existing operator retention still applies after room activity goes idle.
    await env.db.execute(
        "UPDATE {{tables.room_messages}} SET created_at=now()-interval '60 days'"
    )
    assert (await gc_inactive_scopes(env.infra))["scopes_deleted"] == 1
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 0
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.team_rooms}}") == 0

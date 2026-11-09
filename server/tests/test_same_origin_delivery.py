"""Same-origin address delivery through real HTTP, AWID, PostgreSQL and Redis.

Only disposable namespace/member state is provisioned directly. The existing
development-only registry pin avoids external DNS; signatures, address lookup,
residence, federation ingress and policy all run their actual implementations.
The observer records requests without replacing transport or handler results.
"""
import asyncio
from datetime import datetime, timezone
import json
import os
import socket
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
import uvicorn
from nacl.signing import SigningKey

from awid.dns_verify import DomainAuthority
from awid.external_authority import DNSLookup
from awid.registry import CachedRegistryClient
from awid_service.deps import get_domain_verifier
from aweb.human_kind_revalidation import revalidate_human_kind
from test_id_chain_request_auth import ROOT, _signed_fixture_certificate

from awid.signing import canonical_json_bytes, sign_message
from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import encrypt_e2ee_message, generate_x25519_keypair
from aweb.federation.activation import build_federation_authority_activation
from aweb.mcp.server import create_mcp_app
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from aweb.testing import running_server
from identity_binding_support import register_global_identity
from test_cli_never_grants import registry_listener
from test_cli_human_reply import _pem
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import (
    _encode_certificate, _make_certificate, _make_keypair, _signed_team_headers, _signed_identity_headers,
)


@pytest.fixture(scope="module")
def same_origin_registry_socket():
    # Reuse an actual registry origin across fresh database fixtures. Shared
    # Redis cache entries outlive each database; disposable addresses must not.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        yield listener


@pytest_asyncio.fixture
async def same_origin(privacy_app, monkeypatch, same_origin_registry_socket):
    env = privacy_app
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "disposable-acst-proxy-secret")
    target_team = "recipients:recipient.test"
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
        "VALUES ($1, 'recipient.test', 'recipients', $2)", target_team, env.team_did,
    )
    sk, _, did = _make_keypair()
    target = SimpleNamespace(sk=sk, did=did, id=uuid4())
    address = f"recipient.test/recipient-{uuid4().hex[:12]}"
    global_sender_address = f"example.test/alice-{uuid4().hex[:12]}"
    ingress = []
    stack = env.app.middleware_stack or env.app.build_middleware_stack()

    async def observe(scope, receive, send):
        if scope.get("type") == "http" and scope.get("path") == "/v1/federation/messages":
            ingress.append(scope["path"])
        await stack(scope, receive, send)

    env.app.middleware_stack = observe
    async with registry_listener(env, listener_socket=same_origin_registry_socket.dup()) as (registry, registry_origin):
        stable = await register_global_identity(env, target, address)
        await env.registry_db.execute(
            "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1",
            env.app.state.public_origin,
        )
        monkeypatch.setenv("APP_ENV", "development")
        monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
        monkeypatch.setenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "1")
        monkeypatch.setenv("AWID_REGISTRY_URL", registry_origin)
        authority = build_federation_authority_activation(
            env.infra, public_origin=env.app.state.public_origin,
        )
        env.app.state.federation_authority = authority

        # Human fixtures enroll the actual subject key in the real public tree.
        # DNS alone is fixture authority; production revalidation projects kind.
        human_domain = f"awtest-same-origin-{uuid4().hex}.test"
        human_namespace_registered = False
        env.registry_app.state.awid_public_origins = (registry_origin,)

        async def exact_dns(domain):
            assert domain == human_domain
            return DomainAuthority(ROOT["did_key"], registry_origin, "_awid." + domain)

        async def lookup_txt(name):
            controllers = {
                "_awid." + human_domain: ROOT["did_key"],
                "_awid.example.test": env.team_did,
                "_awid.recipient.test": env.team_did,
            }
            assert name in controllers
            return DNSLookup("record", (
                f"awid=v1; controller={controllers[name]}; registry={registry_origin};",
            ))

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        cached = CachedRegistryClient(
            registry_origin, env.redis, service_token=registry.service_token,
            domain_verifier=exact_dns,
        )
        env.app.state.awid_registry_client = cached

        async def verify_human(actor, did_aw, db):
            nonlocal human_namespace_registered
            if not human_namespace_registered:
                await registry.register_namespace(
                    human_domain, ROOT["did_key"], bytes.fromhex(ROOT["seed_hex"]),
                )
                human_namespace_registered = True
            certificate = _signed_fixture_certificate(
                "alice", domain=human_domain, identity=did_aw,
                parent={"kind": "namespace", "id": human_domain}, issuer="root",
            )
            await registry.register_id_certificate(
                {"v": 1, "type": "aweb.id-chain", "certificates": [certificate]},
                signer=lambda payload: (actor.did, SigningKey(actor.sk).sign(payload).signature),
                expected_head=None, invitation_id=None,
            )
            report = await revalidate_human_kind(db, cached, apply=True)
            assert report["unresolved_active"] == 0, report
            assert await db.fetch_value(
                "SELECT human_verified_key FROM {{tables.agents}} WHERE agent_id=$1",
                actor.id,
            ) == actor.did

        async def resident(*, human=False, deleted=False, inbound_mode="open", db=None):
            db = db or env.db
            await db.execute(
                "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
                "VALUES ($1, 'recipient.test', 'recipients', $2) ON CONFLICT DO NOTHING",
                target_team, env.team_did,
            )
            await db.execute(
                "INSERT INTO {{tables.agents}} "
                "(agent_id, team_id, alias, did_key, did_aw, did_aw_verified_key, "
                "address, identity_scope, inbound_mode, agent_type, deleted_at) "
                "VALUES ($1,$2,'recipient',$3,$4,$3,$5,'global',$8,$6, "
                "CASE WHEN $7 THEN clock_timestamp() ELSE NULL END)",
                target.id, target_team, target.did, stable, address,
                "human" if human else "agent", False if human else deleted, inbound_mode,
            )
            if human:
                await verify_human(target, stable, db)
                if deleted:
                    await db.execute(
                        "UPDATE {{tables.agents}} SET deleted_at=clock_timestamp() WHERE agent_id=$1",
                        target.id,
                    )

        async def send_message(kind, sender_kind="local", *, continuation=None, target_key=None, target_sk=None, encrypted=False):
            actor = env.actors["alice"]
            sender_stable = ""
            sender_address = global_sender_address if sender_kind != "local" else "example.test/alice"
            if continuation is not None:
                sender_stable = continuation.signed.get("from_stable_id", "")
                sender_address = continuation.signed["from"]
            elif sender_kind != "local":
                sender_stable = await register_global_identity(env, actor, sender_address)
                await env.registry_db.execute(
                    "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1 "
                    "WHERE domain='example.test'", env.app.state.public_origin,
                )
                await env.db.execute(
                    "UPDATE {{tables.agents}} SET did_aw=$1, address=$2, "
                    "identity_scope='global', did_aw_verified_key=did_key, agent_type=$3 "
                    "WHERE agent_id=$4", sender_stable, sender_address,
                    "human" if sender_kind == "human" else "agent", actor.id,
                )
                if sender_kind == "human":
                    await verify_human(actor, sender_stable, env.db)
            certificate = _make_certificate(
                env.team_sk, env.team_did, actor.did, team_id=TEAM, alias="alice",
                identity_scope="global" if sender_stable else "local",
                member_did_aw=sender_stable, member_address=sender_address if sender_stable else "",
            )
            mid, cid = str(uuid4()), str(continuation.conversation_id) if continuation else str(uuid4())
            timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            signed = dict(
                type=kind, from_did=actor.did, to=address,
                to_did=target_key or target.did, to_stable_id=stable, message_id=mid,
                conversation_id=cid, timestamp=timestamp,
                body="Same-origin continuation" if continuation else "Same-origin delivery",
            )
            signed["from"] = sender_address
            if sender_stable:
                signed["from_stable_id"] = sender_stable
            if kind == "mail":
                signed.update(subject="Same-origin delivery", priority="normal")
                payload = dict(to_address=address, subject=signed["subject"],
                               body=signed["body"], conversation_id=cid)
                path = "/v1/messages"
            else:
                signed["sender_leaving"] = True
                payload = dict(to_addresses=[address], message=signed["body"],
                               session_id=cid, leaving=True)
                path = "/v1/chat/sessions"
                if continuation is not None:
                    payload = dict(body=signed["body"], leaving=True)
                    path += f"/{cid}/messages"
            encoded = canonical_json_bytes(signed).decode()
            payload.update(from_did=signed["from_did"], message_id=mid, timestamp=timestamp,
                           signed_payload=encoded, signature=sign_message(actor.sk, encoded.encode()))
            if encrypted:
                envelope = _encrypted_continuation(
                    kind, actor, sender_stable, signed,
                    target_key or target.did, target_sk or target.sk, stable, target_address=address,
                )
                payload.pop("signature")
                payload.pop("signed_payload")
                payload.update(content_mode="encrypted_v2", message_version=2, encrypted_envelope=envelope)
                if kind == "mail":
                    payload.update(body="", subject="")
                else:
                    payload["body" if continuation else "message"] = ""
            raw = json.dumps(payload).encode()
            headers = _signed_team_headers(
                actor.sk, actor.did, TEAM, _encode_certificate(certificate), raw,
            )
            response = await env.client.post(path, content=raw, headers={
                **headers, "Content-Type": "application/json",
            })
            return response, SimpleNamespace(
                message_id=UUID(mid), conversation_id=UUID(cid), signed=signed,
                signed_payload=encoded, signature=payload.get("signature"),
            )

        async def effects():
            tables = ("messages", "chat_messages", "conversations", "chat_sessions",
                      "conversation_participants", "chat_participants", "contacts",
                      "message_ingress_receipts", "federation_mutation_outbox")
            return {table: await env.db.fetch_value(
                "SELECT count(*) FROM {{tables." + table + "}}",
            ) for table in tables}

        try:
            yield SimpleNamespace(env=env, resident=resident, send=send_message,
                                  dns=SimpleNamespace(lookup_txt=lookup_txt),
                                  ingress=ingress, effects=effects, target_did=stable, target=target,
                                  target_address=address)
        finally:
            env.app.middleware_stack = stack
            env.app.state.awid_registry_client = registry
            await cached.aclose()
            await authority.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("sender_kind", ["local", "global", "human"])
@pytest.mark.parametrize("deleted", [False, True], ids=["absent", "deleted"])
async def test_same_origin_nonresident_refuses_without_federating(same_origin, kind, sender_kind, deleted):
    if deleted:
        await same_origin.resident(deleted=True)
    before = await same_origin.effects()
    response, _ = await same_origin.send(kind, sender_kind)
    after = await same_origin.effects()
    assert after == before, response.text
    assert not same_origin.ingress, (
        f"Self-federation reached the real ingress: HTTP {response.status_code} {response.text}"
    )
    assert response.status_code == 404, response.text
    assert response.json()["reason"] == "recipient_identity_not_found"
    assert response.json()["retryable"] is False
    assert "Ask the recipient or the person who manages that server" in response.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("human", [False, True], ids=["agent", "human"])
@pytest.mark.parametrize("sender_kind", ["local", "global", "human"])
async def test_same_origin_resident_delivery_and_human_chat_policy(same_origin, kind, human, sender_kind):
    await same_origin.resident(human=human)
    before = await same_origin.effects()
    response, submitted = await same_origin.send(kind, sender_kind)
    assert not same_origin.ingress, response.text
    if kind == "chat" and human:
        assert response.status_code == 422, response.text
        assert response.json()["reason"] == "recipient_human_mail_only"
        assert await same_origin.effects() == before
    else:
        assert response.status_code == 200, response.text
        after = await same_origin.effects()
        assert after["messages" if kind == "mail" else "chat_messages"] == 1
        db = same_origin.env.db
        table = "messages" if kind == "mail" else "chat_messages"
        row = await db.fetch_one(
            "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1",
            submitted.message_id,
        )
        assert row is not None
        sender_did = submitted.signed.get("from_stable_id", submitted.signed["from_did"])
        assert row["from_did"] == sender_did
        assert row["body"] == submitted.signed["body"]
        assert row["signed_payload"] == submitted.signed_payload
        assert row["signature"] == submitted.signature
        link = "conversation_id" if kind == "mail" else "session_id"
        assert row[link] == submitted.conversation_id
        if kind == "mail":
            assert row["to_did"] == same_origin.target_did
            assert row["subject"] == submitted.signed["subject"]
        else:
            session = await db.fetch_one(
                "SELECT session_id FROM {{tables.chat_sessions}} WHERE session_id=$1",
                submitted.conversation_id,
            )
            assert session is not None
        conversation = await db.fetch_one(
            "SELECT conversation_type FROM {{tables.conversations}} WHERE conversation_id=$1",
            submitted.conversation_id,
        )
        assert conversation is not None
        assert conversation["conversation_type"] == kind
        participant_tables = [("conversation_participants", "conversation_id")]
        if kind == "chat":
            participant_tables.append(("chat_participants", "session_id"))
        for participant_table, link in participant_tables:
            participants = await db.fetch_all(
                "SELECT did FROM {{tables." + participant_table + "}} WHERE " + link + "=$1",
                submitted.conversation_id,
            )
            assert {p["did"] for p in participants} == {
                sender_did, same_origin.target_did,
            }


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("inbound_mode", ["team_and_contacts", "contacts_only"])
async def test_same_origin_resident_policy_refuses_cross_team_noncontact(same_origin, kind, inbound_mode):
    await same_origin.resident(inbound_mode=inbound_mode)
    before = await same_origin.effects()
    assert before["contacts"] == 0
    response, _ = await same_origin.send(kind)
    assert response.status_code == 403, response.text
    assert "exact active contacts" in response.text
    assert not same_origin.ingress, response.text
    assert await same_origin.effects() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_same_origin_old_alias_is_not_residence_of_new_did(same_origin, kind):
    await same_origin.resident(human=True)
    await same_origin.env.db.execute(
        "UPDATE {{tables.agents}} SET did_aw=$1, address=NULL WHERE did_aw=$2",
        "did:aw:older-unrelated-identity", same_origin.target_did,
    )
    before = await same_origin.effects()
    response, _ = await same_origin.send(kind)
    assert not same_origin.ingress, response.text
    assert response.status_code == 404, response.text
    assert response.json()["reason"] == "recipient_identity_not_found"
    assert await same_origin.effects() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_same_origin_comparison_normalizes_public_origin(same_origin, kind):
    same_origin.env.app.state.public_origin += "/"
    response, _ = await same_origin.send(kind)
    assert not same_origin.ingress, response.text
    assert response.status_code == 404, response.text
    assert response.json()["reason"] == "recipient_identity_not_found"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("strict", [False, True], ids=["registry-fallback", "strict-authority"])
async def test_same_origin_nonhome_resolution_refuses_without_federating(same_origin, kind, strict):
    # No local namespace: exercise the other two address-resolution branches.
    await same_origin.env.db.execute(
        "DELETE FROM {{tables.teams}} WHERE namespace='recipient.test'",
    )
    if not strict:
        same_origin.env.app.state.federation_authority = None
    before = await same_origin.effects()
    response, _ = await same_origin.send(kind)
    assert not same_origin.ingress, response.text
    assert response.status_code == 404, response.text
    assert response.json()["reason"] == "recipient_identity_not_found"
    assert await same_origin.effects() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_same_origin_mcp_nonresident_refusal(same_origin, kind):
    env = same_origin.env
    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        federation_authority=env.app.state.federation_authority,
        public_origin=env.app.state.public_origin,
    )
    env.app.mount("/same-origin-mcp", mcp)
    await mcp.startup()
    try:
        actor = env.actors["alice"]
        arguments = (
            dict(to=same_origin.target_address, body="Same-origin MCP", plaintext=True)
            if kind == "mail" else
            dict(to_address=same_origin.target_address, message="Same-origin MCP", plaintext=True)
        )
        raw = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "send_mail" if kind == "mail" else "chat_send", "arguments": arguments},
        }).encode()
        before = await same_origin.effects()
        response = await env.client.post("/same-origin-mcp/", content=raw, headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, raw),
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        })
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert not result.get("isError"), result
        refusal = json.loads(result["content"][0]["text"])
        assert refusal["reason"] == "recipient_identity_not_found", refusal
        assert refusal["retryable"] is False
        assert "Ask the recipient or the person who manages that server" in refusal["error"]
        assert not same_origin.ingress
        assert await same_origin.effects() == before
    finally:
        await mcp.shutdown()


@pytest_asyncio.fixture
async def foreign_receiver(same_origin, test_db_factory, monkeypatch):
    """A second actual server, listener and database; AWID is shared over HTTP."""
    env = same_origin.env
    database = await test_db_factory.create_db(suffix="same_origin_foreign")
    monkeypatch.setenv("AWEB_DATABASE_URL", database.config.get_dsn())
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    async with running_server(
        database.config.get_dsn(), env.redis,
        awid_transport=httpx.AsyncHTTPTransport(), public_origin=origin,
    ) as receiver:
        # An enrolled human sender requires controller authority for its ID
        # namespace, which a default-registry pin alone cannot establish.
        activation = receiver.app.state.federation_authority
        activation.test_default_registry_authority = None
        activation.txt_resolver = same_origin.dns
        manager = receiver.db.get_manager("aweb")
        await same_origin.resident(db=manager)
        await env.registry_db.execute(
            "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1 "
            "WHERE domain='recipient.test'", origin,
        )
        ingress = []
        statuses = []
        stack = receiver.app.build_middleware_stack()

        async def observe(scope, receive, send):
            if scope.get("type") == "http" and scope.get("path") == "/v1/federation/messages":
                ingress.append(scope["path"])
                async def observed_send(message):
                    if message["type"] == "http.response.start":
                        statuses.append(message["status"])
                    await send(message)
                await stack(scope, receive, observed_send)
            else:
                await stack(scope, receive, send)

        receiver.app.middleware_stack = observe
        server = uvicorn.Server(uvicorn.Config(receiver.app, lifespan="off", log_level="error", ws="none"))
        serving = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            for _ in range(100):
                if server.started:
                    break
                await asyncio.sleep(.02)
            assert server.started
            yield SimpleNamespace(db=manager, ingress=ingress, statuses=statuses, origin=origin, app=receiver.app)
        finally:
            server.should_exit = True
            await asyncio.wait_for(serving, 5)
            sock.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("incarnation", ["first", "second"])
async def test_same_registry_origin_does_not_reuse_another_fixture_recipient(
    same_origin, foreign_receiver, incarnation,
):
    # Each incarnation has fresh keys/databases and the same registry origin.
    # The second must not resolve the first's cached disposable address.
    response, submitted = await same_origin.send("mail", "global")
    assert response.status_code == 200, response.text
    stored = await foreign_receiver.db.fetch_one(
        "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", submitted.message_id,
    )
    assert stored is not None
    assert stored["to_did"] == same_origin.target_did


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("sender_kind", ["local", "global", "human"])
async def test_foreign_origin_still_reaches_real_receiver(same_origin, foreign_receiver, kind, sender_kind):
    response, submitted = await same_origin.send(kind, sender_kind)
    assert not same_origin.ingress, response.text
    assert foreign_receiver.ingress == ["/v1/federation/messages"], response.text
    table = "messages" if kind == "mail" else "chat_messages"
    row = await foreign_receiver.db.fetch_one(
        "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", submitted.message_id,
    )
    if sender_kind == "local":
        # Existing first-contact limit; actf will replace this, not this fix.
        assert response.status_code == 422, response.text
        assert "local_sender_route_mismatch" in response.text
        assert row is None
    else:
        assert response.status_code == 200, response.text
        assert row is not None
        assert row["body"] == submitted.signed["body"]
        assert row["signed_payload"] == submitted.signed_payload
        assert row["signature"] == submitted.signature
        assert row["from_did"] == submitted.signed["from_stable_id"]
        assert row["conversation_id" if kind == "mail" else "session_id"] == submitted.conversation_id
        if kind == "mail":
            assert row["to_did"] == same_origin.target_did
        participants = await foreign_receiver.db.fetch_all(
            "SELECT did FROM {{tables.conversation_participants}} WHERE conversation_id=$1",
            submitted.conversation_id,
        )
        assert {p["did"] for p in participants} == {
            same_origin.target_did, submitted.signed["from_stable_id"],
        }


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("route", ["resident", "nonresident", "foreign"])
async def test_real_cli_address_delivery(same_origin, foreign_receiver, source_cli_binary, tmp_path, kind, route):
    env = same_origin.env
    if route != "foreign":
        await env.registry_db.execute(
            "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1 "
            "WHERE domain='recipient.test'", env.app.state.public_origin,
        )
    if route == "resident":
        await same_origin.resident()
    actor = env.actors["alice"]
    cert = _make_certificate(env.team_sk, env.team_did, actor.did, team_id=TEAM, alias="alice", identity_scope="local")
    for field in ("signature", "member_did_aw", "member_address"):
        cert.pop(field)
    cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
    identity_home = tmp_path / "sender" / ".aw"
    identity_home.mkdir(parents=True, mode=0o700)
    _pem(identity_home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    (identity_home / "identity.yaml").write_text(json.dumps(dict(did=actor.did, custody="self", identity_scope="local")))
    (identity_home / "certificate.json").write_text(json.dumps(cert))
    membership = dict(team_id=TEAM, alias="alice", cert_path="certificate.json")
    (identity_home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
    (identity_home / "workspace.yaml").write_text(json.dumps(dict(
        aweb_url=str(env.client.base_url), memberships=[dict(membership, workspace_id=str(actor.workspace))],
    )))
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW_", "AWEB_", "AWID_", "OATS_"))}
    child_env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"), AW_NO_UPDATE_CHECK="1",
                     AWID_REGISTRY_URL=env.app.state.awid_registry_client.registry_url)
    body_file = tmp_path / "message.txt"
    body_file.write_text("Real CLI address delivery")
    args = (
        ["mail", "send", "--to-address", same_origin.target_address, "--subject", "Routing control"]
        if kind == "mail" else ["chat", "send-and-leave", same_origin.target_address]
    )
    before = await same_origin.effects()
    process = await asyncio.create_subprocess_exec(
        str(source_cli_binary), "--identity-home", str(identity_home), *args, "--body-file", str(body_file),
        cwd=tmp_path, env=child_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    data, _ = await asyncio.wait_for(process.communicate(), 30)
    output = data.decode()
    assert not same_origin.ingress, output
    assert bool(foreign_receiver.ingress) == (route == "foreign"), output
    if route == "resident":
        assert process.returncode == 0, output
        table = "messages" if kind == "mail" else "chat_messages"
        row = await env.db.fetch_one("SELECT * FROM {{tables." + table + "}}")
        assert row is not None
        assert row["body"] == body_file.read_text()
        signed = json.loads(row["signed_payload"])
        assert str(row["message_id"]) == signed["message_id"]
        assert signed["to_stable_id"] == same_origin.target_did
        if kind == "mail":
            assert row["to_did"] == same_origin.target_did
        else:
            participants = await env.db.fetch_all(
                "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1", row["session_id"],
            )
            assert {p["did"] for p in participants} == {actor.did, same_origin.target_did}
    else:
        assert process.returncode != 0, output
        assert await same_origin.effects() == before
        if route == "nonresident":
            assert "Ask the recipient or the person who manages that server" in output
        else:
            assert "local_sender_route_mismatch" in output


@pytest.mark.asyncio
async def test_chat_route_refresh_to_nonresident_own_origin_has_no_effects(same_origin, foreign_receiver):
    env = same_origin.env
    response, first = await same_origin.send("chat", "global")
    assert response.status_code == 200, response.text
    # The identity moves away from the old receiver. The old receiver remains
    # reachable, but its real ingress now refuses the nonresident target (404).
    await foreign_receiver.db.execute(
        "UPDATE {{tables.agents}} SET deleted_at=clock_timestamp() WHERE did_aw=$1",
        same_origin.target_did,
    )
    await env.registry_db.execute(
        "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1 WHERE domain='recipient.test'",
        env.app.state.public_origin,
    )
    async def routes():
        return [dict(row) for table, column in (
            ("chat_participants", "session_id"), ("conversation_participants", "conversation_id"),
        ) for row in await env.db.fetch_all(
            "SELECT did, delivery_origin, current_did_key FROM {{tables." + table + "}} WHERE " + column + "=$1 ORDER BY did",
            first.conversation_id,
        )]
    before_routes = await routes()
    before = await same_origin.effects()
    response, submitted = await same_origin.send("chat", "global", continuation=first)
    assert foreign_receiver.ingress == ["/v1/federation/messages"] * 2, response.text
    assert foreign_receiver.statuses == [200, 404]
    assert await same_origin.effects() == before, response.text
    assert await foreign_receiver.db.fetch_value(
        "SELECT count(*) FROM {{tables.chat_messages}} WHERE message_id=$1", submitted.message_id,
    ) == 0
    assert not same_origin.ingress, response.text
    assert await routes() == before_routes
    assert response.status_code == 404, response.text
    assert response.json()["reason"] == "recipient_identity_not_found"
    assert response.json()["retryable"] is False


def _encrypted_continuation(kind, actor, sender_stable, fields, target_key, target_sk, target_stable, *, target_address):
    # Model keys already available when MCP chose its signed message time.
    # A fresh wall-clock read here can cross a second and mint future keys.
    created_at = datetime.fromisoformat(fields["timestamp"].replace("Z", "+00:00"))

    def identity(did, stable, address, sk):
        _, public_key = generate_x25519_keypair()
        return dict(
            did=did, stable_id=stable, address=address, signing_key=sk,
            encryption_key=build_encryption_key_assertion(
                signing_key=sk, identity_did=did, identity_stable_id=stable,
                encryption_public_key=public_key, custody="hosted_custodial",
                now=created_at,
            ),
        )
    return encrypt_e2ee_message(
        kind=kind, sender=identity(actor.did, sender_stable, fields.get("from", "example.test/alice"), actor.sk),
        recipients=[identity(target_key, target_stable, target_address, target_sk)],
        body=fields["body"], subject=fields.get("subject", ""),
        message_id=fields["message_id"], conversation_id=fields["conversation_id"],
        created_at=created_at,
    )


@pytest.mark.parametrize("kind", ["mail", "chat"])
def test_hosted_continuation_fixture_crosses_clock_second(kind, monkeypatch):
    """The fixture's keys must exist at the MCP-selected envelope time."""
    class LaterClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 4, 12, 0, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(f"{__name__}.datetime", LaterClock)
    sender_sk, _, sender_did = _make_keypair()
    target_sk, _, target_did = _make_keypair()
    fields = dict(
        timestamp="2026-11-04T12:00:00Z", body="second-boundary regression",
        subject="fixture timeline", message_id=str(uuid4()), conversation_id=str(uuid4()),
    )
    envelope = _encrypted_continuation(
        kind, SimpleNamespace(sk=sender_sk, did=sender_did), None,
        fields, target_did, target_sk, None, target_address="recipient.test/recipient",
    )
    assert envelope["created_at"] == fields["timestamp"]
    assert envelope["message_id"] == fields["message_id"]
    assert envelope["conversation_id"] == fields["conversation_id"]


async def _mcp_continue(same_origin, first, kind, *, target_key=None, target_sk=None, encrypted=False):
    env = same_origin.env
    actor = env.actors["alice"]

    async def signer(**kwargs):
        fields = dict(kwargs["payload"])
        if target_key is not None:
            # A real custodian signature can still bind an obsolete target.
            # The hosted-signing contract must refuse a stale signer result.
            fields["to_did"] = target_key
        payload = canonical_signed_payload(fields)
        return HostedMessageSigningResult(
            from_did=actor.did, signed_payload=payload,
            signature=sign_message(actor.sk, payload.encode()), signing_key_id=actor.did,
        )

    async def encryptor(**kwargs):
        envelope = _encrypted_continuation(
            kind, actor, first.signed["from_stable_id"], kwargs["payload"],
            target_key or same_origin.target.did, target_sk or same_origin.target.sk, same_origin.target_did,
            target_address=same_origin.target_address,
        )
        return dict(content_mode="encrypted_v2", message_version=2, encrypted_envelope=envelope)

    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        federation_authority=env.app.state.federation_authority,
        hosted_signer=signer, hosted_encryptor=encryptor, public_origin=env.app.state.public_origin,
    )
    env.app.mount("/continuation-mcp", mcp)
    await mcp.startup()
    try:
        arguments = (
            dict(conversation_id=str(first.conversation_id), body="MCP continuation", plaintext=not encrypted)
            if kind == "mail" else
            dict(session_id=str(first.conversation_id), message="MCP continuation", plaintext=not encrypted)
        )
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "send_mail" if kind == "mail" else "chat_send", "arguments": arguments,
        }}).encode()
        principal = str(uuid4())
        response = await env.client.post("/continuation-mcp/", content=raw, headers={
            "X-Team-ID": TEAM, "X-User-ID": principal, "X-AWEB-Actor-ID": str(actor.id),
            "X-AWEB-Auth": build_internal_auth_header_value(
                secret="disposable-acst-proxy-secret", team_id=TEAM,
                principal_type="u", principal_id=principal, actor_id=str(actor.id),
            ),
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        })
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert not result.get("isError"), result
        return json.loads(result["content"][0]["text"])
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("api", ["http", "mcp"])
@pytest.mark.parametrize("route", ["own", "own_alias", "foreign"])
async def test_stored_continuation_routes(same_origin, foreign_receiver, kind, api, route):
    env = same_origin.env
    response, first = await same_origin.send(kind, "global")
    assert response.status_code == 200, response.text
    if route == "own":
        for table, column in (("conversation_participants", "conversation_id"), ("chat_participants", "session_id")):
            await env.db.execute(
                "UPDATE {{tables." + table + "}} SET delivery_origin=$1 WHERE " + column + "=$2 AND did=$3",
                env.app.state.public_origin, first.conversation_id, same_origin.target_did,
            )
    elif route == "own_alias":
        # The transport destination is a real listener, so an omitted alias
        # guard would deliver there. Ingress and sends must share this set.
        env.app.state.federation_public_origins = [foreign_receiver.origin + "/"]
    before = await same_origin.effects()
    before_routes = [dict(row) for table, column in (
        ("conversation_participants", "conversation_id"), ("chat_participants", "session_id"),
    ) for row in await env.db.fetch_all(
        "SELECT did, delivery_origin, current_did_key FROM {{tables." + table + "}} WHERE " + column + "=$1 ORDER BY did",
        first.conversation_id,
    )]
    if api == "http":
        response, submitted = await same_origin.send(kind, "global", continuation=first)
        result = response.json()
    else:
        result = await _mcp_continue(same_origin, first, kind)
    assert not same_origin.ingress, result
    if route == "foreign":
        assert "error" not in result, result
        if api == "http":
            assert response.status_code == 200, response.text
        assert len(foreign_receiver.ingress) == 2
        table = "messages" if kind == "mail" else "chat_messages"
        stored = await foreign_receiver.db.fetch_one(
            "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", UUID(result["message_id"]),
        )
        assert stored is not None
        assert stored["conversation_id" if kind == "mail" else "session_id"] == first.conversation_id
        assert stored["from_did"] == first.signed["from_stable_id"]
        if kind == "mail":
            assert stored["to_did"] == same_origin.target_did
    else:
        assert result.get("reason") == "recipient_identity_not_found", result
        assert result["retryable"] is False
        if api == "http":
            assert response.status_code == 404
        assert await same_origin.effects() == before
        assert len(foreign_receiver.ingress) == 1
        after_routes = [dict(row) for table, column in (
            ("conversation_participants", "conversation_id"), ("chat_participants", "session_id"),
        ) for row in await env.db.fetch_all(
            "SELECT did, delivery_origin, current_did_key FROM {{tables." + table + "}} WHERE " + column + "=$1 ORDER BY did",
            first.conversation_id,
        )]
        assert after_routes == before_routes


@pytest.mark.asyncio
async def test_chat_refresh_to_changed_foreign_origin_still_delivers(same_origin, foreign_receiver):
    env = same_origin.env
    response, first = await same_origin.send("chat", "global")
    assert response.status_code == 200, response.text
    # One actual receiver under a new public origin: old URL returns its real
    # 421 target_route_mismatch; the refreshed URL reaches the same live app.
    moved_origin = foreign_receiver.origin.replace("127.0.0.1", "localhost")
    foreign_receiver.app.state.public_origin = moved_origin
    await env.registry_db.execute(
        "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1 WHERE domain='recipient.test'", moved_origin,
    )
    response, submitted = await same_origin.send("chat", "global", continuation=first)
    assert response.status_code == 200, response.text
    assert foreign_receiver.statuses == [200, 421, 200]
    assert not same_origin.ingress
    stored = await foreign_receiver.db.fetch_one(
        "SELECT * FROM {{tables.chat_messages}} WHERE message_id=$1", submitted.message_id,
    )
    assert stored["signed_payload"] == submitted.signed_payload
    assert stored["signature"] == submitted.signature
    assert stored["session_id"] == first.conversation_id
    for table, column in (("conversation_participants", "conversation_id"), ("chat_participants", "session_id")):
        assert await env.db.fetch_value(
            "SELECT delivery_origin FROM {{tables." + table + "}} WHERE " + column + "=$1 AND did=$2",
            first.conversation_id, same_origin.target_did,
        ) == moved_origin


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("api", ["http", "mcp"])
@pytest.mark.parametrize("recipient", ["open", "contacts_only", "human"])
async def test_stored_own_route_resident_uses_local_policy(same_origin, foreign_receiver, kind, api, recipient):
    env = same_origin.env
    response, first = await same_origin.send(kind, "global")
    assert response.status_code == 200, response.text
    await same_origin.resident(human=recipient == "human", inbound_mode="contacts_only" if recipient == "contacts_only" else "open")
    for table, column in (("conversation_participants", "conversation_id"), ("chat_participants", "session_id")):
        await env.db.execute(
            "UPDATE {{tables." + table + "}} SET delivery_origin=$1 WHERE " + column + "=$2 AND did=$3",
            env.app.state.public_origin, first.conversation_id, same_origin.target_did,
        )
    before = await same_origin.effects()
    if api == "http":
        response, submitted = await same_origin.send(kind, "global", continuation=first)
        result = response.json()
    else:
        result = await _mcp_continue(same_origin, first, kind)
    assert not same_origin.ingress, result
    assert len(foreign_receiver.ingress) == 1, result
    if recipient == "contacts_only" or (kind == "chat" and recipient == "human"):
        assert "error" in result or "detail" in result, result
        if api == "http":
            assert response.status_code == (422 if recipient == "human" else 403), result
        assert await same_origin.effects() == before
    else:
        assert "error" not in result, result
        if api == "http":
            assert response.status_code == 200, result
        table = "messages" if kind == "mail" else "chat_messages"
        stored = await env.db.fetch_one(
            "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", UUID(result["message_id"]),
        )
        assert stored is not None
        assert stored["conversation_id" if kind == "mail" else "session_id"] == first.conversation_id
        assert stored["from_did"] == first.signed["from_stable_id"]
        if kind == "mail":
            assert stored["to_did"] == same_origin.target_did
        await _assert_recipient_can_read(same_origin, kind, stored)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_first_contact_accepted_origin_alias_is_local(same_origin, kind):
    env = same_origin.env
    original = env.app.state.public_origin
    env.app.state.public_origin = original.replace("127.0.0.1", "localhost")
    env.app.state.federation_public_origins = [original + "/"]
    before = await same_origin.effects()
    response, _ = await same_origin.send(kind)
    assert response.status_code == 404, response.text
    assert response.json()["reason"] == "recipient_identity_not_found"
    assert response.json()["retryable"] is False
    assert not same_origin.ingress
    assert await same_origin.effects() == before


async def _assert_recipient_can_read(same_origin, kind, stored):
    """Read using the recipient's actual identity, with no participant repair."""
    env, target = same_origin.env, same_origin.target
    conversation_id = str(stored["conversation_id" if kind == "mail" else "session_id"])
    if kind == "chat":
        assert await env.db.fetch_value(
            "SELECT agent_id FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2",
            UUID(conversation_id), same_origin.target_did,
        ) is None  # Retain the exact remote-participant shape under review.

    async def http_read(path):
        response = await env.client.get(path, headers=_signed_identity_headers(
            target.sk, target.did, same_origin.target_did,
        ))
        assert response.status_code == 200, response.text
        return response.json()

    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=env.app.state.public_origin,
    )
    env.app.mount("/recipient-mcp", mcp)
    await mcp.startup()
    try:
        async def mcp_read(tool, **arguments):
            raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": tool, "arguments": arguments,
            }}).encode()
            response = await env.client.post("/recipient-mcp/", content=raw, headers={
                **_signed_identity_headers(target.sk, target.did, same_origin.target_did, raw),
                "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            })
            assert response.status_code == 200, response.text
            result = response.json()["result"]
            assert not result.get("isError"), result
            data = json.loads(result["content"][0]["text"])
            assert "error" not in data, data
            return data

        if kind == "mail":
            reads = [await http_read("/v1/messages/inbox?unread_only=true"), await mcp_read("check_mail")]
        else:
            for pending in [await http_read("/v1/chat/pending"), await mcp_read("check_chats")]:
                session = next((row for row in pending["pending"] if row["session_id"] == conversation_id), None)
                assert session is not None, pending
                assert session["unread_count"] > 0
                assert session["last_message"] == stored["body"]
            reads = [await http_read(f"/v1/chat/sessions/{conversation_id}/messages"),
                     await mcp_read("read_chat", conversation_id=conversation_id)]
        for data in reads:
            message = next((row for row in data["messages"] if row["message_id"] == str(stored["message_id"])), None)
            assert message is not None, data
            assert message["conversation_id"] == conversation_id
            assert message["body"] == stored["body"]
            assert message["signed_payload"] == stored["signed_payload"]
            assert message["signature"] == stored["signature"]
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("api", ["http", "mcp"])
@pytest.mark.parametrize("key", ["obsolete", "current"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "encrypted"])
async def test_stored_own_route_rotation_requires_current_target(same_origin, foreign_receiver, kind, api, key, encrypted):
    env, target = same_origin.env, same_origin.target
    response, first = await same_origin.send(kind, "global")
    assert response.status_code == 200, response.text
    new_sk, _, new_key = _make_keypair()
    await env.app.state.awid_registry_client.rotate_key(same_origin.target_did, new_key, target.sk, new_sk)
    # Admit the exact DID locally, but retain its stale projection and marker.
    # Residence must not depend on either; neither may become current evidence.
    await same_origin.resident()
    await env.db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=NULL WHERE did_aw=$1", same_origin.target_did,
    )
    await env.registry_db.execute(
        "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1 WHERE domain='recipient.test'", env.app.state.public_origin,
    )
    for table, column in (("conversation_participants", "conversation_id"), ("chat_participants", "session_id")):
        await env.db.execute(
            "UPDATE {{tables." + table + "}} SET delivery_origin=$1 WHERE " + column + "=$2 AND did=$3",
            env.app.state.public_origin, first.conversation_id, same_origin.target_did,
        )
    async def state():
        return [dict(row) for table, where, value in (
            ("agents", "did_aw", same_origin.target_did),
            ("conversation_participants", "conversation_id", first.conversation_id),
            ("chat_participants", "session_id", first.conversation_id),
        ) for row in await env.db.fetch_all("SELECT * FROM {{tables." + table + "}} WHERE " + where + "=$1", value)]
    before = await same_origin.effects()
    before_state = await state()
    chosen_key = target.did if key == "obsolete" else new_key
    if api == "http":
        response, submitted = await same_origin.send(kind, "global", continuation=first, target_key=chosen_key, target_sk=target.sk if key == "obsolete" else new_sk, encrypted=encrypted)
        result = response.json()
    else:
        result = await _mcp_continue(same_origin, first, kind, target_key=chosen_key, target_sk=target.sk if key == "obsolete" else new_sk, encrypted=encrypted)
    assert not same_origin.ingress
    assert len(foreign_receiver.ingress) == 1
    if key == "obsolete":
        assert "error" in result or "detail" in result, result
        expected = (
            "encrypted envelope recipient did mismatch" if encrypted else
            "hosted custodial signer returned signed_payload for different fields" if api == "mcp" else
            "identity_binding_mismatch" if kind == "mail" else
            "signed_payload recipient must match the chat target"
        )
        assert result.get("error", result.get("detail")) == expected, result
        if api == "http":
            assert response.status_code in (403, 422), result
        assert await same_origin.effects() == before
        assert await state() == before_state
    else:
        assert "error" not in result, result
        if api == "http":
            assert response.status_code == 200, result
        table = "messages" if kind == "mail" else "chat_messages"
        stored = await env.db.fetch_one(
            "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", UUID(result["message_id"]),
        )
        assert stored is not None
        if encrypted:
            envelope = stored["encrypted_envelope"]
            envelope = json.loads(envelope) if isinstance(envelope, str) else envelope
            assert envelope["recipients"][0]["did"] == new_key
        else:
            assert json.loads(stored["signed_payload"])["to_did"] == new_key
        assert stored["conversation_id" if kind == "mail" else "session_id"] == first.conversation_id
        assert await env.db.fetch_value(
            "SELECT did_aw_verified_key FROM {{tables.agents}} WHERE did_aw=$1", same_origin.target_did,
        ) is None


@pytest.mark.asyncio
async def test_own_route_current_binding_unavailable_refuses(same_origin, foreign_receiver):
    """A real connection failure cannot promote even a marked resident key.

    Exercise the shared classification boundary directly so sender auth cannot
    consume the dependency failure before recipient validation is reached.
    """
    from awid.registry import RegistryClient
    from fastapi import HTTPException
    from aweb.messaging.address_auth import local_recipient_for_own_route

    env = same_origin.env
    response, first = await same_origin.send("mail", "global")
    assert response.status_code == 200, response.text
    await same_origin.resident()
    route = dict(await env.db.fetch_one(
        "SELECT * FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
        first.conversation_id, same_origin.target_did,
    ))
    route["delivery_origin"] = env.app.state.public_origin
    before = await same_origin.effects()
    before_agent = dict(await env.db.fetch_one(
        "SELECT * FROM {{tables.agents}} WHERE did_aw=$1", same_origin.target_did,
    ))
    # Reserve but do not listen: real HTTP connect refusal, no fake authority.
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        client = RegistryClient(f"http://127.0.0.1:{unavailable.getsockname()[1]}", timeout_seconds=0.2)
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(awid_registry_client=client)), state=SimpleNamespace())
        try:
            with pytest.raises(HTTPException) as refused:
                await local_recipient_for_own_route(
                    env.infra, route, request=request, origins={env.app.state.public_origin},
                )
        finally:
            await client.aclose()
    assert refused.value.status_code == 503
    assert refused.value.detail == "identity_binding_unavailable"
    assert not same_origin.ingress
    assert len(foreign_receiver.ingress) == 1
    assert await same_origin.effects() == before
    assert dict(await env.db.fetch_one(
        "SELECT * FROM {{tables.agents}} WHERE did_aw=$1", same_origin.target_did,
    )) == before_agent

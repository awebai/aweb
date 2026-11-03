"""Team-vouched local senders through two real aweb/AWID servers and DNS.

SQL provisions disposable identities and namespace ownership. All signatures,
certificate publication/status, team-server records, DNS discovery and delivery
use the actual implementations over loopback sockets. Observers forward bytes
unchanged; no resolver, authority, clock, transport or handler is mocked.
"""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import socket
from types import SimpleNamespace
from uuid import UUID, uuid4

import dns.asyncresolver
import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis
import uvicorn

from aweb.e2ee_messages import encrypt_e2ee_message, generate_x25519_keypair
from aweb.testing import running_server
from aweb_naapp_testing.network import DnsServer
from awid.e2ee_keys import build_encryption_key_assertion
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from awid.team_server_record import build_team_server_record, sign_team_server_record
from awid_service.testing import running_registry
from test_messages_http import (
    _encode_certificate, _make_certificate, _make_keypair, _signed_team_headers,
    _insert_agent_encryption_assertion,
)


def _socket():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock


def _origin(sock):
    return f"http://127.0.0.1:{sock.getsockname()[1]}"


@asynccontextmanager
async def _listener(app, sock):
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="error", ws="none"))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(.02)
        assert server.started, "real HTTP listener did not start"
        yield
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, 5)
        sock.close()


def _observe(app):
    requests = []
    stack = app.middleware_stack or app.build_middleware_stack()

    async def observer(scope, receive, send):
        if scope.get("type") == "http":
            requests.append((scope["method"], scope["path"]))
        await stack(scope, receive, send)

    app.middleware_stack = observer
    return requests


@pytest_asyncio.fixture
async def route_pair(test_db_factory, monkeypatch):
    """Separate home registries; actual UDP TXT discovery between the nodes."""
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
    monkeypatch.setenv("AWID_ALLOW_INSECURE_DELIVERY_ORIGIN", "1")
    monkeypatch.delenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", raising=False)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    monkeypatch.setenv("AWEB_LOG_LEVEL", "error")
    token = "actf-disposable-service-token-32-bytes"
    monkeypatch.setenv("AWID_SERVICE_TOKEN", token)
    async with AsyncExitStack() as stack:
        redis = await stack.enter_async_context(Redis.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True,
        ))
        await redis.ping()
        dns_server = DnsServer()
        await dns_server.start()
        stack.callback(dns_server.close)
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = ["127.0.0.1"]
        resolver.port = dns_server.port
        resolver.timeout = resolver.lifetime = 1
        monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
        nodes = []
        for name in ("alpha", "beta"):
            # Unique domains avoid cross-test Redis membership cache collisions.
            domain = f"{name}-{uuid4().hex[:12]}.test"
            team_id = f"members:{domain}"
            team_sk, _, team_did = _make_keypair()
            db = await test_db_factory.create_db(suffix=f"actf_{name}")
            await db.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
            dsn = db.config.get_dsn()
            registry = await stack.enter_async_context(running_registry(dsn, service_token=token, redis=redis))
            registry_sock = _socket()
            registry_origin = _origin(registry_sock)
            registry_calls = _observe(registry.app)
            await stack.enter_async_context(_listener(registry.app, registry_sock))
            registry_client = RegistryClient(registry_origin, service_token=token)
            stack.push_async_callback(registry_client.aclose)
            await registry.add_team(team_id, team_did, visibility="private")
            server_sock = _socket()
            public_origin = _origin(server_sock)
            await registry.db.execute(
                "INSERT INTO {{tables.dns_namespaces}} "
                "(domain, controller_did, verification_status, default_delivery_origin) "
                "VALUES ($1,$2,'verified',$3)", domain, team_did, public_origin,
            )
            dns_server.records[(f"_awid.{domain}", "TXT")] = [
                f'"awid=v1;controller={team_did};registry={registry_origin}"',
            ]
            monkeypatch.setenv("AWID_REGISTRY_URL", registry_origin)
            server = await stack.enter_async_context(running_server(
                dsn, redis, awid_transport=httpx.AsyncHTTPTransport(), public_origin=public_origin,
            ))
            manager = server.db.get_manager("aweb")
            await manager.execute(
                "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
                "VALUES ($1,$2,'members',$3)", team_id, domain, team_did,
            )
            server_calls = _observe(server.app)
            await stack.enter_async_context(_listener(server.app, server_sock))
            client = await stack.enter_async_context(httpx.AsyncClient(base_url=public_origin, timeout=10))
            record = build_team_server_record(team_id, team_did, public_origin, datetime.now(timezone.utc))
            await registry_client.publish_team_server_record(
                domain, "members", record, sign_team_server_record(team_sk, record),
            )
            node = SimpleNamespace(
                domain=domain, team_id=team_id, team_sk=team_sk, team_did=team_did,
                registry=registry, registry_client=registry_client, registry_calls=registry_calls,
                server=server, db=manager, client=client, origin=public_origin, calls=server_calls,
            )
            node.local = await _actor(node, "local", global_identity=False)
            node.global_actor = await _actor(node, "global", global_identity=True)
            nodes.append(node)
        yield SimpleNamespace(source=nodes[0], target=nodes[1], dns=dns_server)


async def _actor(node, alias, *, global_identity):
    sk, _, did = _make_keypair()
    stable, address = "", ""
    if global_identity:
        mapping = await node.registry_client.register_did(did, sk)
        stable, address = mapping.did_aw, f"{node.domain}/{alias}"
        await node.registry.db.execute(
            "INSERT INTO {{tables.public_addresses}} (namespace_id, name, did_aw) "
            "SELECT namespace_id,$2,$3 FROM {{tables.dns_namespaces}} WHERE domain=$1",
            node.domain, alias, stable,
        )
    agent_id, workspace_id = uuid4(), uuid4()
    await node.db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, team_id, alias, did_key, did_aw, did_aw_verified_key, address, identity_scope, inbound_mode) "
        "VALUES ($1,$2,$3,$4,NULLIF($5,''),CASE WHEN $5='' THEN NULL ELSE $4 END,NULLIF($6,''),$7,'open')",
        agent_id, node.team_id, alias, did, stable, address, "global" if stable else "local",
    )
    await node.db.execute(
        "INSERT INTO {{tables.workspaces}} (workspace_id, team_id, agent_id, alias) VALUES ($1,$2,$3,$4)",
        workspace_id, node.team_id, agent_id, alias,
    )
    certificate = _make_certificate(
        node.team_sk, node.team_did, did, team_id=node.team_id, alias=alias,
        member_did_aw=stable, member_address=address, identity_scope="global" if stable else "local",
        certificate_id=str(uuid4()),
    )
    if not global_identity:
        # Match the released Go certificate serialization: absent optional
        # global fields, rather than signed empty strings it cannot preserve.
        for field in ("signature", "member_did_aw", "member_address"):
            certificate.pop(field)
        certificate["signature"] = sign_message(node.team_sk, canonical_json_bytes(certificate))
    encoded = _encode_certificate(certificate)
    await node.registry_client.register_team_certificate(
        node.domain, "members", team_controller_signing_key=node.team_sk,
        certificate_id=certificate["certificate_id"], member_did_key=did,
        member_did_aw=stable or None, member_address=address or None,
        alias=alias, identity_scope=certificate["identity_scope"], certificate=encoded,
    )
    encryption_private, encryption_public = generate_x25519_keypair()
    assertion = build_encryption_key_assertion(
        signing_key=sk, identity_did=did, identity_stable_id=stable or None,
        encryption_public_key=encryption_public, custody="self", now=datetime.now(timezone.utc),
    )
    await _insert_agent_encryption_assertion(
        node.db, agent_id=agent_id, team_id=node.team_id, assertion=assertion,
    )
    return SimpleNamespace(
        node=node, alias=alias, sk=sk, did=did, stable=stable, address=address,
        id=agent_id, workspace=workspace_id, certificate=certificate, encoded_certificate=encoded,
        encryption_private=encryption_private, encryption_key=assertion,
    )


def _submission(sender, target, kind, *, encrypted=False, continuation=None):
    mid, cid = str(uuid4()), continuation or str(uuid4())
    created = datetime.now(timezone.utc).replace(microsecond=0)
    body = f"{kind} {'reply' if continuation else 'first contact'} {mid}"
    to_label = target.address or target.did
    fields = dict(type=kind, from_did=sender.did, to=to_label, to_did=target.did,
                  message_id=mid, conversation_id=cid, timestamp=created.isoformat().replace("+00:00", "Z"), body=body)
    fields["from"] = sender.address or f"{sender.node.team_id}/{sender.alias}"
    if sender.stable:
        fields["from_stable_id"] = sender.stable
    if target.stable:
        fields["to_stable_id"] = target.stable
    if kind == "mail":
        fields.update(subject="Team-vouched return route", priority="normal")
        payload = dict(subject=fields["subject"], body=body, conversation_id=cid)
        payload["to_address" if target.address else "to_did"] = to_label
        path = "/v1/messages"
    else:
        fields["sender_leaving"] = True
        if continuation:
            path = f"/v1/chat/sessions/{cid}/messages"
            payload = dict(body=body, leaving=True)
        else:
            path = "/v1/chat/sessions"
            payload = dict(to_addresses=[to_label], message=body, session_id=cid, leaving=True)
    encoded = canonical_json_bytes(fields).decode()
    payload.update(from_did=sender.did, message_id=mid, timestamp=fields["timestamp"],
                   signed_payload=encoded, signature=sign_message(sender.sk, encoded.encode()))
    envelope = None
    if encrypted:
        def identity(actor):
            return dict(did=actor.did, stable_id=actor.stable, address=actor.address,
                        team_id=actor.node.team_id, signing_key=actor.sk, encryption_key=actor.encryption_key)
        envelope = encrypt_e2ee_message(
            kind=kind, sender=identity(sender), recipients=[identity(target)],
            body=body, subject=fields.get("subject", ""), message_id=mid,
            conversation_id=cid, created_at=created,
        )
        payload.pop("signature")
        payload.pop("signed_payload")
        payload.update(content_mode="encrypted_v2", message_version=2, encrypted_envelope=envelope)
        if kind == "mail":
            payload.update(subject="", body="")
        else:
            payload["body" if continuation else "message"] = ""
    return path, payload, SimpleNamespace(mid=UUID(mid), cid=UUID(cid), fields=fields, envelope=envelope)


async def _send(sender, target, kind, *, encrypted=False, continuation=None):
    path, payload, submitted = _submission(sender, target, kind, encrypted=encrypted, continuation=continuation)
    raw = json.dumps(payload).encode()
    response = await sender.node.client.post(path, content=raw, headers={
        **_signed_team_headers(sender.sk, sender.did, sender.node.team_id, sender.encoded_certificate, raw),
        "Content-Type": "application/json",
    })
    return response, submitted


def _federation_packet(sender, target, kind, *, encrypted=False, continuation=None):
    _, payload, submitted = _submission(sender, target, kind, encrypted=encrypted, continuation=continuation)
    envelope = dict(
        version=1, type=kind, sender_did_aw=sender.stable or sender.did,
        sender_current_did_key=sender.did, sender_delivery_origin=sender.node.origin,
        sender_certificate=sender.encoded_certificate,
        target_did_aw=target.stable or target.did, target_current_did_key=target.did,
        target_address=target.address or target.did, target_delivery_origin=target.node.origin,
        message_id=str(submitted.mid), conversation_id=str(submitted.cid),
        timestamp=submitted.fields["timestamp"], body=payload.get("body", payload.get("message", "")),
    )
    if kind == "mail":
        envelope.update(subject=payload["subject"], priority="normal")
    else:
        envelope["sender_leaving"] = True
    if encrypted:
        envelope.update(content_mode="encrypted_v2", message_version=2, encrypted_envelope=submitted.envelope)
        signature = submitted.envelope["signature"]
    else:
        envelope["signed_payload"] = payload["signed_payload"]
        signature = payload["signature"]
    return dict(envelope=envelope, signature=signature), submitted


async def _effects(node):
    tables = ("messages", "chat_messages", "conversations", "chat_sessions",
              "conversation_participants", "chat_participants", "contacts",
              "message_ingress_receipts", "federation_mutation_outbox")
    return {table: await node.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") for table in tables}


async def _stored(target, kind, submitted):
    table = "messages" if kind == "mail" else "chat_messages"
    row = await target.node.db.fetch_one(
        "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1", submitted.mid,
    )
    assert row is not None
    assert row["conversation_id" if kind == "mail" else "session_id"] == submitted.cid
    assert row["from_did"] == submitted.fields.get("from_stable_id", submitted.fields["from_did"])
    if submitted.envelope is None:
        assert row["body"] == submitted.fields["body"]
        assert json.loads(row["signed_payload"]) == submitted.fields
    else:
        stored = row["encrypted_envelope"]
        assert (json.loads(stored) if isinstance(stored, str) else stored) == submitted.envelope
    return row


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_global_neighbor_through_real_dns(route_pair, kind, encrypted):
    pair = route_pair
    response, sent = await _send(pair.source.global_actor, pair.target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    await _stored(pair.target.global_actor, kind, sent)
    assert pair.dns.queries[(f"_awid.{pair.target.domain}", "TXT")] > 0
    assert pair.dns.queries[(f"_awid.{pair.source.domain}", "TXT")] > 0
    assert pair.target.calls.count(("POST", "/v1/federation/messages")) == 1
    assert ("POST", "/v1/federation/messages") not in pair.source.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_local_first_contact_and_global_reply(route_pair, kind, encrypted):
    pair = route_pair
    response, sent = await _send(pair.source.local, pair.target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    await _stored(pair.target.global_actor, kind, sent)
    sender = await pair.target.db.fetch_one(
        "SELECT * FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
        sent.cid, pair.source.local.did,
    )
    assert sender["address"] is None
    assert sender["route_team_id"] == pair.source.team_id
    assert sender["route_certificate_id"] == pair.source.local.certificate["certificate_id"]
    assert sender["route_certificate"] == pair.source.local.encoded_certificate
    assert sender["delivery_origin"] == pair.source.origin
    response, reply = await _send(pair.target.global_actor, pair.source.local, kind,
                                  encrypted=encrypted, continuation=str(sent.cid))
    assert response.status_code == 200, response.text
    await _stored(pair.source.local, kind, reply)
    assert pair.dns.queries[(f"_awid.{pair.source.domain}", "TXT")] > 0
    assert pair.target.calls.count(("POST", "/v1/federation/messages")) == 1
    assert pair.source.calls.count(("POST", "/v1/federation/messages")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_team_vouched_ingress_and_exact_receipt(route_pair, kind, encrypted):
    """Independently exercise ingress, beyond the source's label checks."""
    pair = route_pair
    packet, submitted = _federation_packet(pair.source.local, pair.target.global_actor, kind, encrypted=encrypted)
    response = await pair.target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 200, response.text
    await _stored(pair.target.global_actor, kind, submitted)
    before = await _effects(pair.target)
    registry_reads = list(pair.source.registry_calls)
    dns_reads = dict(pair.dns.queries)
    # Removing DNS and revoking membership cannot undo an established receipt.
    await pair.source.registry.revoke(pair.source.local.certificate["certificate_id"])
    pair.dns.records.clear()
    repeated = await pair.target.client.post("/v1/federation/messages", json=packet)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json() == response.json()
    assert await _effects(pair.target) == before
    assert pair.source.registry_calls == registry_reads
    assert dict(pair.dns.queries) == dns_reads
    # Certificate substitution with exactly the same signed message conflicts.
    changed = json.loads(json.dumps(packet))
    cert = dict(pair.source.local.certificate, certificate_id=str(uuid4()))
    cert.pop("signature")
    cert["signature"] = sign_message(pair.source.team_sk, canonical_json_bytes(cert))
    changed["envelope"]["sender_certificate"] = _encode_certificate(cert)
    conflict = await pair.target.client.post("/v1/federation/messages", json=changed)
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["reason"] == "federation_message_replay_conflict"
    assert await _effects(pair.target) == before
    assert pair.source.registry_calls == registry_reads


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("fault,reason,status", [
    ("missing", "local_sender_certificate_required", 422),
    ("invalid", "local_sender_certificate_invalid", 422),
    ("team-swap", "local_sender_certificate_invalid", 422),
    ("revoked", "local_sender_certificate_revoked", 403),
    ("old-team-key", "local_sender_team_key_stale", 409),
    ("no-record", "local_sender_team_server_missing", 424),
    ("self-record", "local_sender_route_mismatch", 422),
    ("policy", "recipient_policy_rejected", 403),
])
async def test_team_route_ingress_refuses_without_effects(route_pair, kind, encrypted, fault, reason, status):
    pair = route_pair
    source, target = pair.source, pair.target
    packet, _ = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
    if fault == "missing":
        packet["envelope"].pop("sender_certificate")
    elif fault == "invalid":
        packet["envelope"]["sender_certificate"] = "not-a-certificate"
    elif fault == "team-swap":
        # Same namespace, member, alias and certificate ID; different full team.
        other_sk, _, other_did = _make_keypair()
        other_team = f"other:{source.domain}"
        await source.registry.add_team(other_team, other_did, visibility="private")
        forged = _make_certificate(
            other_sk, other_did, source.local.did, team_id=other_team, alias=source.local.alias,
            certificate_id=source.local.certificate["certificate_id"], identity_scope="local",
        )
        await source.registry_client.register_team_certificate(
            source.domain, "other", team_controller_signing_key=other_sk,
            certificate_id=forged["certificate_id"], member_did_key=source.local.did,
            member_did_aw=None, member_address=None, alias=source.local.alias,
            identity_scope="local", certificate=_encode_certificate(forged),
        )
        record = build_team_server_record(other_team, other_did, source.origin, datetime.now(timezone.utc))
        await source.registry_client.publish_team_server_record(
            source.domain, "other", record, sign_team_server_record(other_sk, record),
        )
        packet["envelope"]["sender_certificate"] = _encode_certificate(forged)
    elif fault == "revoked":
        await source.registry.revoke(source.local.certificate["certificate_id"])
    elif fault == "old-team-key":
        _, _, new_team_key = _make_keypair()
        await source.registry.rotate_team_key(source.team_id, new_team_key)
    elif fault in {"no-record", "self-record"}:
        await source.registry.db.execute("DELETE FROM {{tables.team_server_records}}")
        if fault == "self-record":
            record = build_team_server_record(source.team_id, source.team_did, target.origin, datetime.now(timezone.utc))
            await source.registry_client.publish_team_server_record(
                source.domain, "members", record, sign_team_server_record(source.team_sk, record),
            )
            packet["envelope"]["sender_delivery_origin"] = target.origin
    elif fault == "policy":
        await target.db.execute("UPDATE {{tables.agents}} SET inbound_mode='contacts_only' WHERE agent_id=$1", target.global_actor.id)
    before = await _effects(target)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == status, response.text
    assert response.json().get("reason") == reason, response.text
    assert response.json()["retryable"] is False
    if fault != "policy":
        next_steps = {"missing": "Upgrade aw", "invalid": "fetch-cert", "team-swap": "fetch-cert",
                      "revoked": "no longer a member", "old-team-key": "reissue", "no-record": "set-server",
                      "self-record": "show-server"}
        assert next_steps[fault] in response.json()["detail"], response.text
    assert await _effects(target) == before
    assert ("POST", "/v1/federation/messages") not in source.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_hosted_hook_retains_exact_certificate(kind, encrypted):
    """Real custodial signatures/encryption, preserving the exact opaque proof."""
    from aweb.mcp.signing import encrypt_hosted_message, sign_hosted_message
    team_sk, _, team_did = _make_keypair()
    node = SimpleNamespace(team_id="members:hook.test", team_sk=team_sk, team_did=team_did)
    def actor(alias):
        sk, _, did = _make_keypair()
        _, public = generate_x25519_keypair()
        return SimpleNamespace(node=node, alias=alias, sk=sk, did=did, stable="", address="",
                               encryption_key=build_encryption_key_assertion(
                                   signing_key=sk, identity_did=did, identity_stable_id=None,
                                   encryption_public_key=public, now=datetime.now(timezone.utc)))
    sender, target = actor("alice"), actor("bob")
    certificate = _encode_certificate(_make_certificate(
        team_sk, team_did, sender.did, team_id=node.team_id, alias=sender.alias, identity_scope="local"))
    _, payload, submitted = _submission(sender, target, kind, encrypted=encrypted)
    auth = SimpleNamespace(trusted_proxy=True, workspace_id=str(uuid4()), agent_id=str(uuid4()),
                           team_id=node.team_id, did_key=sender.did)
    if encrypted:
        async def encryptor(**kwargs):
            return dict(encrypted_envelope=submitted.envelope, content_mode="encrypted_v2",
                        message_version=2, sender_certificate=certificate)
        result = await encrypt_hosted_message(auth=auth, encryptor=encryptor, message_type=kind,
                                              payload=submitted.fields, recipient={"did_key": target.did})
    else:
        async def signer(**kwargs):
            return dict(from_did=sender.did, signed_payload=payload["signed_payload"],
                        signature=payload["signature"], sender_certificate=certificate)
        result = await sign_hosted_message(auth=auth, signer=signer, message_type=kind, payload=submitted.fields)
    assert result.sender_certificate == certificate


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_recipient_reads_team_vouched_author(route_pair, kind, encrypted):
    from test_messages_http import _signed_identity_headers
    pair, target = route_pair, route_pair.target.global_actor
    response, submitted = await _send(pair.source.local, target, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    path = "/v1/messages/inbox" if kind == "mail" else f"/v1/chat/sessions/{submitted.cid}/messages"
    read = await target.node.client.get(path, headers=_signed_identity_headers(target.sk, target.did, target.stable))
    assert read.status_code == 200, read.text
    message = next(item for item in read.json()["messages"] if item["message_id"] == str(submitted.mid))
    assert message["from_did"] == pair.source.local.did
    assert message["sender_membership"] == dict(team_id=pair.source.team_id, member_did_aw=None, state="active")
    assert message.get("from_alias", message.get("from_agent")) == pair.source.local.alias
    assert not message.get("from_address")
    if not encrypted:
        assert message["body"] == submitted.fields["body"]
        assert json.loads(message["signed_payload"]) == submitted.fields
    else:
        assert message["encrypted_envelope"] == submitted.envelope


async def _expire_team_evidence(node):
    # Delete only this fixture's real shared cache; no resolver/clock substitution.
    await node.db.execute("DELETE FROM {{tables.federation_authority_results}} WHERE scope_key LIKE 'team-route:%'")


async def _route_rows(node, cid, did):
    return [await node.db.fetch_one(
        "SELECT did,address,delivery_origin,route_team_id,route_certificate_id,route_certificate "
        "FROM {{tables." + table + "}} WHERE " + key + "=$1 AND did=$2", cid, did,
    ) for table, key in (("conversation_participants", "conversation_id"), ("chat_participants", "session_id"))]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("label", ["alias", "legacy-address"])
async def test_released_local_labels_still_deliver_locally(route_pair, kind, label):
    node = route_pair.source
    sender, target = node.local, node.global_actor
    path, payload, sent = _submission(sender, target, kind)
    sent.fields["from"] = sender.alias if label == "alias" else f"{node.domain}/{sender.alias}"
    payload["signed_payload"] = canonical_json_bytes(sent.fields).decode()
    payload["signature"] = sign_message(sender.sk, payload["signed_payload"].encode())
    raw = json.dumps(payload).encode()
    response = await node.client.post(path, content=raw, headers={
        **_signed_team_headers(sender.sk, sender.did, node.team_id, sender.encoded_certificate, raw),
        "Content-Type": "application/json",
    })
    assert response.status_code == 200, response.text
    await _stored(target, kind, sent)
    assert ("POST", "/v1/federation/messages") not in node.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("fault", ["revoked", "record-gone", "own-nonresident"])
async def test_reply_revalidates_team_route_without_effects(route_pair, kind, encrypted, fault):
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    if fault == "revoked":
        await source.registry.revoke(source.local.certificate["certificate_id"])
    else:
        await source.registry.db.execute("DELETE FROM {{tables.team_server_records}}")
        if fault == "own-nonresident":
            record = build_team_server_record(source.team_id, source.team_did, target.origin, datetime.now(timezone.utc))
            await source.registry_client.publish_team_server_record(
                source.domain, "members", record, sign_team_server_record(source.team_sk, record),
            )
    await _expire_team_evidence(target)
    before = await _effects(target), await _effects(source)
    routes = await _route_rows(target, first.cid, source.local.did)
    posts = (source.calls.count(("POST", "/v1/federation/messages")), target.calls.count(("POST", "/v1/federation/messages")))
    response, _ = await _send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=str(first.cid))
    assert response.status_code == 404, response.text
    assert response.json().get("reason") == "local_recipient_route_missing", response.text
    assert response.json()["retryable"] is False
    assert (await _effects(target), await _effects(source)) == before
    assert await _route_rows(target, first.cid, source.local.did) == routes
    assert (source.calls.count(("POST", "/v1/federation/messages")), target.calls.count(("POST", "/v1/federation/messages"))) == posts


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_same_origin_certificate_reissue_persists_exact_proof(route_pair, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    old = source.local.certificate
    await source.registry.revoke(old["certificate_id"])
    cert = _make_certificate(source.team_sk, source.team_did, source.local.did,
        team_id=source.team_id, alias=source.local.alias, identity_scope="local", certificate_id=str(uuid4()))
    encoded = _encode_certificate(cert)
    await source.registry_client.register_team_certificate(
        source.domain, "members", team_controller_signing_key=source.team_sk,
        certificate_id=cert["certificate_id"], member_did_key=source.local.did,
        member_did_aw=None, member_address=None, alias=source.local.alias, identity_scope="local", certificate=encoded,
    )
    source.local.certificate, source.local.encoded_certificate = cert, encoded
    await _expire_team_evidence(source)
    await _expire_team_evidence(target)
    response, renewed = await _send(source.local, target.global_actor, kind, encrypted=encrypted, continuation=str(first.cid))
    assert response.status_code == 200, response.text
    await _stored(target.global_actor, kind, renewed)
    for row in await _route_rows(target, first.cid, source.local.did):
        if row is None:
            assert kind == "mail"
            continue
        assert row["route_certificate_id"] == cert["certificate_id"]
        assert row["route_certificate"] == encoded
        assert row["delivery_origin"] == source.origin
    response, reply = await _send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=str(first.cid))
    assert response.status_code == 200, response.text
    await _stored(source.local, kind, reply)


async def _publish_server(node, origin):
    await node.registry.db.execute("DELETE FROM {{tables.team_server_records}}")
    record = build_team_server_record(node.team_id, node.team_did, origin, datetime.now(timezone.utc))
    await node.registry_client.publish_team_server_record(
        node.domain, "members", record, sign_team_server_record(node.team_sk, record),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_reply_follows_moved_server_and_persists_only_on_acceptance(route_pair, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    sock = _socket()
    moved = _origin(sock)
    # Same deployment under a new public URL: real listener, same stored thread.
    source.server.app.state.federation_public_origins = [moved]
    async with _listener(source.server.app, sock):
        await _publish_server(source, moved)
        await _expire_team_evidence(target)
        response, reply = await _send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=str(first.cid))
        assert response.status_code == 200, response.text
        await _stored(source.local, kind, reply)
        for row in await _route_rows(target, first.cid, source.local.did):
            if row is None:
                assert kind == "mail"
                continue
            assert row["delivery_origin"] == moved
            assert row["route_certificate"] == source.local.encoded_certificate
        assert source.calls.count(("POST", "/v1/federation/messages")) == 1
        assert target.calls.count(("POST", "/v1/federation/messages")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_reply_own_team_route_resident_delivers_and_reads_locally(route_pair, kind, encrypted):
    from test_messages_http import _signed_identity_headers
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    # Admit the exact key on this deployment; historical remote actor stays NULL.
    resident_id = uuid4()
    await target.db.execute(
        "INSERT INTO {{tables.agents}} (agent_id,team_id,alias,did_key,identity_scope,inbound_mode) "
        "VALUES ($1,$2,'moved',$3,'local','open')", resident_id, target.team_id, source.local.did,
    )
    await _insert_agent_encryption_assertion(target.db, agent_id=resident_id, team_id=target.team_id,
                                             assertion=source.local.encryption_key)
    moved_cert = _make_certificate(target.team_sk, target.team_did, source.local.did,
        team_id=target.team_id, alias="moved", identity_scope="local", certificate_id=str(uuid4()))
    moved_encoded = _encode_certificate(moved_cert)
    await target.registry_client.register_team_certificate(
        target.domain, "members", team_controller_signing_key=target.team_sk,
        certificate_id=moved_cert["certificate_id"], member_did_key=source.local.did,
        member_did_aw=None, member_address=None, alias="moved", identity_scope="local", certificate=moved_encoded,
    )
    await _publish_server(source, target.origin)
    await _expire_team_evidence(target)
    response, reply = await _send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=str(first.cid))
    assert response.status_code == 200, response.text
    await _stored(SimpleNamespace(node=target), kind, reply)
    path = "/v1/messages/inbox" if kind == "mail" else f"/v1/chat/sessions/{first.cid}/messages"
    read = await target.client.get(path, headers=_signed_team_headers(source.local.sk, source.local.did, target.team_id, moved_encoded))
    assert read.status_code == 200, read.text
    assert any(message["message_id"] == str(reply.mid) for message in read.json()["messages"])
    assert ("POST", "/v1/federation/messages") not in source.calls
    assert target.calls.count(("POST", "/v1/federation/messages")) == 1
    for row in await _route_rows(target, first.cid, source.local.did):
        if row is not None:
            assert row["delivery_origin"] == target.origin


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("mode", ["team_and_contacts", "contacts_only"])
async def test_team_route_continuation_rechecks_open_policy(route_pair, kind, encrypted, mode):
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    await target.db.execute("UPDATE {{tables.agents}} SET inbound_mode=$1 WHERE agent_id=$2", mode, target.global_actor.id)
    before = await _effects(target)
    routes = await _route_rows(target, first.cid, source.local.did)
    response, _ = await _send(source.local, target.global_actor, kind, encrypted=encrypted, continuation=str(first.cid))
    assert response.status_code == 403, response.text
    assert "recipient_policy_rejected" in response.text
    assert await _effects(target) == before
    assert await _route_rows(target, first.cid, source.local.did) == routes


async def _hosted_mcp_send(sender, target, kind, *, encrypted, continuation=None):
    from aweb.internal_auth import build_internal_auth_header_value
    from aweb.mcp.server import create_mcp_app
    node = sender.node
    async def signer(**kwargs):
        raw = canonical_json_bytes(kwargs["payload"]).decode()
        return dict(from_did=sender.did, signed_payload=raw, signature=sign_message(sender.sk, raw.encode()),
                    sender_certificate=sender.encoded_certificate)
    async def encryptor(**kwargs):
        fields = kwargs["payload"]
        def identity(actor):
            return dict(did=actor.did, stable_id=actor.stable, address=actor.address,
                        team_id=actor.node.team_id, signing_key=actor.sk, encryption_key=actor.encryption_key)
        envelope = encrypt_e2ee_message(kind=kind, sender=identity(sender), recipients=[identity(target)],
            body=fields["body"], subject=fields.get("subject", ""), message_id=fields["message_id"],
            conversation_id=fields["conversation_id"],
            created_at=datetime.fromisoformat(fields["timestamp"].replace("Z", "+00:00")))
        return dict(content_mode="encrypted_v2", message_version=2, encrypted_envelope=envelope,
                    sender_certificate=sender.encoded_certificate)
    mcp = create_mcp_app(db_infra=node.server.db, redis=node.server.app.state.redis,
        registry_client=node.server.app.state.awid_registry_client,
        federation_authority=node.server.app.state.federation_authority,
        hosted_signer=signer, hosted_encryptor=encryptor, public_origin=node.origin)
    mount = "/actf-mcp-" + uuid4().hex
    node.server.app.mount(mount, mcp)
    await mcp.startup()
    try:
        args = dict(body="Hosted team route", plaintext=not encrypted) if kind == "mail" else dict(message="Hosted team route", plaintext=not encrypted, leaving=True)
        if continuation:
            args["conversation_id" if kind == "mail" else "session_id"] = continuation
        else:
            args["to" if kind == "mail" else "to_address"] = target.address
        raw = json.dumps(dict(jsonrpc="2.0", id=1, method="tools/call", params=dict(
            name="send_mail" if kind == "mail" else "chat_send", arguments=args))).encode()
        principal = str(uuid4())
        response = await node.client.post(mount+"/", content=raw, headers={
            "X-Team-ID": node.team_id, "X-User-ID": principal, "X-AWEB-Actor-ID": str(sender.id),
            "X-AWEB-Auth": build_internal_auth_header_value(secret="disposable-actf-proxy-secret", team_id=node.team_id,
                principal_type="u", principal_id=principal, actor_id=str(sender.id)),
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
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_hosted_mcp_team_route_round_trip(route_pair, monkeypatch, kind, encrypted):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "disposable-actf-proxy-secret")
    source, target = route_pair.source, route_pair.target
    first = await _hosted_mcp_send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert "error" not in first, first
    cid = first["conversation_id"]
    table = "messages" if kind == "mail" else "chat_messages"
    received = await target.db.fetch_one("SELECT * FROM {{tables."+table+"}} WHERE message_id=$1", UUID(first["message_id"]))
    assert received["from_did"] == source.local.did
    if not encrypted:
        assert json.loads(received["signed_payload"])["from"] == f"{source.team_id}/{source.local.alias}"
    reply = await _hosted_mcp_send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=cid)
    assert "error" not in reply, reply
    received = await source.db.fetch_one("SELECT * FROM {{tables."+table+"}} WHERE message_id=$1", UUID(reply["message_id"]))
    assert received["from_did"] == target.global_actor.stable
    answer = await _hosted_mcp_send(source.local, target.global_actor, kind, encrypted=encrypted, continuation=cid)
    assert "error" not in answer, answer
    assert await target.db.fetch_value("SELECT count(*) FROM {{tables."+table+"}} WHERE message_id=$1", UUID(answer["message_id"])) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_hosted_mcp_reply_refuses_revoked_route_with_typed_error(route_pair, monkeypatch, kind, encrypted):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "disposable-actf-proxy-secret")
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    await source.registry.revoke(source.local.certificate["certificate_id"])
    await _expire_team_evidence(target)
    before = await _effects(source), await _effects(target)
    routes = await _route_rows(target, first.cid, source.local.did)
    reply = await _hosted_mcp_send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=str(first.cid))
    assert reply.get("reason") == "local_recipient_route_missing", reply
    assert reply["retryable"] is False
    assert (await _effects(source), await _effects(target)) == before
    assert await _route_rows(target, first.cid, source.local.did) == routes
    assert not source.calls.count(("POST", "/v1/federation/messages"))


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_reply_move_without_conversation_refuses_no_backfill(route_pair, test_db_factory, monkeypatch, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    db = await test_db_factory.create_db(suffix="actf_moved_empty")
    await db.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
    sock = _socket()
    origin = _origin(sock)
    monkeypatch.setenv("AWID_REGISTRY_URL", source.registry_client.registry_url)
    async with running_server(db.config.get_dsn(), source.server.app.state.redis,
                              awid_transport=httpx.AsyncHTTPTransport(), public_origin=origin) as server:
        calls = _observe(server.app)
        async with _listener(server.app, sock):
            moved = SimpleNamespace(db=server.db.get_manager("aweb"))
            before_moved = await _effects(moved)
            await _publish_server(source, origin)
            await _expire_team_evidence(target)
            routes = await _route_rows(target, first.cid, source.local.did)
            before = await _effects(target)
            response, _ = await _send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=str(first.cid))
            assert response.status_code == 404, response.text
            assert response.json().get("reason") == "local_recipient_route_missing", response.text
            assert response.json()["retryable"] is False
            assert await _effects(moved) == before_moved
            assert await _effects(target) == before
            assert await _route_rows(target, first.cid, source.local.did) == routes
            assert calls.count(("POST", "/v1/federation/messages")) == 1
            assert not source.calls.count(("POST", "/v1/federation/messages"))


@pytest.mark.asyncio
async def test_team_evidence_expiring_during_real_database_wait_is_reread(route_pair):
    source, target = route_pair.source, route_pair.target
    packet, first = _federation_packet(source.local, target.global_actor, "mail")
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 200, response.text
    status_path = f"/v1/namespaces/{source.domain}/teams/members/certificates/{source.local.certificate['certificate_id']}/status"
    reads = source.registry_calls.count(("GET", status_path))
    # A new message uses warm proof while still repeating signature and policy.
    warm, _ = _federation_packet(source.local, target.global_actor, "mail", continuation=str(first.cid))
    response = await target.client.post("/v1/federation/messages", json=warm)
    assert response.status_code == 200, response.text
    assert source.registry_calls.count(("GET", status_path)) == reads
    before = await _effects(target)
    routes = await _route_rows(target, first.cid, source.local.did)
    next_packet, _ = _federation_packet(source.local, target.global_actor, "mail", continuation=str(first.cid))
    # Age the real evidence first; the lock itself stays within the ordinary
    # five-second database limit while spanning the sixty-second cache bound.
    await asyncio.sleep(58)
    pending = None
    try:
        async with target.db.transaction() as lock:
            await lock.fetch_one("SELECT conversation_id FROM {{tables.conversations}} WHERE conversation_id=$1 FOR UPDATE", first.cid)
            pending = asyncio.create_task(target.client.post("/v1/federation/messages", json=next_packet, timeout=85))
            for _ in range(200):
                waiting = await target.db.fetch_value(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                    "AND wait_event_type='Lock' AND query LIKE '%conversations%' AND pid<>pg_backend_pid()")
                if waiting:
                    break
                await asyncio.sleep(.05)
            assert waiting, "the real admission never reached the held conversation lock"
            await source.registry.revoke(source.local.certificate["certificate_id"])
            # Actual wall time: no clock replacement or fabricated authority evidence.
            await asyncio.sleep(3)
        response = await pending
        assert response.status_code == 403, response.text
        assert response.json()["reason"] == "local_sender_certificate_revoked"
        assert source.registry_calls.count(("GET", status_path)) > reads
        assert await _effects(target) == before
        assert await _route_rows(target, first.cid, source.local.did) == routes
    finally:
        if pending is not None and not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)



def _reader_home(actor, root):
    from test_cli_human_reply import _pem
    home = root / ".aw"
    home.mkdir(parents=True, mode=0o700)
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    (home / "identity.yaml").write_text(json.dumps(dict(
        did=actor.did, stable_id=actor.stable, address=actor.address,
        custody="self", identity_scope="global" if actor.stable else "local")))
    (home / "certificate.json").write_text(json.dumps(actor.certificate))
    membership = dict(team_id=actor.node.team_id, alias=actor.alias, cert_path="certificate.json")
    (home / "teams.yaml").write_text(json.dumps(dict(active_team=actor.node.team_id, memberships=[membership])))
    (home / "workspace.yaml").write_text(json.dumps(dict(aweb_url=actor.node.origin,
        memberships=[dict(membership, workspace_id=str(actor.workspace))])))
    _pem(home / "encryption.key", "X25519 PRIVATE KEY", actor.encryption_private)
    assertion = actor.encryption_key
    (home / "assertion.json").write_text(json.dumps(assertion))
    (home / "encryption.yaml").write_text(json.dumps(dict(active_key_id=assertion["encryption_key_id"], keys=[dict(
        key_id=assertion["encryption_key_id"], public_key=assertion["encryption_public_key"],
        private_key_path="encryption.key", assertion_path="assertion.json",
        **{key: assertion[key] for key in ("created_at", "not_before", "expires_at")})])))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AW_", "AWEB_", "AWID_", "OATS_"))}
    env.update(HOME=str(root), XDG_CONFIG_HOME=str(root / "config"), AW_NO_UPDATE_CHECK="1",
               AWEB_IDENTITY_HOME=str(home), AWID_REGISTRY_URL=actor.node.registry_client.registry_url)
    return home, env


async def _cli(binary, home, env, *args):
    process = await asyncio.create_subprocess_exec(str(binary), "--identity-home", str(home), *args,
        cwd=home.parent, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await asyncio.wait_for(process.communicate(), 30)
    assert process.returncode == 0, out.decode() + err.decode()
    return json.loads(out)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("reader", ["source", "released"])
async def test_cli_reads_team_vouched_message_as_verified(route_pair, request, tmp_path, kind, encrypted, reader):
    if reader == "released":
        binary = os.environ.get("AW_TEST_RELEASED_CLI_BINARY")
        if not binary:
            pytest.skip("set AW_TEST_RELEASED_CLI_BINARY to a pre-actf release")
    else:
        binary = request.getfixturevalue("source_cli_binary")
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    home, env = _reader_home(target.global_actor, tmp_path)
    args = ["mail", "inbox"] if kind == "mail" else ["chat", "history", "--session-id", str(first.cid)]
    result = await _cli(binary, home, env, *args, "--json")
    message = next(item for item in result["messages"] if item["message_id"] == str(first.mid))
    assert message["verification_status"] == "verified", message
    assert message["body"] == first.fields["body"]
    assert message["from_did"] == source.local.did


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_released_channel_presents_team_vouched_message_as_verified(route_pair, tmp_path, kind, encrypted):
    package = os.environ.get("AW_TEST_RELEASED_CHANNEL_ROOT")
    binary = os.environ.get("AW_TEST_RELEASED_CLI_BINARY")
    if not package or not binary:
        pytest.skip("set AW_TEST_RELEASED_CHANNEL_ROOT and AW_TEST_RELEASED_CLI_BINARY to released artifacts")
    source, target = route_pair.source, route_pair.target
    home, env = _reader_home(target.global_actor, tmp_path)
    env.update(AWEB_DELIVERY="channel", AW_BIN=binary)
    process = await asyncio.create_subprocess_exec("node", str(Path(package) / "dist/index.js"),
        cwd=tmp_path, env=env, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    errors = asyncio.create_task(process.stderr.read())
    async def write(value):
        process.stdin.write((json.dumps(value)+"\n").encode())
        await process.stdin.drain()
    async def read():
        line = await asyncio.wait_for(process.stdout.readline(), 20)
        assert line, (await errors).decode()
        return json.loads(line)
    try:
        await write(dict(jsonrpc="2.0", id=1, method="initialize", params=dict(
            protocolVersion="2024-11-05", capabilities={}, clientInfo=dict(name="actf-real-reader", version="1"))))
        initialized = await read()
        assert initialized.get("id") == 1 and "result" in initialized, initialized
        await write(dict(jsonrpc="2.0", method="notifications/initialized"))
        response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
        assert response.status_code == 200, response.text
        while True:
            notification = await read()
            if notification.get("method") != "notifications/claude/channel":
                continue
            params = notification["params"]
            if params.get("meta", {}).get("message_id") == str(first.mid):
                break
        assert params["meta"]["verified"] == "true", params
        assert params["meta"]["trust_status"] == "verified", params
        assert params["content"] == first.fields["body"], params
    finally:
        if process.returncode is None:
            process.stdin.close()
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 2)
            except TimeoutError:
                process.kill()
        await process.wait()
        stderr = (await errors).decode()
        assert "fatal:" not in stderr, stderr


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_real_cli_team_route_first_reply_answer(route_pair, source_cli_binary, tmp_path, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    home, env = _reader_home(source.local, tmp_path / "sender")
    # CLI target discovery uses the target's actual public registry. Servers
    # still select the sender's separate registry through actual _awid DNS.
    env["AWID_REGISTRY_URL"] = target.registry_client.registry_url
    body = tmp_path / "body.txt"
    body.write_text("Real CLI team-vouched first contact")
    args = (["mail", "send", "--to-address", target.global_actor.address, "--subject", "CLI"]
            if kind == "mail" else ["chat", "send-and-leave", target.global_actor.address])
    if not encrypted:
        args.append("--plaintext")
    sent = await _cli(source_cli_binary, home, env, *args, "--body-file", str(body), "--json")
    cid = sent.get("conversation_id", sent.get("session_id"))
    assert cid, sent
    response, reply = await _send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=cid)
    assert response.status_code == 200, response.text
    read_args = ["mail", "inbox"] if kind == "mail" else ["chat", "history", "--session-id", cid]
    read = await _cli(source_cli_binary, home, env, *read_args, "--json")
    message = next(row for row in read["messages"] if row["message_id"] == str(reply.mid))
    assert message["verification_status"] == "verified", message
    body.write_text("Real CLI continued answer")
    args = (["mail", "send", "--conversation-id", cid] if kind == "mail"
            else ["chat", "send", "--session-id", cid])
    if not encrypted:
        args.append("--plaintext")
    answer = await _cli(source_cli_binary, home, env, *args, "--body-file", str(body), "--json")
    table = "messages" if kind == "mail" else "chat_messages"
    assert await target.db.fetch_value("SELECT count(*) FROM {{tables."+table+"}} WHERE message_id=$1", UUID(answer["message_id"])) == 1

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
    monkeypatch.delenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", raising=False)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    monkeypatch.setenv("AWEB_LOG_LEVEL", "error")
    token = "actf-disposable-service-token"
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
        encryption_public_key=encryption_public, custody="self_custodial", now=datetime.now(timezone.utc),
    )
    return SimpleNamespace(
        node=node, alias=alias, sk=sk, did=did, stable=stable, address=address,
        id=agent_id, workspace=workspace_id, certificate=certificate, encoded_certificate=encoded,
        encryption_private=encryption_private, encryption_key=assertion,
    )


async def _send(sender, target, kind, *, encrypted=False, continuation=None):
    mid, cid = str(uuid4()), continuation or str(uuid4())
    created = datetime.now(timezone.utc).replace(microsecond=0)
    body = f"{kind} {'reply' if continuation else 'first contact'} {mid}"
    to_label = target.address or target.did
    fields = dict(type=kind, from_did=sender.did, to=to_label, to_did=target.did,
                  message_id=mid, conversation_id=cid, timestamp=created.isoformat(), body=body)
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
    raw = json.dumps(payload).encode()
    response = await sender.node.client.post(path, content=raw, headers={
        **_signed_team_headers(sender.sk, sender.did, sender.node.team_id, sender.encoded_certificate, raw),
        "Content-Type": "application/json",
    })
    return response, SimpleNamespace(mid=UUID(mid), cid=UUID(cid), fields=fields, envelope=envelope)


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

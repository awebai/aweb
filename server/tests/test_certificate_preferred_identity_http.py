"""Exercise the embedding policy through signed native mail and chat routes."""

import asyncio
import json
from contextlib import aclosing
from datetime import datetime, timedelta, timezone
from time import monotonic
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import Request
from nacl.signing import SigningKey

from awid.did import did_key_from_signing_key
from awid.id_certificates import (
    encode_id_chain_header,
    id_certificate_id,
    sign_id_certificate,
)
from awid.registry import CachedRegistryClient
from awid.signing import canonical_json_bytes, sign_message

from aweb import identity_auth_deps
from aweb.application_state import application_registry_client
from aweb.identity_binding import identity_binding_cache
from aweb.team_auth_deps import (
    IdentityEvidencePolicy,
    read_team_member_snapshot,
    resolve_team_membership,
    verify_request_certificate,
)
from messaging_actor_support import (
    admit_messaging_actor,
    issue_global_certificate_to_local_member,
    messaging_actor_headers,
)
from test_dashboard_privacy import TEAM, privacy_app
from test_id_chain_request_auth import ROOT, _signed_fixture_certificate


__all__ = ["privacy_app"]


def mount_policy(env, monkeypatch):
    live_kinds = []

    async def mounted_identity(request: Request, db):
        if request.method != "POST":
            return await native_identity(request, db)
        checked = await verify_request_certificate(
            request,
            db,
            identity_evidence=IdentityEvidencePolicy.PREFER_LIVE,
        )
        live_kinds.append(checked["identity_kind"])
        snapshot = await read_team_member_snapshot(env.db, checked, request=request)
        resolved = await resolve_team_membership(
            env.db, checked, request=request, snapshot=snapshot
        )
        return resolved.identity

    native_identity = identity_auth_deps.get_team_identity
    monkeypatch.setattr(identity_auth_deps, "get_team_identity", mounted_identity)
    return live_kinds


def identity_chain(*certificates):
    return {"v": 1, "type": "aweb.id-chain", "certificates": list(certificates)}


def signer_for(key: SigningKey):
    did = did_key_from_signing_key(bytes(key))
    return lambda message: (did, key.sign(message).signature)


async def sign_revision(certificate, issuer):
    fields = certificate["certificate"]
    next_issue = datetime.fromisoformat(fields["issued_at"]) + timedelta(seconds=1)
    return await sign_id_certificate(
        {**fields, "issued_at": next_issue.strftime("%Y-%m-%dT%H:%M:%SZ")},
        signer=signer_for(issuer),
    )


async def registered_chain(env, registry, actor, *, domain, reissue=None):
    root = SigningKey(bytes.fromhex(ROOT["seed_hex"]))
    await env.registry.ensure_namespace(domain=domain, controller=bytes(root))
    cert = _signed_fixture_certificate(
        "root-agent",
        domain=domain,
        identity=actor.stable_id,
        parent={"kind": "namespace", "id": domain},
        issuer="root",
    )
    parents = []
    issuer = root
    if reissue is not None:
        issuer = SigningKey.generate()
        parent_did = did_key_from_signing_key(bytes(issuer))
        parent_id = (await registry.register_did(parent_did, bytes(issuer))).did_aw
        parent = _signed_fixture_certificate(
            "alice",
            domain=domain,
            identity=parent_id,
            parent={"kind": "namespace", "id": domain},
            issuer="root",
        )
        await registry.register_id_certificate(
            identity_chain(parent),
            signer=signer_for(issuer),
            expected_head=None,
            invitation_id=None,
        )
        parents = [parent]
        cert = await sign_id_certificate(
            {
                **cert["certificate"],
                "issuer_key": parent_did,
                "parent": {"kind": "identity", "id": parent_id},
            },
            signer=signer_for(issuer),
        )
    chain = identity_chain(*parents, cert)
    key = SigningKey(actor.signing_key)
    await registry.register_id_certificate(
        chain,
        signer=signer_for(key),
        expected_head=None,
        invitation_id=None,
    )
    if reissue == "superseded-own":
        current = await sign_revision(cert, issuer)
        await registry.register_id_certificate(
            identity_chain(*parents, current),
            signer=signer_for(key),
            expected_head=id_certificate_id(cert["certificate"]),
            invitation_id=None,
        )
    elif reissue == "superseded-parent":
        current = await sign_revision(parent, root)
        await registry.register_id_certificate(
            identity_chain(current),
            signer=signer_for(issuer),
            expected_head=id_certificate_id(parent["certificate"]),
            invitation_id=None,
        )
    return chain


def signed_message(sender, receiver, *, kind):
    message_id, conversation_id = str(uuid4()), str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    common = {
        "message_id": message_id,
        "timestamp": timestamp,
        "from_did": sender.did_key,
    }
    content = f"signed {kind} with stable sender"
    signed = {
        **common,
        "conversation_id": conversation_id,
        "from_stable_id": sender.stable_id,
        "from": sender.address,
        "to_did": receiver.did_key,
        "body": content,
        "type": kind,
    }
    if kind == "mail":
        path = "/v1/messages"
        request = {
            **common,
            "conversation_id": conversation_id,
            "body": content,
            "to_did": receiver.did_key,
            "subject": "",
        }
        signed["subject"] = ""
    else:
        path = "/v1/chat/sessions"
        request = {
            **common,
            "session_id": conversation_id,
            "message": content,
            "to_dids": [receiver.did_key],
        }
    payload = canonical_json_bytes(signed)
    body = json.dumps(
        {
            **request,
            "signed_payload": payload.decode(),
            "signature": sign_message(sender.signing_key, payload),
        }
    ).encode()
    return path, body


async def sender_projection(env, actor):
    return dict(
        await env.db.fetch_one(
            """
        SELECT did_aw, did_aw_verified_key, address, certificate_id, xmin::text AS revision
        FROM {{tables.agents}} WHERE agent_id=$1
        """,
            UUID(actor.agent_id),
        )
    )


async def serve_messages(env, sender, receiver, chain_header, *, bounded):
    results = []
    for kind in ("mail", "chat"):
        path, body = signed_message(sender, receiver, kind=kind)
        headers = messaging_actor_headers(sender, body=body)
        if chain_header is not None:
            headers["X-AWID-ID-Chain"] = chain_header
        started = monotonic()
        async with asyncio.timeout(3):
            response = await env.client.post(path, content=body, headers=headers)
        if bounded:
            assert 0.9 <= monotonic() - started < 3
        results.append(response)
    return results


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "live",
        "withdrawn",
        "outage",
        "hung",
        "chain-unavailable",
        "superseded-own",
        "superseded-parent",
        "did-missing",
        "rotated",
        "reassigned",
        "malformed",
    ],
)
async def test_preferred_live_certificate_sender_preserves_authority_and_delivery(
    privacy_app,
    monkeypatch,
    scenario,
):
    env = privacy_app
    registry = application_registry_client(env.app.state)
    # The address namespace is not the sender's team namespace, so the owner
    # can withdraw its address without touching the valid team certificate.
    domain = f"sender-address-{uuid4().hex[:8]}.test"
    sender = await admit_messaging_actor(
        env, alias="global-sender", team_id=TEAM, address=f"{domain}/sender"
    )
    receiver = await admit_messaging_actor(
        env, alias="local-receiver", team_id=TEAM, local=True
    )
    superseded = scenario in ("superseded-own", "superseded-parent")
    chain = await registered_chain(
        env,
        registry,
        sender,
        domain=f"issuer-{uuid4().hex[:8]}.test",
        reissue=scenario if superseded else None,
    )
    controller = await env.registry.ensure_namespace(domain=domain)
    if scenario == "withdrawn":
        await registry.delete_address(domain, "sender", controller)
        assert await registry.resolve_address_fresh(domain, "sender") is None
        identity_binding_cache(env.app.state).clear()
        connect = await env.client.post(
            "/v1/connect",
            content=b"{}",
            headers=messaging_actor_headers(sender, body=b"{}"),
        )
        assert connect.status_code == 403, connect.text
        assert connect.json()["detail"] == "identity_binding_mismatch"
    elif scenario == "rotated":
        new_key = bytes(SigningKey.generate())
        await registry.rotate_key(
            sender.stable_id,
            did_key_from_signing_key(new_key),
            sender.signing_key,
            new_key,
        )
    elif scenario == "reassigned":
        other = await registry.register_did(receiver.did_key, receiver.signing_key)
        await registry.reassign_address(domain, "sender", other.did_aw, controller)
        assert (
            await registry.resolve_address_fresh(domain, "sender")
        ).did_aw == other.did_aw

    # Use the serving SDK's real Redis cache for required team authority. The
    # fault injector is at the registry transport, after all product setup.
    async with aclosing(
        CachedRegistryClient(
            registry_url=registry.registry_url,
            redis_client=env.redis,
            transport=env.registry.transport,
            service_token=registry.service_token,
            domain_verifier=env.registry.namespace_authority,
        )
    ) as cached:
        monkeypatch.setattr(env.app.state, "awid_registry_client", cached)
        team_name, team_domain = TEAM.split(":", 1)
        assert await cached.get_team(team_domain, team_name) is not None
        await cached.get_team_revocations(team_domain, team_name)
        identity_binding_cache(
            env.app.state
        ).clear()  # Expire positive proof from connect.
        live_kinds = mount_policy(env, monkeypatch)
        before = await sender_projection(env, sender)
        if superseded:
            connect_headers = messaging_actor_headers(sender, body=b"{}")
            connect_headers["X-AWID-ID-Chain"] = encode_id_chain_header(chain)
            connect = await env.client.post(
                "/v1/connect", content=b"{}", headers=connect_headers
            )
            assert connect.status_code == 403, connect.text
            assert connect.json()["detail"] == "superseded_certificate"
            assert "aw id parent refresh" in connect.json()["message"]
        calls = len(env.registry.transport.calls)
        env.registry.transport.down = scenario == "outage"
        env.registry.transport.delay = 10 if scenario == "hung" else 0
        if scenario in ("chain-unavailable", "did-missing"):

            def registry_fault(request, response):
                if (
                    scenario == "did-missing"
                    and request.url.path == f"/v1/did/{sender.stable_id}/key"
                ):
                    return httpx.Response(
                        404,
                        json={
                            "detail": "DID not found",
                            "id_tree": {"enrolled": False},
                        },
                    )
                if (
                    scenario == "chain-unavailable"
                    and request.method == "POST"
                    and "id-certificates" in request.url.path
                ):
                    return httpx.Response(
                        503, json={"detail": "temporarily unavailable"}
                    )
                return None

            env.registry.transport.fault = registry_fault
        try:
            mail, chat = await serve_messages(
                env,
                sender,
                receiver,
                "invalid!"
                if scenario == "malformed"
                else encode_id_chain_header(chain),
                bounded=scenario == "hung",
            )
        finally:
            env.registry.transport.down = False
            env.registry.transport.delay = 0
            env.registry.transport.fault = None
        if scenario in ("outage", "hung"):
            aborted = env.registry.transport.calls[calls:]
            assert any(sender.stable_id in call.url.path for call in aborted)
        refusal = {
            "rotated": (403, "identity_binding_mismatch"),
            "reassigned": (403, "identity_binding_mismatch"),
            "malformed": (403, "invalid_encoding"),
            "did-missing": (403, "identity_binding_mismatch"),
            "superseded-own": (403, "superseded_certificate"),
            "superseded-parent": (403, "superseded_certificate"),
            "chain-unavailable": (503, "evidence_unavailable"),
        }.get(scenario)
        if refusal is not None:
            status, detail = refusal
            for response in (mail, chat):
                assert response.status_code == status, response.text
                assert response.json()["detail"] == detail
            assert live_kinds == []
            assert await sender_projection(env, sender) == before
            return

        for response in (mail, chat):
            assert response.status_code == 200, response.text
        received_mail = await env.client.get(
            f"/v1/messages/{mail.json()['message_id']}",
            headers=messaging_actor_headers(receiver),
        )
        received_chat = await env.client.get(
            f"/v1/chat/sessions/{chat.json()['session_id']}/messages",
            headers=messaging_actor_headers(receiver),
        )
        assert received_mail.status_code == received_chat.status_code == 200
        inbox = await env.client.get(
            "/v1/messages/inbox", headers=messaging_actor_headers(receiver)
        )
        assert inbox.status_code == 200, inbox.text
        inbox_item = next(
            item
            for item in inbox.json()["messages"]
            if item["message_id"] == mail.json()["message_id"]
        )
        pending = await env.client.get(
            "/v1/chat/pending", headers=messaging_actor_headers(receiver)
        )
        assert pending.status_code == 200, pending.text
        thread = next(
            item
            for item in pending.json()["pending"]
            if item["session_id"] == chat.json()["session_id"]
        )
        assert thread["last_from_stable_id"] == sender.stable_id
        assert (thread["last_from_address"] or None) == (
            sender.address if scenario == "live" else None
        )
        item = received_chat.json()["messages"][0]
        for received in (received_mail.json(), inbox_item, item):
            assert received["from_stable_id"] == sender.stable_id
            assert received["id_chain"] == (chain if scenario == "live" else None)
            assert (received["from_address"] or None) == (
                sender.address if scenario == "live" else None
            )
        if scenario != "live":
            assert before["address"] == sender.address
            assert await sender_projection(env, sender) == before
            assert live_kinds == [None, None]


@pytest.mark.asyncio
async def test_preferred_live_cannot_adopt_an_unverified_stable_did(
    privacy_app, monkeypatch
):
    env = privacy_app
    registry = application_registry_client(env.app.state)
    sender = await admit_messaging_actor(
        env, alias="unbound-sender", team_id=TEAM, local=True
    )
    receiver = await admit_messaging_actor(
        env, alias="local-receiver", team_id=TEAM, local=True
    )
    domain = f"unbound-address-{uuid4().hex[:8]}.test"
    new_certificate = await issue_global_certificate_to_local_member(
        env,
        sender,
        address=f"{domain}/sender",
    )
    controller = await env.registry.ensure_namespace(domain=domain)
    await registry.delete_address(domain, "sender", controller)
    assert await registry.resolve_address_fresh(domain, "sender") is None
    before = await sender_projection(env, sender)
    assert before["did_aw_verified_key"] is None
    mount_policy(env, monkeypatch)
    for response in await serve_messages(
        env, new_certificate, receiver, None, bounded=False
    ):
        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "identity_binding_mismatch"
    assert await sender_projection(env, sender) == before

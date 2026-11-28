"""Actual source/receiver: optional source kind, verified receiver human refusal."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from aweb.application_state import application_registry_client
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from messaging_actor_support import admit_messaging_actor, register_messaging_team
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_team_headers
from test_same_origin_delivery import (
    SAME_ORIGIN_PROXY_SECRET,
    foreign_receiver as foreign_receiver,
    same_origin as same_origin,
    same_origin_registry_socket as same_origin_registry_socket,
)

__all__ = ["foreign_receiver", "same_origin"]


@pytest.fixture(autouse=True)
def configured_host_signing(monkeypatch):
    # Configure the public host boundary before native/MCP creation, including
    # hosts which capture their configuration at resource startup.
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", SAME_ORIGIN_PROXY_SECRET)


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter", ["http", "mcp"])
@pytest.mark.parametrize("existing", [False, True])
async def test_remote_human_refusal_keeps_typed_body_through_source(
    same_origin, foreign_receiver, monkeypatch, adapter, existing
):
    env = same_origin.env
    alice = await admit_messaging_actor(
        env,
        alias="alice",
        team_id=TEAM,
        address="example.test/alice",
        signing_key=bytes(env.actors["alice"].sk),
    )
    source_registry = application_registry_client(env.app.state)
    target = same_origin.target
    receiver_team = await foreign_receiver.db.fetch_value(
        "SELECT team_id FROM {{tables.agents}} WHERE agent_id=$1", target.id
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=foreign_receiver.app),
        base_url=foreign_receiver.origin,
    ) as receiver_client:
        receiver_env = SimpleNamespace(
            app=foreign_receiver.app,
            client=receiver_client,
            registry=env.registry,
            team_sk=env.team_sk,
            team_did=env.team_did,
        )
        await register_messaging_team(receiver_env, team_id=receiver_team)
        bob = await admit_messaging_actor(
            receiver_env,
            alias="recipient",
            team_id=receiver_team,
            address=same_origin.target_address,
            signing_key=bytes(target.sk),
        )

    kind_lookups = []
    original_fresh = source_registry.resolve_key_fresh

    async def observe_source_kind(did, *args, **kwargs):
        if did == bob.stable_id:
            kind_lookups.append(did)
        return await original_fresh(did, *args, **kwargs)

    # A delegating observation of the actual SDK, never replacement authority.
    monkeypatch.setattr(source_registry, "resolve_key_fresh", observe_source_kind)
    initial = await source_registry.resolve_key_fresh(bob.stable_id)
    assert initial.current_did_key == bob.did_key
    assert initial.id_tree is None or not initial.id_tree.enrolled
    assert kind_lookups == [bob.stable_id]
    kind_lookups.clear()

    async def signer(**kwargs):
        payload = canonical_signed_payload(kwargs["payload"])
        return HostedMessageSigningResult(
            from_did=alice.did_key,
            signing_key_id=alice.did_key,
            signed_payload=payload,
            signature=sign_message(alice.signing_key, payload.encode()),
        )

    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=source_registry,
        federation_authority=env.app.state.federation_authority,
        hosted_signer=signer,
        public_origin=env.app.state.public_origin,
    )
    env.app.mount("/human-refusal-mcp", mcp)
    await mcp.startup()
    principal = str(uuid4())

    async def send(cid, *, continuation=False):
        if adapter == "mcp":
            arguments = dict(message="hello", plaintext=True, leaving=True)
            arguments.update(
                {"conversation_id": cid} if continuation else {"to": bob.address}
            )
            path = "/human-refusal-mcp/"
            raw = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "send_chat", "arguments": arguments},
                }
            ).encode()
        else:
            mid = str(uuid4())
            timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            signed = canonical_json_bytes(
                dict(
                    type="chat",
                    from_did=alice.did_key,
                    from_stable_id=alice.stable_id,
                    body="hello",
                    conversation_id=cid,
                    message_id=mid,
                    timestamp=timestamp,
                    sender_leaving=True,
                    to=bob.address,
                    to_did=bob.did_key,
                    to_stable_id=bob.stable_id,
                    **{"from": alice.address},
                )
            ).decode()
            payload = dict(
                from_did=alice.did_key,
                message_id=mid,
                timestamp=timestamp,
                signature=sign_message(alice.signing_key, signed.encode()),
                signed_payload=signed,
            )
            if continuation:
                path = f"/v1/chat/sessions/{cid}/messages"
                payload.update(body="hello", leaving=True)
            else:
                path = "/v1/chat/sessions"
                payload.update(
                    session_id=cid,
                    to_addresses=[bob.address],
                    message="hello",
                    leaving=True,
                )
            raw = json.dumps(payload).encode()
        response = await env.client.post(
            path,
            content=raw,
            headers={
                **_signed_team_headers(
                    alice.signing_key, alice.did_key, TEAM, alice.certificate, raw
                ),
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **(
                    {
                        "X-Team-ID": TEAM,
                        "X-User-ID": principal,
                        "X-AWEB-Actor-ID": alice.agent_id,
                        "X-AWEB-Auth": build_internal_auth_header_value(
                            secret=SAME_ORIGIN_PROXY_SECRET,
                            team_id=TEAM,
                            principal_type="u",
                            principal_id=principal,
                            actor_id=alice.agent_id,
                        ),
                    }
                    if adapter == "mcp"
                    else {}
                ),
            },
        )
        if adapter == "mcp":
            assert response.status_code == 200, response.text
            result = response.json()["result"]
            assert not result.get("isError"), result
            return json.loads(result["content"][0]["text"])
        return {"http_status": response.status_code, **response.json()}

    try:
        # Legacy runtime provenance alone is not a positive human-kind fact.
        await foreign_receiver.db.execute(
            "UPDATE {{tables.agents}} SET agent_type='human',human_verified_key=NULL WHERE agent_id=$1",
            target.id,
        )
        control = await send(str(uuid4()))
        assert "error" not in control and control.get("http_status", 200) == 200, (
            control
        )
        cid = control["session_id"]
        assert (
            await foreign_receiver.db.fetch_value(
                "SELECT count(*) FROM {{tables.chat_messages}}"
            )
            == 1
        )
        # Publish the actual controller-signed kind and project from fresh SDK
        # evidence; keep the source's earlier optional-kind cache independent.
        fresh_reader = RegistryClient(
            registry_url=source_registry.registry_url,
            service_token=source_registry.service_token,
            domain_verifier=same_origin.domain_authority,
        )
        try:
            await same_origin.verify_human(
                target, bob.stable_id, foreign_receiver.db, registry_client=fresh_reader
            )
        finally:
            await fresh_reader.aclose()
        refused = await send(cid if existing else str(uuid4()), continuation=existing)
        assert refused.get("http_status", 422) == 422, refused
        assert refused.get("reason") == "recipient_human_mail_only", refused
        assert refused["retryable"] is False
        assert refused["recipients"] == [bob.address]
        assert kind_lookups == []
        assert foreign_receiver.statuses == [200, 422]
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}")
            == 1
        )
        assert (
            await foreign_receiver.db.fetch_value(
                "SELECT count(*) FROM {{tables.chat_messages}}"
            )
            == 1
        )
        assert (
            await foreign_receiver.db.fetch_value(
                "SELECT count(*) FROM {{tables.message_ingress_receipts}}"
            )
            == 1
        )
    finally:
        await mcp.shutdown()

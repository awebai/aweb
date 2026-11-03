"""Same-origin address delivery through real HTTP, AWID, PostgreSQL and Redis.

Only disposable namespace/member state is provisioned directly. The existing
development-only registry pin avoids external DNS; signatures, address lookup,
residence, federation ingress and policy all run their actual implementations.
The observer records requests without replacing transport or handler results.
"""
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from awid.signing import canonical_json_bytes, sign_message
from aweb.federation.activation import build_federation_authority_activation
from identity_binding_support import register_global_identity
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import (
    _encode_certificate, _make_certificate, _make_keypair, _signed_team_headers,
)


@pytest_asyncio.fixture
async def same_origin(privacy_app, monkeypatch):
    env = privacy_app
    target_team = "recipients:recipient.test"
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
        "VALUES ($1, 'recipient.test', 'recipients', $2)", target_team, env.team_did,
    )
    sk, _, did = _make_keypair()
    target = SimpleNamespace(sk=sk, did=did, id=uuid4())
    address = "recipient.test/recipient"
    ingress = []
    stack = env.app.middleware_stack or env.app.build_middleware_stack()

    async def observe(scope, receive, send):
        if scope.get("type") == "http" and scope.get("path") == "/v1/federation/messages":
            ingress.append(scope["path"])
        await stack(scope, receive, send)

    env.app.middleware_stack = observe
    async with registry_listener(env) as (registry, registry_origin):
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

        async def resident(*, human=False, deleted=False, inbound_mode="open"):
            await env.db.execute(
                "INSERT INTO {{tables.agents}} "
                "(agent_id, team_id, alias, did_key, did_aw, did_aw_verified_key, "
                "address, identity_scope, inbound_mode, agent_type, deleted_at) "
                "VALUES ($1,$2,'recipient',$3,$4,$3,$5,'global',$8,$6, "
                "CASE WHEN $7 THEN clock_timestamp() ELSE NULL END)",
                target.id, target_team, target.did, stable, address,
                "human" if human else "agent", deleted, inbound_mode,
            )

        async def send_message(kind, sender_kind="local"):
            actor = env.actors["alice"]
            sender_stable = ""
            sender_address = "example.test/alice"
            if sender_kind != "local":
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
            certificate = _make_certificate(
                env.team_sk, env.team_did, actor.did, team_id=TEAM, alias="alice",
                identity_scope="global" if sender_stable else "local",
                member_did_aw=sender_stable, member_address=sender_address if sender_stable else "",
            )
            mid, cid = str(uuid4()), str(uuid4())
            timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            signed = dict(
                type=kind, from_did=actor.did, to=address,
                to_did=target.did, to_stable_id=stable, message_id=mid,
                conversation_id=cid, timestamp=timestamp, body="Same-origin delivery",
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
            encoded = canonical_json_bytes(signed).decode()
            payload.update(from_did=signed["from_did"], message_id=mid, timestamp=timestamp,
                           signed_payload=encoded, signature=sign_message(actor.sk, encoded.encode()))
            raw = json.dumps(payload).encode()
            headers = _signed_team_headers(
                actor.sk, actor.did, TEAM, _encode_certificate(certificate), raw,
            )
            response = await env.client.post(path, content=raw, headers={
                **headers, "Content-Type": "application/json",
            })
            return response, SimpleNamespace(
                message_id=UUID(mid), conversation_id=UUID(cid), signed=signed,
                signed_payload=encoded, signature=payload["signature"],
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
                                  ingress=ingress, effects=effects, target_did=stable)
        finally:
            env.app.middleware_stack = stack
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


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("human", [False, True], ids=["agent", "human"])
async def test_same_origin_resident_delivery_and_human_chat_policy(same_origin, kind, human):
    await same_origin.resident(human=human)
    before = await same_origin.effects()
    response, submitted = await same_origin.send(kind)
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
        assert row["from_did"] == submitted.signed["from_did"]
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
                submitted.signed["from_did"], same_origin.target_did,
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

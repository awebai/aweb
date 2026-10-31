"""Hosted-key refusal uses the exact published assertion, not recipient labels.

Local cases use the real HTTP apps, registry, PostgreSQL, Redis and signatures.
Federation cases exercise the atomic delivery transaction on real PostgreSQL.
"""

from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest

from awid.e2ee_keys import build_encryption_key_assertion, encryption_assertion_payload
from awid.federation_errors import FederationAuthorityError
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import encrypt_e2ee_message, generate_x25519_keypair
from aweb.federation.delivery import deliver_federated_phase_b
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_federation_activation_delivery import _DB, _envelope, _seed_recipient_and_authority
from test_messages_http import _insert_agent_encryption_assertion, _make_keypair, _signed_team_headers


def _identity(actor, custody="self", *, address="", stable_id=""):
    _, public_key = generate_x25519_keypair()
    assertion = build_encryption_key_assertion(
        signing_key=actor.sk, identity_did=actor.did,
        identity_stable_id=stable_id or None, encryption_public_key=public_key,
        custody=custody or "self", now=datetime.now(timezone.utc),
    )
    if custody is None:
        assertion.pop("custody")
        assertion["signature"] = sign_message(
            actor.sk, canonical_json_bytes(encryption_assertion_payload(assertion)),
        )
    return dict(did=actor.did, stable_id=stable_id, address=address,
                signing_key=actor.sk, encryption_key=assertion)


async def _publish(env, name, identity):
    actor = env.actors[name]
    body = json.dumps(identity["encryption_key"]).encode()
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body)
    response = await env.client.put(
        "/v1/agents/me/encryption-key", content=body,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 200, response.text


async def _counts(env):
    return tuple([await env.db.fetch_val("SELECT COUNT(*) FROM {{tables." + table + "}}")
                  for table in ("messages", "chat_messages", "conversations", "chat_sessions")])


async def _send(env, sender, recipient, *, kind, continuation=False):
    conversation_id = str(uuid4())
    if continuation:
        # The hosted recipient starts the session; the native sender continues.
        if kind == "mail":
            opened = await _request(env, "bob", "POST", "/v1/messages", {
                "to_did": sender["did"], "body": "start", "conversation_id": conversation_id,
            })
        else:
            opened = await _request(env, "bob", "POST", "/v1/chat/sessions", {
                "to_dids": [sender["did"]], "message": "start", "session_id": conversation_id,
            })
        assert opened.status_code == 200, opened.text
    message_id = str(uuid4())
    envelope = encrypt_e2ee_message(
        kind=kind, sender=sender, recipients=[recipient], body="private",
        subject="private" if kind == "mail" else "", message_id=message_id,
        conversation_id=conversation_id, created_at=datetime.now(timezone.utc),
    )
    payload = dict(message_id=message_id, content_mode="encrypted_v2",
                   message_version=2, encrypted_envelope=envelope)
    if kind == "mail":
        path = "/v1/messages"
        payload["conversation_id"] = conversation_id
        if not continuation:
            payload["to_did"] = recipient["did"]
    else:
        payload["timestamp"] = envelope["created_at"]
        if continuation:
            path = f"/v1/chat/sessions/{conversation_id}/messages"
        else:
            path = "/v1/chat/sessions"
            payload.update(session_id=conversation_id, to_dids=[recipient["did"]], message="")
    before, mutations = await _counts(env), len(env.dispatched)
    response = await _request(env, "alice", "POST", path, payload)
    return response, before, mutations


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("continuation", [False, True])
@pytest.mark.parametrize("custody", ["hosted_custodial", "self", None])
async def test_exact_recipient_key_custody_controls_encrypted_delivery(privacy_app, kind, continuation, custody):
    env = privacy_app
    alice, bob = _identity(env.actors["alice"]), _identity(env.actors["bob"], custody)
    await _publish(env, "bob", bob)
    response, before, mutations = await _send(env, alice, bob, kind=kind, continuation=continuation)
    if custody == "hosted_custodial":
        assert response.status_code == 422, response.text
        assert response.json()["reason"] == "recipient_custodial_no_e2ee"
        assert response.json()["detail"] == "recipient_custodial_no_e2ee"
        assert response.json()["retryable"] is False
        assert await _counts(env) == before
        assert len(env.dispatched) == mutations
    else:
        assert response.status_code == 200, response.text
        after = await _counts(env)
        assert after[0 if kind == "mail" else 1] == before[0 if kind == "mail" else 1] + 1


@pytest.mark.asyncio
@pytest.mark.parametrize("custody", ["hosted_custodial", "self"])
async def test_custody_comes_from_delivered_key_not_latest_key(privacy_app, custody):
    env = privacy_app
    alice, bob = _identity(env.actors["alice"]), _identity(env.actors["bob"], custody)
    await _publish(env, "bob", bob)
    other = _identity(env.actors["bob"], "self" if custody == "hosted_custodial" else "hosted_custodial")
    await _publish(env, "bob", other)
    response, before, _ = await _send(env, alice, bob, kind="mail")
    assert response.status_code == (422 if custody == "hosted_custodial" else 200), response.text
    if custody == "hosted_custodial":
        assert response.json()["reason"] == "recipient_custodial_no_e2ee"
        assert await _counts(env) == before


@pytest.mark.asyncio
async def test_unverified_custody_projection_does_not_classify_recipient(privacy_app):
    env = privacy_app
    alice, bob = _identity(env.actors["alice"]), _identity(env.actors["bob"])
    await _publish(env, "bob", bob)
    await env.db.execute(
        "UPDATE {{tables.agent_encryption_keys}} SET assertion_custody='hosted_custodial' WHERE agent_id=$1",
        env.actors["bob"].id,
    )
    response, _, _ = await _send(env, alice, bob, kind="mail")
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_forged_hosted_assertion_is_invalid_not_verified_custody(privacy_app):
    env = privacy_app
    alice, bob = _identity(env.actors["alice"]), _identity(env.actors["bob"])
    await _publish(env, "bob", bob)
    forged = {**bob["encryption_key"], "custody": "hosted_custodial"}
    await env.db.execute(
        "UPDATE {{tables.agent_encryption_keys}} SET assertion_canonical=$2 WHERE agent_id=$1",
        env.actors["bob"].id, canonical_json_bytes(encryption_assertion_payload(forged)).decode(),
    )
    response, before, _ = await _send(env, alice, bob, kind="mail")
    assert response.status_code == 422, response.text
    assert response.json()["reason"] == "recipient_encryption_assertion_invalid_or_stale"
    assert await _counts(env) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("published", [True, False])
async def test_hosted_key_does_not_refuse_plaintext_or_imply_custody_when_absent(privacy_app, published):
    env = privacy_app
    alice, bob = _identity(env.actors["alice"]), _identity(env.actors["bob"], "hosted_custodial")
    if published:
        await _publish(env, "bob", bob)
        response = await _request(env, "alice", "POST", "/v1/messages", {"to_did": bob["did"], "body": "explicit default"})
    else:
        response, _, _ = await _send(env, alice, bob, kind="mail")
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("custody", ["hosted_custodial", "self", None])
@pytest.mark.parametrize("sender_custody", ["self", "hosted_custodial"])
async def test_federation_refuses_verified_hosted_key_before_atomic_effects(aweb_cloud_db, kind, custody, sender_custody):
    from types import SimpleNamespace

    sender_sk, _, sender_did = _make_keypair()
    recipient_sk, _, recipient_did = _make_keypair()
    alice = _identity(SimpleNamespace(sk=sender_sk, did=sender_did), sender_custody, address="alpha.example/alice", stable_id="did:aw:alice")
    bob = _identity(SimpleNamespace(sk=recipient_sk, did=recipient_did), custody, address="beta.example/bob", stable_id="did:aw:bob")
    envelope = _envelope(kind=kind).model_copy(update={
        "sender_current_did_key": sender_did, "target_current_did_key": recipient_did,
    })
    encrypted = encrypt_e2ee_message(
        kind=kind, sender=alice, recipients=[bob], body="private",
        subject="private" if kind == "mail" else "", message_id=envelope.message_id,
        conversation_id=envelope.conversation_id, created_at=datetime.now(timezone.utc),
    )
    envelope = envelope.model_copy(update={
        "content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": encrypted,
        "body": "", "subject": "" if kind == "mail" else None, "signed_payload": None,
    })
    manager = aweb_cloud_db.aweb_db
    recipient, token = await _seed_recipient_and_authority(manager, envelope)
    await _insert_agent_encryption_assertion(manager, agent_id=recipient["agent_id"],
                                           team_id=recipient["team_id"], assertion=bob["encryption_key"])
    async def deliver():
        return await deliver_federated_phase_b(
            _DB(manager), envelope=envelope, signature=encrypted["signature"],
            recipient=recipient, authority_token=token,
        )
    if custody == "hosted_custodial" and sender_custody == "self":
        with pytest.raises(FederationAuthorityError) as refused:
            await deliver()
        assert refused.value.reason == "recipient_custodial_no_e2ee"
        assert refused.value.http_status == 422
        for table in ("messages", "chat_messages", "conversations", "chat_sessions", "message_ingress_receipts", "federation_mutation_outbox"):
            assert await manager.fetch_val("SELECT COUNT(*) FROM {{tables." + table + "}}") == 0
    else:
        result = await deliver()
        assert result["message_id"] == envelope.message_id

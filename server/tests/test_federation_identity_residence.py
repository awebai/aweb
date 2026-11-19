"""Federation delivers to an exact resident identity without granting a team actor."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4

import httpx
import pytest
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)
from test_same_origin_delivery import (
    foreign_receiver as foreign_receiver,
    same_origin as same_origin,
    same_origin_registry_socket as same_origin_registry_socket,
)


class ResidenceAdmission(StrEnum):
    CURRENT_MEMBER = "current-member"
    SUPERSEDED_MEMBER = "superseded-member"


async def _supersede_resident_membership(fixture, receiver) -> None:
    """Rotate the actual registry team, then admit another member on the receiver."""
    env = fixture.env
    next_sk, _, next_did = _make_keypair()
    # The federation and certificate adapters consult the same fixture DNS
    # authority through their respective public resolver injection points.
    receiver.app.state.awid_txt_resolver = fixture.dns
    payload = {
        "operation": "rotate_team_key",
        "domain": "recipient.test",
        "name": "recipients",
        "new_team_did_key": next_did,
    }
    timestamp = datetime.now(timezone.utc).isoformat()
    namespace_key = await env.registry.ensure_namespace(domain="recipient.test")
    namespace = await env.registry.namespace_authority("recipient.test")
    signature = sign_message(
        bytes(namespace_key), canonical_json_bytes({**payload, "timestamp": timestamp})
    )
    # Preserve the real clock's precision: admission is a first-sight floor,
    # and the later controller act must actually be newer than that floor.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env.registry_app),
        base_url="http://registry.test",
    ) as registry_http:
        rotated = await registry_http.post(
            "/v1/namespaces/recipient.test/teams/recipients/rotate",
            json={"new_team_did_key": next_did},
            headers={
                "Authorization": f"DIDKey {namespace.controller_did} {signature}",
                "X-AWEB-Timestamp": timestamp,
            },
        )
    assert rotated.status_code == 200, rotated.text
    member_sk, _, member_did = _make_keypair()
    certificate = _encode_certificate(
        _make_certificate(
            next_sk,
            next_did,
            member_did,
            team_id="recipients:recipient.test",
            alias="new-member",
            identity_scope="local",
            certificate_id="reissued-" + uuid4().hex,
        )
    )
    body = b"{}"
    async with httpx.AsyncClient(base_url=receiver.origin) as client:
        connected = await client.post(
            "/v1/connect",
            content=body,
            headers={
                **_signed_team_headers(
                    member_sk,
                    member_did,
                    "recipients:recipient.test",
                    certificate,
                    body,
                ),
                "Content-Type": "application/json",
            },
        )
    assert connected.status_code == 200, connected.text
    row = await receiver.db.fetch_one(
        "SELECT a.accepted_team_did_key,t.team_did_key FROM {{tables.agents}} a "
        "JOIN {{tables.teams}} t ON t.team_id=a.team_id WHERE a.agent_id=$1",
        fixture.target.id,
    )
    assert row["team_did_key"] == next_did
    assert row["accepted_team_did_key"] != next_did


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("admission", list(ResidenceAdmission))
async def test_federation_first_contact_and_new_continuation_keep_identity_residence(
    same_origin,
    foreign_receiver,
    monkeypatch,
    kind,
    admission,
):
    # identity-messaging-contract.md:262-277: the registry address supplies
    # canonical DID/key/route; residence does not require current membership.
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    if admission is ResidenceAdmission.SUPERSEDED_MEMBER:
        await _supersede_resident_membership(same_origin, foreign_receiver)
    first_response, first = await same_origin.send(kind, "global")
    assert first_response.status_code == 200, first_response.text
    second_response, second = await same_origin.send(kind, "global", continuation=first)
    assert second_response.status_code == 200, second_response.text
    assert second.message_id != first.message_id
    table = "messages" if kind == "mail" else "chat_messages"
    rows = await foreign_receiver.db.fetch_all(
        "SELECT message_id,from_did FROM {{tables." + table + "}} WHERE message_id=ANY($1::uuid[])",
        [first.message_id, second.message_id],
    )
    assert {row["message_id"] for row in rows} == {first.message_id, second.message_id}
    assert {row["from_did"] for row in rows} == {first.signed["from_stable_id"]}
    assert foreign_receiver.statuses == [200, 200]
    participants = await foreign_receiver.db.fetch_all(
        "SELECT agent_id FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
        first.conversation_id,
        same_origin.target_did,
    )
    assert len(participants) == 1
    assert participants[0]["agent_id"] is None
    await _require_identity_wakes(same_origin, kind=kind)


async def _publish_resident_encryption_key(fixture, receiver) -> dict:
    """Publish through the member route before retiring its team admission."""
    from awid.e2ee_keys import build_encryption_key_assertion
    from aweb.e2ee_messages import generate_x25519_keypair

    receiver.app.state.awid_txt_resolver = fixture.dns
    target, env = fixture.target, fixture.env
    _, public_key = generate_x25519_keypair()
    assertion = build_encryption_key_assertion(
        signing_key=target.sk,
        identity_did=target.did,
        identity_stable_id=fixture.target_did,
        encryption_public_key=public_key,
    )
    certificate = _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            target.did,
            team_id="recipients:recipient.test",
            alias="recipient",
            identity_scope="global",
            member_did_aw=fixture.target_did,
            member_address=fixture.target_address,
        )
    )

    body = json.dumps(assertion).encode()
    async with httpx.AsyncClient(base_url=receiver.origin) as client:
        published = await client.put(
            "/v1/agents/me/encryption-key",
            content=body,
            headers={
                **_signed_team_headers(
                    target.sk,
                    target.did,
                    "recipients:recipient.test",
                    certificate,
                    body,
                ),
                "Content-Type": "application/json",
            },
        )
    assert published.status_code == 200, published.text
    return assertion


async def _send_encrypted_continuation(fixture, *, first, kind, assertion):
    """Use actual sender HTTP and receiver federation with a published key."""
    from aweb.e2ee_messages import encrypt_e2ee_message, generate_x25519_keypair
    from awid.e2ee_keys import build_encryption_key_assertion
    from test_dashboard_privacy import TEAM

    actor = fixture.env.actors["alice"]
    _, public_key = generate_x25519_keypair()
    sender_stable = first.signed["from_stable_id"]
    envelope = encrypt_e2ee_message(
        kind=kind,
        sender={
            "did": actor.did,
            "stable_id": sender_stable,
            "address": first.signed["from"],
            "signing_key": actor.sk,
            "encryption_key": build_encryption_key_assertion(
                signing_key=actor.sk,
                identity_did=actor.did,
                identity_stable_id=sender_stable,
                encryption_public_key=public_key,
            ),
        },
        recipients=[
            {
                "did": fixture.target.did,
                "stable_id": fixture.target_did,
                "address": fixture.target_address,
                "encryption_key": assertion,
            }
        ],
        body="Encrypted resident continuation",
        subject="Residence",
        message_id=str(uuid4()),
        conversation_id=str(first.conversation_id),
        created_at=datetime.now(timezone.utc).replace(microsecond=0),
    )
    payload = {
        "body": "",
        "from_did": actor.did,
        "message_id": envelope["message_id"],
        "timestamp": envelope["created_at"],
        "content_mode": "encrypted_v2",
        "message_version": 2,
        "encrypted_envelope": envelope,
    }
    if kind == "mail":
        path = "/v1/messages"
        payload.update(
            to_address=fixture.target_address,
            subject="",
            conversation_id=str(first.conversation_id),
        )
    else:
        path = f"/v1/chat/sessions/{first.conversation_id}/messages"
    body = json.dumps(payload).encode()
    certificate = _encode_certificate(
        _make_certificate(
            fixture.env.team_sk,
            fixture.env.team_did,
            actor.did,
            team_id=TEAM,
            alias="alice",
            identity_scope="global",
            member_did_aw=sender_stable,
            member_address=first.signed["from"],
        )
    )
    response = await fixture.env.client.post(
        path,
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, certificate, body),
            "Content-Type": "application/json",
        },
    )
    return response, envelope


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("admission", list(ResidenceAdmission))
async def test_encrypted_federation_uses_identity_assertion_after_member_supersession(
    same_origin,
    foreign_receiver,
    monkeypatch,
    kind,
    admission,
):
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    assertion = await _publish_resident_encryption_key(same_origin, foreign_receiver)
    if admission is ResidenceAdmission.SUPERSEDED_MEMBER:
        await _supersede_resident_membership(same_origin, foreign_receiver)
    response, first = await same_origin.send(kind, "global")
    assert response.status_code == 200, response.text
    response, envelope = await _send_encrypted_continuation(
        same_origin,
        first=first,
        kind=kind,
        assertion=assertion,
    )
    assert response.status_code == 200, response.text
    table = "messages" if kind == "mail" else "chat_messages"
    stored = await foreign_receiver.db.fetch_one(
        "SELECT content_mode,from_did FROM {{tables." + table + "}} WHERE message_id=$1::uuid",
        response.json()["message_id"],
    )
    assert stored["content_mode"] == "encrypted_v2"
    assert stored["from_did"] == first.signed["from_stable_id"]
    assert envelope["recipients"][0]["encryption_key_id"] == assertion["encryption_key_id"]
    # Explicit storage tampering is a negative boundary, not normal setup.
    original = await foreign_receiver.db.fetch_value(
        "SELECT assertion_canonical FROM {{tables.agent_encryption_keys}} "
        "WHERE agent_id=$1 AND encryption_key_id=$2",
        same_origin.target.id,
        assertion["encryption_key_id"],
    )
    await foreign_receiver.db.execute(
        "UPDATE {{tables.agent_encryption_keys}} SET assertion_canonical='{}' "
        "WHERE encryption_key_id=$1",
        assertion["encryption_key_id"],
    )
    invalid, _ = await _send_encrypted_continuation(
        same_origin,
        first=first,
        kind=kind,
        assertion=assertion,
    )
    assert invalid.status_code == 422, invalid.text
    assert "recipient_encryption_assertion_invalid_or_stale" in invalid.text
    await foreign_receiver.db.execute(
        "UPDATE {{tables.agent_encryption_keys}} SET assertion_canonical=$2 "
        "WHERE encryption_key_id=$1",
        assertion["encryption_key_id"],
        original,
    )
    # Explicit corruption models a revoked key at the receiver; the next
    # distinct message must fail, even though the conversation already exists.
    await foreign_receiver.db.execute(
        "UPDATE {{tables.agent_encryption_keys}} SET revoked_at=clock_timestamp() "
        "WHERE encryption_key_id=$1",
        assertion["encryption_key_id"],
    )
    refused, _ = await _send_encrypted_continuation(
        same_origin,
        first=first,
        kind=kind,
        assertion=assertion,
    )
    assert refused.status_code == 424, refused.text
    assert "recipient_encryption_assertion_missing" in refused.text
    assert (
        await foreign_receiver.db.fetch_value(
            "SELECT count(*) FROM {{tables." + table + "}} WHERE conversation_id=$1"
            if kind == "mail"
            else "SELECT count(*) FROM {{tables.chat_messages}} WHERE session_id=$1",
            first.conversation_id,
        )
        == 2
    )


async def _require_identity_wakes(fixture, *, kind):
    from aweb.agent_wake import did_wake_key, read_wake_marks

    keys = [did_wake_key(fixture.target_did), did_wake_key(fixture.target.did)]
    async with asyncio.timeout(2):
        while True:
            marks = await read_wake_marks(fixture.env.redis, keys)
            if all(marks[(key, kind)] is not None for key in keys):
                return
            await asyncio.sleep(0.02)

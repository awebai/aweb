# ruff: noqa: F811 -- shared real fixture imported by name.
"""Pinned released plaintext bytes cross real identity/grant send boundaries."""

import json
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import BaseModel

from awid.did import did_from_public_key, generate_keypair
from awid.signing import sign_message
from aweb.messaging.kinds import MessageKind
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_identity_grants import _grant_headers
from test_messages_http import _signed_team_headers

__all__ = ["privacy_app"]


class ReleasedClientClass(StrEnum):
    ORDINARY = "ordinary"
    RESIDENT_CUSTODY = "resident-custody"


class ReleasedPayloadProfile(BaseModel):
    client_class: ReleasedClientClass
    source_tag: str
    source_commit: str
    signing_go_sha256: str
    payloads: dict[MessageKind, str]


class ReleasedPayloadFixtures(BaseModel):
    profiles: list[ReleasedPayloadProfile]


PROFILES = ReleasedPayloadFixtures.model_validate_json(
    (
        Path(__file__).parent / "fixtures/released_message_payloads/payloads.json"
    ).read_text()
).profiles


async def _mint_real_grant(env, *, session_did):
    actor = env.actors["alice"]
    raw = json.dumps(
        {
            "grant_did_key": session_did,
            "scopes": ["mail.send", "chat.send"],
            "ttl_seconds": 600,
        }
    ).encode()
    result = await env.client.post(
        "/v1/identity-grants",
        content=raw,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, raw),
            "Content-Type": "application/json",
        },
    )
    assert result.status_code == 200, result.text
    return result.json()["grant_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", PROFILES, ids=lambda profile: profile.source_tag)
@pytest.mark.parametrize("kind", [MessageKind.MAIL, MessageKind.CHAT])
async def test_pinned_released_payload_bytes_verify_with_the_transport_subject(
    privacy_app, profile, kind
):
    env = privacy_app
    sender, recipient = env.actors["alice"], env.actors["bob"]
    session_key, public_key = generate_keypair()
    session_did = did_from_public_key(public_key)
    grant_id = None
    if profile.client_class is ReleasedClientClass.RESIDENT_CUSTODY:
        grant_id = await _mint_real_grant(env, session_did=session_did)
    replacements = {
        "@SENDER_DID@": sender.did,
        "@RECIPIENT_DID@": recipient.did,
        "@MESSAGE_ID@": str(uuid4()),
        "@CONVERSATION_ID@": str(uuid4()),
        "@TIMESTAMP@": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    signed_payload = profile.payloads[kind]
    for marker, value in replacements.items():
        signed_payload = signed_payload.replace(marker, value)
    signed = json.loads(signed_payload)
    if kind is MessageKind.MAIL:
        path, table = "/v1/messages", "messages"
        wire = dict(to_alias="bob", subject=signed["subject"], body=signed["body"])
        if "conversation_id" in signed:
            wire["conversation_id"] = signed["conversation_id"]
    else:
        path, table = "/v1/chat/sessions", "chat_messages"
        wire = dict(to_aliases=["bob"], message=signed["body"])
        if "conversation_id" in signed:
            wire["session_id"] = signed["conversation_id"]
    wire.update(
        from_did=sender.did,
        message_id=signed["message_id"],
        timestamp=signed["timestamp"],
        signature=sign_message(sender.sk, signed_payload.encode("utf-8")),
        signed_payload=signed_payload,
    )

    async def post(payload):
        raw = json.dumps(payload).encode()
        if grant_id is not None:
            headers = _grant_headers(
                signing_key=session_key,
                did_key=session_did,
                grant_id=grant_id,
                method="POST",
                path=path,
                body=raw,
                aud=str(env.client.base_url).rstrip("/"),
            )
        else:
            headers = _signed_team_headers(
                sender.sk, sender.did, TEAM, sender.certificate, raw
            )
        return await env.client.post(
            path, content=raw, headers={**headers, "Content-Type": "application/json"}
        )

    # Equivalent parsed JSON is not the original signed byte string. A server
    # that reserializes before verifying would incorrectly accept this change.
    altered = await post({**wire, "signed_payload": signed_payload + " "})
    assert altered.status_code == 422, altered.text
    assert altered.json()["detail"] == (
        "The message signature does not verify. Sign the message again with the authenticated sender's key and resend it."
    )
    if grant_id is not None:
        wrong_key = await post(
            {
                **wire,
                "signature": sign_message(session_key, signed_payload.encode("utf-8")),
            }
        )
        assert wrong_key.status_code == 422, wrong_key.text
        assert wrong_key.json()["detail"] == (
            "The message signature does not verify. Sign the message again with the authenticated sender's key and resend it."
        )
    assert (
        await env.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}") == 0
    )
    assert env.dispatched == []
    accepted = await post(wire)
    assert accepted.status_code == 200, accepted.text
    stored = await env.db.fetch_one(
        f"SELECT from_did,body,signature,signed_payload FROM {{{{tables.{table}}}}} WHERE message_id=$1",
        UUID(wire["message_id"]),
    )
    assert stored["from_did"] == sender.did
    assert stored["signed_payload"].encode("utf-8") == signed_payload.encode("utf-8")
    assert stored["body"] == "released <tag> café \n line \u2028"
    assert len(env.dispatched) == 1
    repeated = await post(wire)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["message_id"] == accepted.json()["message_id"]
    assert await env.db.fetch_one(
        f"SELECT from_did,body,signature,signed_payload FROM {{{{tables.{table}}}}} WHERE message_id=$1",
        UUID(wire["message_id"]),
    ) == dict(stored)
    assert (
        await env.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}") == 1
    )
    assert len(env.dispatched) == 1

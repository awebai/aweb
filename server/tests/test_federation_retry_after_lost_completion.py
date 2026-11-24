"""Real sender/receiver projections survive a completion lost beyond plaintext age."""

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import httpx
import pytest

from aweb.federation.delivery import federation_envelope_hash
from aweb.federation.envelope import FederatedDeliveryRequest, FederationEnvelope
from aweb.messaging.kinds import ContentMode, MessageKind
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_mail_retry_after_lost_completion import (
    HOLD_COMPLETION_SECONDS,
    INITIAL_ATTESTATION_AGE_SECONDS,
    HeldMailCompletions,
)
from test_messages_http import _signed_team_headers
from test_same_origin_delivery import (
    foreign_receiver as foreign_receiver,
    same_origin as same_origin,
    same_origin_registry_socket as same_origin_registry_socket,
)

__all__ = ["foreign_receiver", "same_origin"]


@dataclass(frozen=True, kw_only=True)
class PreparedSend:
    kind: MessageKind
    path: str
    content: bytes
    signed: dict
    signature: str

    @property
    def message_id(self) -> UUID:
        return UUID(self.signed["message_id"])


def prepare_send(
    template,
    *,
    kind: MessageKind,
    conversation_id: UUID,
    signer,
    attestation_age_seconds: int = 0,
) -> PreparedSend:
    signed = {
        key: value
        for key, value in template.items()
        if key
        not in {
            "subject",
            "priority",
            "sender_leaving",
            "hang_on",
            "wait_seconds",
            "reply_to",
        }
    }
    signed.update(
        type=kind.value,
        message_id=str(uuid4()),
        conversation_id=str(conversation_id),
        timestamp=(
            datetime.now(timezone.utc) - timedelta(seconds=attestation_age_seconds)
        )
        .replace(microsecond=0)
        .isoformat(),
        body="Retained completion " + kind.value,
    )
    if kind is MessageKind.MAIL:
        signed.update(subject="Retained completion", priority="normal")
        payload = dict(
            to_address=signed["to"],
            conversation_id=str(conversation_id),
            subject=signed["subject"],
            body=signed["body"],
        )
        path = "/v1/messages"
    else:
        payload = dict(body=signed["body"])
        path = f"/v1/chat/sessions/{conversation_id}/messages"
    encoded = canonical_json_bytes(signed)
    signature = sign_message(signer.sk, encoded)
    payload.update(
        from_did=signer.did,
        message_id=signed["message_id"],
        timestamp=signed["timestamp"],
        signed_payload=encoded.decode(),
        signature=signature,
    )
    return PreparedSend(
        kind=kind,
        path=path,
        content=json.dumps(payload).encode(),
        signed=signed,
        signature=signature,
    )


async def post_send(client, *, prepared: PreparedSend, actor, certificate: str):
    return await client.post(
        prepared.path,
        content=prepared.content,
        headers={
            **_signed_team_headers(
                actor.sk, actor.did, TEAM, certificate, prepared.content
            ),
            "Content-Type": "application/json",
        },
    )


def wire_envelope(prepared: PreparedSend, *, sender_origin: str, receiver_origin: str):
    signed = prepared.signed
    return FederationEnvelope(
        type=prepared.kind.value,
        sender_did_aw=signed["from_stable_id"],
        sender_current_did_key=signed["from_did"],
        sender_address=signed["from"],
        sender_delivery_origin=sender_origin,
        target_address=signed["to"],
        target_did_aw=signed["to_stable_id"],
        target_current_did_key=signed["to_did"],
        target_delivery_origin=receiver_origin,
        body=signed["body"],
        subject=signed.get("subject"),
        priority=signed.get("priority"),
        message_id=signed["message_id"],
        conversation_id=signed["conversation_id"],
        timestamp=signed["timestamp"],
        signed_payload=json.loads(prepared.content)["signed_payload"],
        content_mode=ContentMode.PLAINTEXT
        if prepared.kind is MessageKind.CHAT
        else None,
        message_version=1 if prepared.kind is MessageKind.CHAT else None,
    )


async def table_counts(manager):
    return {
        table: await manager.fetch_value(
            f"SELECT count(*) FROM {{{{tables.{table}}}}}"
        )
        for table in (
            "messages",
            "chat_messages",
            "conversations",
            "chat_sessions",
            "conversation_participants",
            "chat_participants",
            "contacts",
            "message_ingress_receipts",
            "federation_mutation_outbox",
        )
    }


@pytest.mark.asyncio
async def test_plaintext_outbound_and_ingress_retry_after_completion_fault_crosses_window(
    same_origin,
    foreign_receiver,
):
    """One real hold covers mail projection, continued chat and both ingress receipts."""
    env = same_origin.env
    actor = env.actors["alice"]
    prime, submitted = await same_origin.send("mail", "global")
    assert prime.status_code == 200, prime.text
    certificate = prime.request.headers["X-AWID-Team-Certificate"]
    # Open a genuine remote chat without re-registering the already admitted sender.
    opening = prepare_send(
        submitted.signed, kind=MessageKind.CHAT, conversation_id=uuid4(), signer=actor
    )
    opening_payload = json.loads(opening.content)
    opening_payload["message"] = opening_payload.pop("body")
    opening_payload.update(
        session_id=opening.signed["conversation_id"],
        to_addresses=[same_origin.target_address],
    )
    opening_raw = json.dumps(opening_payload).encode()
    created = await env.client.post(
        "/v1/chat/sessions",
        content=opening_raw,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, certificate, opening_raw),
            "Content-Type": "application/json",
        },
    )
    assert created.status_code == 200, created.text
    prepared = [
        prepare_send(
            submitted.signed,
            kind=MessageKind.MAIL,
            conversation_id=submitted.conversation_id,
            signer=actor,
            attestation_age_seconds=INITIAL_ATTESTATION_AGE_SECONDS,
        ),
        prepare_send(
            submitted.signed,
            kind=MessageKind.CHAT,
            conversation_id=UUID(created.json()["session_id"]),
            signer=actor,
            attestation_age_seconds=INITIAL_ATTESTATION_AGE_SECONDS,
        ),
    ]
    proxy = HeldMailCompletions(upstream_url=str(env.client.base_url), response_count=2)
    proxy_url = await proxy.start()
    attempts = []
    try:
        async with httpx.AsyncClient(base_url=proxy_url, timeout=None) as interrupted:
            attempts = [
                asyncio.create_task(
                    post_send(
                        interrupted, prepared=item, actor=actor, certificate=certificate
                    )
                )
                for item in prepared
            ]
            await asyncio.wait_for(proxy.all_held.wait(), timeout=45)
            assert not proxy.failures, proxy.failures
            assert proxy.responses == [b"HTTP/1.1 200 OK\r\n"] * 2
            assert len(proxy.response_bodies) == 2
            originals = {
                (body.get("message") or body)["message_id"]: body
                for body in map(json.loads, proxy.response_bodies)
            }
            envelopes = {}
            for item in prepared:
                envelope = wire_envelope(
                    item,
                    sender_origin=env.app.state.public_origin,
                    receiver_origin=foreign_receiver.origin,
                )
                receipt = await foreign_receiver.db.fetch_one(
                    "SELECT envelope_hash,established_result FROM {{tables.message_ingress_receipts}} WHERE message_id=$1",
                    item.message_id,
                )
                assert receipt is not None and receipt["established_result"] is not None
                assert receipt["envelope_hash"] == federation_envelope_hash(
                    envelope, item.signature
                )
                envelopes[item.message_id] = (envelope, receipt["established_result"])
            before = (
                await table_counts(env.db),
                await table_counts(foreign_receiver.db),
                list(env.dispatched),
            )
            for item in prepared:
                changed = dict(
                    item.signed,
                    body="fresh conflicting signed content",
                    timestamp=datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat(),
                )
                payload = json.loads(item.content)
                encoded = canonical_json_bytes(changed)
                payload.update(
                    body=changed["body"],
                    timestamp=changed["timestamp"],
                    signed_payload=encoded.decode(),
                    signature=sign_message(actor.sk, encoded),
                )
                raw = json.dumps(payload).encode()
                conflict = await env.client.post(
                    item.path,
                    content=raw,
                    headers={
                        **_signed_team_headers(
                            actor.sk, actor.did, TEAM, certificate, raw
                        ),
                        "Content-Type": "application/json",
                    },
                )
                assert conflict.status_code == 409, conflict.text
                assert conflict.json()["detail"] == (
                    "message_id already exists for a different signed message. Retry the original request unchanged; choose a new message_id only if you intend to send a different message."
                )
            assert (
                await table_counts(env.db),
                await table_counts(foreign_receiver.db),
                env.dispatched,
            ) == before
            started = time.monotonic()
            await asyncio.sleep(HOLD_COMPLETION_SECONDS)
            proxy.release.set()
            assert time.monotonic() - started >= HOLD_COMPLETION_SECONDS
            assert all(
                (
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(item.signed["timestamp"])
                ).total_seconds()
                > 300
                for item in prepared
            )
            losses = await asyncio.wait_for(
                asyncio.gather(*attempts, return_exceptions=True), timeout=10
            )
            assert all(isinstance(loss, httpx.TransportError) for loss in losses), (
                losses
            )
        for item in prepared:
            retried = await post_send(
                env.client, prepared=item, actor=actor, certificate=certificate
            )
            assert retried.status_code == 200, retried.text
            assert retried.json() == originals[str(item.message_id)]
            envelope, result = envelopes[item.message_id]
            if isinstance(result, str):
                result = json.loads(result)
            async with httpx.AsyncClient(base_url=foreign_receiver.origin) as remote:
                repeated = await remote.post(
                    "/v1/federation/messages",
                    json=FederatedDeliveryRequest(
                        envelope=envelope, signature=item.signature
                    ).model_dump(mode="json", exclude_none=True),
                )
            assert repeated.status_code == 200, repeated.text
            assert repeated.json() == result
            # A valid changed signed payload is a new attestation even under an old ID.
            changed = dict(item.signed, body="different signed message")
            payload = json.loads(item.content)
            encoded = canonical_json_bytes(changed)
            payload.update(
                body=changed["body"],
                signed_payload=encoded.decode(),
                signature=sign_message(actor.sk, encoded),
            )
            refused = await env.client.post(
                item.path,
                content=(raw := json.dumps(payload).encode()),
                headers={
                    **_signed_team_headers(actor.sk, actor.did, TEAM, certificate, raw),
                    "Content-Type": "application/json",
                },
            )
            assert refused.status_code == 422, refused.text
            assert (
                refused.headers["X-AWEB-Error-Code"] == "message_timestamp_outside_skew"
            )
            assert refused.json()["detail"].endswith(
                "Sign the message again with the current UTC time and retry."
            )
            changed_envelope = envelope.model_copy(
                update={
                    "body": changed["body"],
                    "signed_payload": encoded.decode(),
                }
            )
            async with httpx.AsyncClient(base_url=foreign_receiver.origin) as remote:
                collision = await remote.post(
                    "/v1/federation/messages",
                    json=FederatedDeliveryRequest(
                        envelope=changed_envelope, signature=payload["signature"]
                    ).model_dump(mode="json", exclude_none=True),
                )
            assert collision.status_code == 422, collision.text
            assert collision.json()["reason"] == "federation_timestamp_invalid"
            # No receipt/projection for another ID can supply a replay exemption.
            changed["message_id"] = str(uuid4())
            encoded = canonical_json_bytes(changed)
            payload.update(
                message_id=changed["message_id"],
                signed_payload=encoded.decode(),
                signature=sign_message(actor.sk, encoded),
            )
            missing = await env.client.post(
                item.path,
                content=(raw := json.dumps(payload).encode()),
                headers={
                    **_signed_team_headers(actor.sk, actor.did, TEAM, certificate, raw),
                    "Content-Type": "application/json",
                },
            )
            assert missing.status_code == 422, missing.text
            assert (
                missing.headers["X-AWEB-Error-Code"] == "message_timestamp_outside_skew"
            )
            assert missing.json()["detail"].endswith(
                "Sign the message again with the current UTC time and retry."
            )
            missing_envelope = changed_envelope.model_copy(
                update={
                    "message_id": changed["message_id"],
                    "signed_payload": encoded.decode(),
                }
            )
            async with httpx.AsyncClient(base_url=foreign_receiver.origin) as remote:
                unstored = await remote.post(
                    "/v1/federation/messages",
                    json=FederatedDeliveryRequest(
                        envelope=missing_envelope, signature=payload["signature"]
                    ).model_dump(mode="json", exclude_none=True),
                )
            assert unstored.status_code == 422, unstored.text
            assert unstored.json()["reason"] == "federation_timestamp_invalid"
        assert (
            await table_counts(env.db),
            await table_counts(foreign_receiver.db),
            env.dispatched,
        ) == before
    finally:
        await proxy.close()
        if attempts:
            await asyncio.gather(*attempts, return_exceptions=True)
        assert not proxy.failures, proxy.failures

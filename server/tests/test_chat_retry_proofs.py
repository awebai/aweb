"""Component proof for stored chat artifact integrity; no server/DB fixtures."""

import base64
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import asyncpg
import pytest
from pgdbm.errors import QueryError

from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import MessagingAuth
from aweb.messaging.chat_models import CreateSessionRequest, SendMessageRequest
from aweb.messaging.chat_send import _stored_exact_chat_send
from aweb.messaging.refusals import DeliveryRefusal
from aweb.messaging.write_conflicts import is_unique_write_conflict


class StoredChatSnapshot:
    """An explicit stored-artifact reader for this component, not a SQL harness."""

    def __init__(self, row, recipient):
        self.row = row
        self.recipient = recipient

    def get_manager(self, name):
        assert name == "aweb"
        return self

    async def fetch_one(self, query, message_id):
        assert message_id == self.row["message_id"]
        return dict(self.row)

    async def fetch_all(self, query, session_id):
        assert session_id == self.row["session_id"]
        return [{"did": self.row["from_did"]}, {"did": self.recipient}]


def retained_request(request_model):
    key, public_key = generate_keypair()
    sender = did_from_public_key(public_key)
    recipient = "did:key:recipient"
    session_id, message_id = uuid4(), uuid4()
    timestamp = (
        (datetime.now(timezone.utc) - timedelta(seconds=600))
        .replace(microsecond=0)
        .isoformat()
    )
    encoded = canonical_json_bytes(
        {
            "type": "chat",
            "from_did": sender,
            "to_did": recipient,
            "conversation_id": str(session_id),
            "message_id": str(message_id),
            "body": "accepted original",
            "timestamp": timestamp,
        }
    )
    fields = dict(
        from_did=sender,
        message_id=str(message_id),
        timestamp=timestamp,
        signature=sign_message(key, encoded),
        signed_payload=encoded.decode(),
    )
    if request_model is CreateSessionRequest:
        request = request_model(
            message="accepted original",
            to_dids=[recipient],
            session_id=str(session_id),
            **fields,
        )
    else:
        request = request_model(body="accepted original", **fields)
    row = dict(
        message_id=message_id,
        session_id=session_id,
        from_did=sender,
        body="accepted original",
        content_mode="legacy_plaintext_v1",
        message_version=1,
        sender_leaving=False,
        hang_on=False,
        reply_to=None,
        encrypted_envelope=None,
        signature=request.signature,
        signed_payload=request.signed_payload,
    )
    auth = MessagingAuth(did_key=sender, did_aw=None, address=None)
    return StoredChatSnapshot(row, recipient), request, auth, session_id, recipient, key


async def stored_answer(snapshot, request, auth, session_id, recipient):
    return await _stored_exact_chat_send(
        snapshot,
        request,
        auth=auth,
        session_id=session_id,
        recipient_rows=[{"did": recipient, "did_key": recipient}],
        actor_dids=[auth.did_key],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("request_model", [CreateSessionRequest, SendMessageRequest])
async def test_exact_plaintext_chat_artifact_retains_answer_after_age(request_model):
    snapshot, request, auth, session_id, recipient, key = retained_request(
        request_model
    )
    result = await stored_answer(snapshot, request, auth, session_id, recipient)
    assert result["message_id"] == UUID(request.message_id)
    assert result["session_id"] == session_id
    assert result["body"] == "accepted original"


@pytest.mark.asyncio
@pytest.mark.parametrize("request_model", [CreateSessionRequest, SendMessageRequest])
async def test_legacy_stored_signature_never_becomes_verified_by_being_stored(
    request_model,
):
    snapshot, request, auth, session_id, recipient, key = retained_request(
        request_model
    )
    invalid = base64.b64encode(bytes(64)).decode().rstrip("=")
    snapshot.row["signature"] = invalid
    request = request.model_copy(update={"signature": invalid})
    with pytest.raises(DeliveryRefusal) as refused:
        await stored_answer(snapshot, request, auth, session_id, recipient)
    assert refused.value.status_code == 422
    assert refused.value.detail == (
        "The message signature does not verify. Sign the message again with the authenticated sender's key and resend it."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("request_model", [CreateSessionRequest, SendMessageRequest])
async def test_changed_chat_artifact_has_no_plaintext_age_exemption(request_model):
    snapshot, request, auth, session_id, recipient, key = retained_request(
        request_model
    )
    field = "message" if request_model is CreateSessionRequest else "body"
    import json

    signed = json.loads(request.signed_payload)
    signed["body"] = "changed request"
    encoded = canonical_json_bytes(signed)
    request = request.model_copy(
        update={
            field: "changed request",
            "signed_payload": encoded.decode(),
            "signature": sign_message(key, encoded),
        }
    )
    with pytest.raises(DeliveryRefusal) as refused:
        await stored_answer(snapshot, request, auth, session_id, recipient)
    assert refused.value.status_code == 422
    assert (
        refused.value.headers["X-AWEB-Error-Code"] == "message_timestamp_outside_skew"
    )


def test_race_classifier_distinguishes_pinned_pgdbm_wrapper_from_other_queries():
    unique = asyncpg.exceptions.UniqueViolationError("duplicate key")
    wrapped = QueryError("query failed", original_error=unique)
    wrapped.__cause__ = unique
    unrelated = QueryError("unrelated query failure")
    assert is_unique_write_conflict(unique)
    assert is_unique_write_conflict(wrapped)
    assert not is_unique_write_conflict(unrelated)
    assert not is_unique_write_conflict(
        asyncpg.exceptions.ForeignKeyViolationError("missing parent")
    )


@pytest.mark.asyncio
async def test_continued_retry_uses_recorded_participant_did_despite_richer_current_projection():
    snapshot, request, auth, session_id, recipient, _ = retained_request(
        SendMessageRequest
    )
    result = await _stored_exact_chat_send(
        snapshot,
        request,
        auth=auth,
        session_id=session_id,
        actor_dids=[auth.did_key],
        recipient_rows=[
            {
                "did": recipient,
                "did_key": recipient,
                "did_aw": "did:aw:current-projection",
            }
        ],
    )
    assert result["message_id"] == UUID(request.message_id)


@pytest.mark.asyncio
async def test_exact_aged_artifact_with_changed_parties_never_requests_another_signature():
    from aweb.service_errors import ConflictError

    snapshot, request, auth, session_id, _, _ = retained_request(SendMessageRequest)
    with pytest.raises(ConflictError) as refused:
        await _stored_exact_chat_send(
            snapshot,
            request,
            auth=auth,
            session_id=session_id,
            actor_dids=[auth.did_key],
            recipient_rows=[{"did_key": "did:key:different-recipient"}],
        )
    assert refused.value.detail == (
        "The stored chat participants differ from the resolved recipients. Retry the original conversation and recipient identities unchanged."
    )

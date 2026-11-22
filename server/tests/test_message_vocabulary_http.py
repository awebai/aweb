# ruff: noqa: F811 -- pytest imports the real shared fixture by name.
"""Real native HTTP requests are observed before exact replay suppresses hooks."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from awid.signing import canonical_json_bytes, sign_message
from aweb.message_vocabulary import MessageInputSource, UNNAMED_MESSAGE_VOCABULARY
from test_dashboard_privacy import privacy_app as privacy_app
from test_delivery_contract_regressions import _send

__all__ = ["privacy_app"]


@pytest.mark.asyncio
async def test_accepted_mail_mode_is_observed_on_exact_retry_without_another_event(
    privacy_app,
):
    env = privacy_app
    alice, bob = env.actors["alice"], env.actors["bob"]
    message_id, conversation_id = str(uuid4()), str(uuid4())
    signed = {
        "type": "mail",
        "from": "alice",
        "from_did": alice.did,
        "body": "preserved",
        "subject": "",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "timestamp": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    original = canonical_json_bytes(signed).decode()
    payload = {
        "to_did": bob.did,
        "from_did": alice.did,
        "body": signed["body"],
        "message_id": message_id,
        "conversation_id": conversation_id,
        "timestamp": signed["timestamp"],
        "signed_payload": original,
        "signature": sign_message(alice.sk, original.encode()),
        "content_mode": " accepted opaque mode ",
    }
    counter = UNNAMED_MESSAGE_VOCABULARY.labels(
        source=MessageInputSource.MAIL_SEND.value,
        field="content_mode",
    )
    before = counter._value.get()
    first = await _send(env, payload)
    assert first.status_code == 200, first.text
    retry = await _send(env, payload)
    assert retry.status_code == 200, retry.text
    assert retry.json()["message_id"] == first.json()["message_id"]
    assert counter._value.get() == before + 2
    events = [
        (name, context) for name, context in env.dispatched if name == "message.sent"
    ]
    assert len(events) == 1
    assert events[0][1]["content_mode"] == payload["content_mode"]
    row = await env.db.fetch_one(
        "SELECT signed_payload, content_mode FROM {{tables.messages}} WHERE message_id=$1",
        UUID(message_id),
    )
    assert row["signed_payload"] == original
    # Storage keeps its existing canonical plaintext mode; only the callback
    # carries the accepted raw metadata observed at ingress.
    assert row["content_mode"] == "legacy_plaintext_v1"

# ruff: noqa: F811 -- shared real-stack fixture is imported for pytest.
"""Native chat commits its policy decision and publishes only visible messages."""

import asyncio
from datetime import datetime, timezone
from enum import Enum, auto
from uuid import UUID, uuid4

import asyncpg
import pytest

from awid.signing import canonical_json_bytes, sign_message
from aweb.event_types import MutationEventType
from test_dashboard_privacy import _request, privacy_app as privacy_app
from test_native_mail_admission_commit import (
    PolicyChange,
    apply_test_policy_change,
    prepare_test_policy_members,
)

__all__ = ["privacy_app"]


class ChatPath(Enum):
    NEW_SESSION = auto()
    CONTINUATION = auto()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", list(ChatPath))
@pytest.mark.parametrize("change", list(PolicyChange))
async def test_native_chat_admission_stays_locked_through_the_actual_message_commit(
    privacy_app,
    path,
    change,
):
    env = privacy_app
    bob = await prepare_test_policy_members(env)
    url = "/v1/chat/sessions"
    payload = {"to_dids": [bob.did_key], "message": "Held chat"}
    count_before = 0
    if path is ChatPath.CONTINUATION:
        initial = await _request(env, "alice", "POST", url, payload)
        assert initial.status_code == 200, initial.text
        url += "/" + initial.json()["session_id"] + "/messages"
        payload = {"body": "Held continuation"}
        count_before = 1
    events_before = list(env.dispatched)
    async with env.db.transaction() as blocker:
        await blocker.execute("LOCK TABLE {{tables.chat_messages}} IN SHARE MODE")
        sending = asyncio.create_task(_request(env, "alice", "POST", url, payload))
        try:
            async with asyncio.timeout(5):
                while not await env.db.fetch_value(
                    "SELECT count(*) FROM pg_locks WHERE relation='aweb.chat_messages'::regclass "
                    "AND mode='RowExclusiveLock' AND NOT granted"
                ):
                    if sending.done():
                        raise AssertionError(
                            "Chat ended before its actual INSERT barrier"
                        )
                    await asyncio.sleep(0.01)
            assert env.dispatched == events_before
            async with env.db.transaction() as changing:
                await changing.execute("SET LOCAL lock_timeout='200ms'")
                with pytest.raises(asyncpg.LockNotAvailableError):
                    await apply_test_policy_change(changing, env, change, bob)
        except BaseException:
            sending.cancel()
            await asyncio.gather(sending, return_exceptions=True)
            raise
    sent = await sending
    assert sent.status_code == 200, sent.text
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}")
        == count_before + 1
    )
    assert len(env.dispatched) == len(events_before) + 1
    async with env.db.transaction() as changing:
        await apply_test_policy_change(changing, env, change, bob)
    if change is PolicyChange.RECIPIENT_MODE:
        refused = await _request(env, "alice", "POST", url, payload)
        assert refused.status_code == 403, refused.text
        assert refused.json()["detail"].endswith(
            "Ask the recipient to add your exact address as a contact or check their inbound policy."
        )
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}")
            == count_before + 1
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("valid_signature", [False, True])
async def test_native_chat_signature_refusal_rolls_back_session_and_success_hook_reads_committed_row(
    privacy_app,
    valid_signature,
):
    env = privacy_app
    alice, bob = env.actors["alice"], env.actors["bob"]
    message_id, session_id = str(uuid4()), str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed = canonical_json_bytes(
        dict(
            type="chat",
            **{"from": alice.did},
            from_did=alice.did,
            to=bob.did,
            to_did=bob.did,
            body="Signature boundary",
            conversation_id=session_id,
            message_id=message_id,
            timestamp=timestamp,
            wait_seconds=0,
        )
    ).decode()
    original_callback = env.app.state.on_mutation
    visible_at_callback = []

    async def observe_committed_message(event, context):
        if event == MutationEventType.CHAT_MESSAGE_SENT:
            visible_at_callback.append(
                await env.db.fetch_value(
                    "SELECT count(*) FROM {{tables.chat_messages}} WHERE message_id=$1",
                    UUID(context["message_id"]),
                )
            )
        await original_callback(event, context)

    env.app.state.on_mutation = observe_committed_message
    response = await _request(
        env,
        "alice",
        "POST",
        "/v1/chat/sessions",
        {
            "to_dids": [bob.did],
            "session_id": session_id,
            "message_id": message_id,
            "message": "Signature boundary",
            "from_did": alice.did,
            "timestamp": timestamp,
            "wait_seconds": 0,
            "signed_payload": signed,
            "signature": sign_message(
                alice.sk if valid_signature else env.actors["carol"].sk, signed.encode()
            ),
        },
    )
    if valid_signature:
        assert response.status_code == 200, response.text
        assert visible_at_callback == [1]
    else:
        assert response.status_code == 422, response.text
        assert response.json()["detail"] == (
            "The message signature does not verify. Sign the message again with the authenticated sender's key and resend it."
        )
        assert visible_at_callback == []
        assert env.dispatched == []
        for table in (
            "chat_sessions",
            "chat_participants",
            "chat_messages",
            "conversations",
            "conversation_participants",
            "chat_read_receipts",
        ):
            assert (
                await env.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}")
                == 0
            )

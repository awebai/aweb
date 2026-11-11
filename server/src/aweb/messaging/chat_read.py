"""Marking chat read: a participant records the messages of a session it has read."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from aweb.agent_wake import agent_wake_scope
from aweb.events import publish_chat_session_signal
from aweb.identity_auth_deps import MessagingAuth, participant_dids
from aweb.messaging.chat import mark_messages_read, mark_messages_read_up_to, resolve_session_actor_did
from aweb.messaging.chat_send import _resolve_actor_agent
from aweb.messaging.runtime import MessagingRuntime


async def mark_chat_read(
    db,
    redis,
    auth: MessagingAuth,
    runtime: MessagingRuntime,
    *,
    session_id: UUID,
    message_ids: list[str] | None,
    up_to_message_id: str | None,
) -> dict[str, Any] | None:
    """Mark messages of a session read for ``auth``, or return None when it is not a participant.

    ``message_ids`` names the messages and takes precedence; otherwise every
    message up to ``up_to_message_id`` is marked. Wakes the reader's streams
    and, when a message was newly marked and there is a Redis, signals the
    session's streams with a ``read_receipt``.
    """
    actor_dids = participant_dids(auth)
    actor_agent = await _resolve_actor_agent(db, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    actor_did = await resolve_session_actor_did(db, session_id=session_id, actor_dids=actor_dids)
    if not actor_did:
        return None

    with agent_wake_scope(runtime.agent_wake_publisher):
        if message_ids is not None:
            result = await mark_messages_read(
                db,
                session_id=session_id,
                participant_did=actor_did,
                participant_agent_id=actor_agent_id,
                message_ids=message_ids,
            )
        else:
            assert up_to_message_id is not None
            result = await mark_messages_read_up_to(
                db,
                session_id=session_id,
                participant_did=actor_did,
                participant_agent_id=actor_agent_id,
                up_to_message_id=up_to_message_id,
            )

    if redis is not None and int(result["messages_marked"] or 0) > 0:
        await publish_chat_session_signal(
            redis,
            session_id=str(session_id),
            signal_type="read_receipt",
            agent_id=actor_did,
            message_id=message_ids[-1] if message_ids is not None else up_to_message_id,
        )
    return result

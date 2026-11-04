"""Per-agent SSE event stream — lightweight wake signals."""

from __future__ import annotations

from aweb.messaging.participant_succession import MailSuccessionScope, load_mail_succession_scope

import asyncio
import json
import logging
import random
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from time import monotonic
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from aweb.app_events import (
    AppEventAuth,
    AppEventRecord,
    AppEventSubscription,
    current_app_events_for_agent,
    delete_app_event_subscription,
    emit_app_event,
    list_app_event_subscriptions,
    upsert_app_event_subscription,
    verify_app_event_auth,
)
from aweb.agent_health import LISTENING_REFRESH_SECONDS, record_stream_listening
from aweb.agent_wake import (
    agent_wake_key,
    agent_wake_publisher,
    agent_wake_scope,
    did_wake_key,
    read_wake_marks,
    team_room_wake_key,
)
from aweb.deps import get_db, get_redis
from aweb.identity_metadata import lookup_identity_metadata_by_did, routable_chat_address
from aweb.messaging.chat import get_pending_conversations
from aweb.messaging.room_notices import RoomAuthorityWindow, current_room_events
from aweb.messaging.waiting import get_waiting_agents, get_waiting_agents_by_session
from aweb.internal_auth import parse_internal_auth_context
from aweb.grant_streams import (
    GRANT_STREAM_RECHECK_SECONDS,
    agent_event_allowed,
    clamp_deadline_to_grant,
    grant_has_scope,
    NeverGrantStreamGuard, grant_expiry_reason,
    grant_terminal_sse,
    require_valid_stream_grant,
)
from aweb.service_errors import ServiceError
from aweb.team_auth_deps import TeamIdentity, get_team_identity, team_identity_with_grant_scope

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/events", tags=["aweb-events"])

EVENTS_RECONCILE_INTERVAL = 15.0  # seconds between wake-counter reconciles
EVENTS_SNAPSHOT_RETRY_INITIAL = 1.0  # first retry delay after a failed snapshot
EVENTS_SNAPSHOT_FAILURE_WINDOW = 30.0  # tolerate bursts; terminate only after >30s
EVENTS_SNAPSHOT_MAX_BACKOFF = 5.0  # cap snapshot retry delay
EVENTS_HEARTBEAT_INTERVAL = 30.0  # seconds between idle SSE heartbeat comments
MAX_STREAM_DURATION = 300  # maximum stream lifetime in seconds

# Snapshot and emission order, and the field each kind's events are keyed by.
STREAM_KINDS = ("mail", "chat", "control", "app", "room")
_STREAM_KEY_FIELDS = {
    "mail": "message_id",
    "chat": "session_id",
    "app": "event_id",
    "room": "message_id",
}


class AppEventEmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., min_length=1, max_length=256)
    resource_ref: str | None = Field(None, max_length=1024)
    delivery_intent: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class AppEventEmitResponse(BaseModel):
    event_id: str
    team_id: str
    app_id: str
    type: str
    resource_ref: str | None = None
    delivery_intent: str
    created_at: str


class AppEventSubscriptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., min_length=1, max_length=256)
    resource_ref: str | None = Field(None, max_length=1024)
    delivery_intent: str | None = None


class AppEventSubscriptionResponse(BaseModel):
    subscription_id: str
    team_id: str
    agent_id: str
    type: str
    resource_ref: str | None = None
    delivery_intent: str
    created_at: str
    updated_at: str


class AppEventSubscriptionsResponse(BaseModel):
    subscriptions: list[AppEventSubscriptionResponse]


def _parse_deadline(raw: str) -> datetime:
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _mail_wake_mode(priority: str | None) -> str:
    normalized = (priority or "normal").strip().lower()
    if normalized in {"high", "urgent"}:
        return "prompt"
    return "idle"


def _chat_wake_mode(*, sender_waiting: bool) -> str:
    return "interrupt" if sender_waiting else "prompt"


def _app_event_response(record: AppEventRecord) -> AppEventEmitResponse:
    return AppEventEmitResponse(
        event_id=record.event_id,
        team_id=record.team_id,
        app_id=record.app_id,
        type=record.event_type,
        resource_ref=record.resource_ref,
        delivery_intent=record.delivery_intent,
        created_at=record.created_at,
    )


def _subscription_response(subscription: AppEventSubscription) -> AppEventSubscriptionResponse:
    return AppEventSubscriptionResponse(
        subscription_id=subscription.subscription_id,
        team_id=subscription.team_id,
        agent_id=subscription.agent_id,
        type=subscription.event_type,
        resource_ref=subscription.resource_ref,
        delivery_intent=subscription.delivery_intent,
        created_at=subscription.created_at,
        updated_at=subscription.updated_at,
    )


async def _subscription_read_identity(request: Request, db) -> tuple[str, str]:
    internal = parse_internal_auth_context(request)
    if internal is not None:
        return internal["team_id"], internal["actor_id"]
    identity = await get_team_identity(request, db)
    return identity.team_id, identity.agent_id


async def _current_actionable_mail(
    aweb_db, *, inbox_dids: list[str], mail_scope: MailSuccessionScope
) -> list[dict[str, Any]]:
    """Return unread incoming mail using preloaded, exact thread evidence."""
    args: list[Any] = [inbox_dids]
    targets = ["m.to_did = ANY($1::text[])"]
    senders = ["m.from_did = ANY($1::text[])"]
    for dids, conversations in mail_scope.identity_threads:
        did_param, conversation_param = len(args) + 1, len(args) + 2
        args.extend((list(dids), list(conversations)))
        for field, clauses in (("to_did", targets), ("from_did", senders)):
            clauses.append(
                f"(m.{field} = ANY(${did_param}::text[]) "
                f"AND m.conversation_id = ANY(${conversation_param}::uuid[]))"
            )
    # Exact current targets retain legacy/no-conversation wake delivery. Extra
    # identities require their recorded thread, on BOTH sides of attribution.
    # A merged predecessor's outgoing mail is not incoming even if sent to H.
    predicate = (
        f"({' OR '.join(targets)}) "
        f"AND NOT COALESCE(({' OR '.join(senders)}), FALSE)"
    )
    rows = await aweb_db.fetch_all(
        f"""
        WITH unread AS (
            SELECT message_id, conversation_id, from_did, from_alias, from_address, subject, priority,
                   created_at, content_mode, message_version
            FROM {{{{tables.messages}}}} m
            WHERE {predicate}
              AND read_at IS NULL
        ),
        windowed AS (
            SELECT message_id, conversation_id, from_did, from_alias, from_address, subject, priority,
                   created_at, content_mode, message_version
            FROM unread
            ORDER BY created_at DESC, message_id DESC
            LIMIT 50
        )
        SELECT
            message_id,
            COALESCE(conversation_id, message_id)::text AS conversation_id,
            from_did,
            from_alias,
            from_address,
            subject,
            priority,
            content_mode,
            message_version,
            created_at,
            (SELECT COUNT(*)::int FROM unread) AS unread_count
        FROM windowed
        ORDER BY created_at ASC, message_id ASC
        """,
        *args,
    )
    sender_map = await lookup_identity_metadata_by_did(
        aweb_db,
        [str(row["from_did"]).strip() for row in rows if row.get("from_did")],
    )
    return [
        {
            "type": "actionable_mail",
            "message_id": str(r["message_id"]),
            "conversation_id": str(r["conversation_id"]),
            "from_alias": r["from_alias"],
            "from_did": (r.get("from_did") or "").strip(),
            "from_stable_id": sender_map.get((r.get("from_did") or "").strip(), {}).get("stable_id", ""),
            "from_address": (
                r.get("from_address")
                or sender_map.get((r.get("from_did") or "").strip(), {}).get("address")
                or r["from_alias"]
                or ""
            ),
            "subject": "" if r.get("content_mode") == "encrypted_v2" else (r["subject"] or ""),
            "priority": (r.get("priority") or "normal").strip().lower(),
            "content_mode": r.get("content_mode") or "legacy_plaintext_v1",
            "message_version": int(r.get("message_version") or 1),
            "encrypted": r.get("content_mode") == "encrypted_v2",
            "unread_count": int(r.get("unread_count") or 0),
            "wake_mode": _mail_wake_mode(r.get("priority")),
            "created_at": r["created_at"].astimezone(timezone.utc).isoformat(),
        }
        for r in rows
    ]


def _identity_dids(viewer: dict[str, Any] | None, identity: TeamIdentity | None = None) -> list[str]:
    dids: list[str] = []
    for value in (
        (getattr(identity, "did_aw", None) or "").strip(),
        (getattr(identity, "did_key", None) or "").strip(),
        (viewer.get("did_aw") if viewer else "") or "",
        (viewer.get("did_key") if viewer else "") or "",
    ):
        value = value.strip()
        if value and value not in dids:
            dids.append(value)
    return dids


ChatWaitingState = dict[str, tuple[tuple[str, ...], bool, bool]]


async def _chat_waiting_state(redis, *, viewer_dids: list[str], other_dids: dict[str, list[str]]) -> ChatWaitingState:
    """Per pending session: its other participants, whether the viewer waits in
    it, and whether another participant waits in it. Read from Redis only."""
    viewer_waiting = await get_waiting_agents_by_session(
        redis,
        {session_id: viewer_dids for session_id in other_dids},
    )
    state: ChatWaitingState = {}
    for session_id, others in other_dids.items():
        state[session_id] = (
            tuple(others),
            bool(viewer_waiting.get(session_id)),
            bool(await get_waiting_agents(redis, session_id, others)),
        )
    return state


async def _chat_waiting_changed(redis, *, viewer_dids: list[str], held: ChatWaitingState) -> bool:
    if not held:
        return False
    current = await _chat_waiting_state(
        redis,
        viewer_dids=viewer_dids,
        other_dids={session_id: list(others) for session_id, (others, _, _) in held.items()},
    )
    return current != held


async def _current_actionable_chat(
    db,
    redis,
    *,
    participant_dids: list[str],
    viewer_team_id: str | None,
    participant_agent_id: str | None = None,
    waiting_state: ChatWaitingState | None = None,
) -> list[dict[str, Any]]:
    """Return the current actionable unread chat state for an identity.

    ``waiting_state``, when given, receives the Redis waiting state the
    result depended on, so a stream can notice when only that state changes.
    """
    pending_by_session: dict[str, dict[str, Any]] = {}
    viewer_did_set = set(participant_dids)
    for participant_did in participant_dids:
        pending = await get_pending_conversations(
            db,
            participant_did=participant_did,
            participant_agent_id=participant_agent_id,
        )
        for item in pending:
            pending_by_session.setdefault(item["session_id"], item)
    actionable: list[dict[str, Any]] = []
    participant_identity_map = await lookup_identity_metadata_by_did(
        db,
        [
            did
            for item in pending_by_session.values()
            for did in list(item.get("participant_dids", []) or [])
            + ([(item.get("last_from_did") or "").strip()] if item.get("last_from_did") else [])
        ],
    )
    state = await _chat_waiting_state(
        redis,
        viewer_dids=participant_dids,
        other_dids={
            session_id: [did for did in item.get("participant_dids", []) if did not in viewer_did_set]
            for session_id, item in pending_by_session.items()
        },
    )
    if waiting_state is not None:
        waiting_state.clear()
        waiting_state.update(state)
    for item in pending_by_session.values():
        _, recipient_waiting, sender_waiting = state[item["session_id"]]
        # A recipient already waiting in this session receives chat in-process.
        # Leave unread state untouched so a later snapshot can wake after they leave.
        if recipient_waiting:
            continue
        last_activity = item.get("last_activity")
        actionable.append(
            {
                "type": "actionable_chat",
                "session_id": item["session_id"],
                "conversation_id": item["session_id"],
                "participants": list(item.get("participants") or []),
                "participant_addresses": [
                    (address or "").strip() or routable_chat_address(
                        participant_identity_map.get((did or "").strip(), {}),
                        viewer_team_id,
                        alias or "",
                    )
                    for did, alias, address in zip(
                        list(item.get("participant_dids") or []),
                        list(item.get("participants") or []),
                        list(item.get("participant_addresses") or []),
                        strict=False,
                    )
                    if (did or "").strip() not in viewer_did_set
                ],
                "from_alias": item.get("last_from") or "",
                "from_did": (item.get("last_from_did") or "").strip(),
                "from_stable_id": participant_identity_map.get(
                    (item.get("last_from_did") or "").strip(), {}
                ).get("stable_id", ""),
                "from_address": item.get("last_from_address") or routable_chat_address(
                    participant_identity_map.get((item.get("last_from_did") or "").strip(), {}),
                    viewer_team_id,
                    item.get("last_from") or "",
                ),
                "last_from": item.get("last_from") or "",
                "last_from_address": item.get("last_from_address") or routable_chat_address(
                    participant_identity_map.get((item.get("last_from_did") or "").strip(), {}),
                    viewer_team_id,
                    item.get("last_from") or "",
                ),
                "last_message": item.get("last_message") or "",
                "last_activity": (
                    last_activity.astimezone(timezone.utc).isoformat() if last_activity else ""
                ),
                "unread_count": int(item.get("unread_count") or 0),
                "sender_waiting": sender_waiting,
                "wake_mode": _chat_wake_mode(sender_waiting=sender_waiting),
            }
        )
    return actionable


def _index_events(events: list[dict[str, Any]], *, key_field: str) -> dict[str, dict[str, Any]]:
    return {str(evt[key_field]): evt for evt in events}


def _new_or_changed_events(
    current: list[dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    *,
    key_field: str,
    ignored_fields: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    changed: list[dict[str, Any]] = []
    for evt in current:
        key = str(evt[key_field])
        previous_event = previous.get(key)
        if previous_event is None or {
            field: value for field, value in previous_event.items() if field not in ignored_fields
        } != {field: value for field, value in evt.items() if field not in ignored_fields}:
            changed.append(evt)
    return changed


def _new_or_changed_mail_events(
    current: list[dict[str, Any]],
    previous: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    changed = _new_or_changed_events(
        current,
        previous,
        key_field="message_id",
        ignored_fields=frozenset({"unread_count"}),
    )
    if changed:
        return changed

    # Actionable mail is ordered oldest-to-newest, so a count-only change uses
    # the newest current row as its single deterministic representative.
    for evt in reversed(current):
        previous_event = previous.get(str(evt["message_id"]))
        if previous_event is not None and previous_event.get("unread_count") != evt.get(
            "unread_count"
        ):
            return [evt]
    return []


async def _poll_control_signals(aweb_db, *, team_id: str, agent_id: UUID) -> list[dict]:
    """Consume and return pending control signals for this agent.

    At-most-once delivery: signals are marked consumed atomically with the read.
    If the connection drops before the client receives the SSE frame, the signal
    is lost.  Acceptable for wake-signal semantics where clients re-fetch state
    after reconnecting.
    """
    rows = await aweb_db.fetch_all(
        """
        UPDATE {{tables.control_signals}}
        SET consumed_at = NOW()
        WHERE signal_id IN (
            SELECT signal_id FROM {{tables.control_signals}}
            WHERE team_id = $1
              AND target_agent_id = $2
              AND consumed_at IS NULL
            ORDER BY created_at ASC
            LIMIT 10
        )
        RETURNING signal_id, signal_type, created_at
        """,
        team_id,
        agent_id,
    )
    return [
        {
            "type": f"control_{r['signal_type']}",
            "signal_id": str(r["signal_id"]),
        }
        for r in rows
    ]


def _sse_frame(evt: dict[str, Any]) -> str:
    return f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"


def _stream_wake_keys(identity: TeamIdentity, viewer_dids: list[str]) -> list[str]:
    keys = [did_wake_key(did) for did in viewer_dids]
    keys.append(agent_wake_key(identity.agent_id))
    if grant_has_scope(identity, "chat.read"):
        keys.append(team_room_wake_key(identity.team_id))
    return keys


async def _read_stream_marks(redis, keys: list[str]) -> dict[tuple[str, str], str | None] | None:
    """The stream's wake counters, or None when Redis cannot answer."""
    if redis is None:
        return None
    try:
        return await read_wake_marks(redis, keys)
    except Exception:
        logger.warning("Agent wake counters unavailable; reconciling from Postgres", exc_info=True)
        return None


def _moved_kinds(
    marks: dict[tuple[str, str], str | None] | None,
    current: dict[tuple[str, str], str | None] | None,
) -> set[str]:
    """Kinds whose counter moved; every kind when either side is unknown."""
    if marks is None or current is None:
        return set(STREAM_KINDS)
    return {mark[1] for mark, value in current.items() if value != marks.get(mark)}


@asynccontextmanager
async def _wake_subscription(hub, keys: list[str]):
    if hub is None:
        yield None
        return
    async with hub.subscribe(keys) as subscription:
        yield subscription


async def _wait_for_wake(subscription, timeout: float) -> None:
    if timeout <= 0:
        return
    if subscription is None:
        await asyncio.sleep(timeout)
        return
    try:
        await asyncio.wait_for(subscription.wait(), timeout)
    except TimeoutError:
        pass


async def _sse_agent_events(
    *,
    request: Request,
    db,
    redis,
    team_id: str,
    agent_id: str,
    identity: TeamIdentity,
    deadline: datetime,
    wake_hub=None,
) -> AsyncIterator[str]:
    """Generate per-agent SSE actionable coordination events.

    State is read from Postgres at open, then again only for the kinds a wake
    names, or whose wake counter moved at the slow reconcile. Disconnects are
    found by the failed write of a heartbeat or event, not by probing.
    """
    aweb_db = db.get_manager("aweb")
    aid = UUID(agent_id)
    viewer = await aweb_db.fetch_one(
        """
        SELECT CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, did_key
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND deleted_at IS NULL
        """,
        aid,
    )
    viewer_dids = _identity_dids(viewer, identity)
    if not viewer_dids:
        yield f"event: error\ndata: {json.dumps({'type': 'error', 'detail': 'identity incomplete'})}\n\n"
        return

    room_authority = RoomAuthorityWindow()
    previous: dict[str, dict[str, dict[str, Any]]] = {kind: {} for kind in STREAM_KINDS}
    chat_waiting: ChatWaitingState = {}

    async def snapshot(kinds: set[str]) -> dict[str, list[dict[str, Any]]]:
        """Current events per kind; control signals are consumed by reading them."""
        current: dict[str, list[dict[str, Any]]] = {}
        if "mail" in kinds:
            current["mail"] = await _current_actionable_mail(
                aweb_db, inbox_dids=viewer_dids, mail_scope=mail_scope
            )
        if "chat" in kinds:
            current["chat"] = await _current_actionable_chat(
                db,
                redis,
                participant_dids=viewer_dids,
                viewer_team_id=team_id,
                participant_agent_id=agent_id,
                waiting_state=chat_waiting,
            )
        if "control" in kinds:
            current["control"] = await _poll_control_signals(aweb_db, team_id=team_id, agent_id=aid)
        if "app" in kinds:
            current["app"] = await current_app_events_for_agent(aweb_db, team_id=team_id, agent_id=agent_id)
        if "room" in kinds:
            current["room"] = await current_room_events(request, db, identity, room_authority)
        return current

    def changes(current: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        """Events to emit, in kind order; records each kind's new state."""
        emitted: list[dict[str, Any]] = []
        for kind in STREAM_KINDS:
            if kind not in current:
                continue
            events = current[kind]
            if kind == "control":
                emitted.extend(events)
                continue
            key_field = _STREAM_KEY_FIELDS[kind]
            if kind == "mail":
                emitted.extend(_new_or_changed_mail_events(events, previous[kind]))
            else:
                emitted.extend(_new_or_changed_events(events, previous[kind], key_field=key_field))
            previous[kind] = _index_events(events, key_field=key_field)
        return emitted

    async with _wake_subscription(wake_hub, _stream_wake_keys(identity, viewer_dids)) as subscription:
        keys = list(subscription.keys) if subscription is not None else []
        marks = await _read_stream_marks(redis, keys) if subscription is not None else None

        yield ": keepalive\n\n"
        last_heartbeat_at = datetime.now(timezone.utc)

        yield f"event: connected\ndata: {json.dumps({'agent_id': agent_id, 'team_id': team_id})}\n\n"
        await record_stream_listening(redis, agent_id, now=datetime.now(timezone.utc))
        listening_recorded_at = monotonic()

        guard = NeverGrantStreamGuard(request, db, identity, grant_expiry_reason)
        reason = await guard.reason()
        if reason:
            yield grant_terminal_sse(reason)
            return

        # Thread evidence is immutable for this stream lifetime, not a per-snapshot read.
        mail_scope = await load_mail_succession_scope(aweb_db, viewer_dids=viewer_dids)
        initial = changes(await snapshot(set(STREAM_KINDS)))

        reason = await guard.reason()
        if reason:
            yield grant_terminal_sse(reason)
            return
        # The caller deadline bounds waiting, not the initial scoped snapshot.
        # Grant expiry still blocks delivery above, even for an expired deadline.

        for evt in initial:
            if evt["type"] == "actionable_room_post" and not room_authority.fresh():
                continue
            if agent_event_allowed(identity, evt):
                yield _sse_frame(evt)

        # Streams opened together reconcile apart.
        next_reconcile_at = monotonic() + random.uniform(0, EVENTS_RECONCILE_INTERVAL)
        pending: set[str] = set()
        failure_started_at: float | None = None
        retry_delay = EVENTS_SNAPSHOT_RETRY_INITIAL
        retry_at = 0.0
        while datetime.now(timezone.utc) < deadline:
            now = monotonic()
            due = [
                next_reconcile_at,
                listening_recorded_at + LISTENING_REFRESH_SECONDS,
                now + (deadline - datetime.now(timezone.utc)).total_seconds(),
                now + max(
                    0.0,
                    EVENTS_HEARTBEAT_INTERVAL
                    - (datetime.now(timezone.utc) - last_heartbeat_at).total_seconds(),
                ),
            ]
            if identity.grant is not None and identity.grant.never_expires:
                due.append(guard.checked_at + GRANT_STREAM_RECHECK_SECONDS)
            if pending:
                due.append(retry_at)
            await _wait_for_wake(subscription, min(due) - now)

            if datetime.now(timezone.utc) >= deadline:
                break

            if monotonic() - listening_recorded_at >= LISTENING_REFRESH_SECONDS:
                await record_stream_listening(redis, agent_id, now=datetime.now(timezone.utc))
                listening_recorded_at = monotonic()

            reason = await guard.reason()
            if reason:
                yield grant_terminal_sse(reason)
                return

            if subscription is not None:
                batch = subscription.take()
                pending |= batch.kinds
                if batch.resync:
                    pending |= set(STREAM_KINDS)
            if monotonic() >= next_reconcile_at:
                next_reconcile_at = monotonic() + EVENTS_RECONCILE_INTERVAL
                if subscription is None:
                    pending |= set(STREAM_KINDS)
                else:
                    current_marks = await _read_stream_marks(redis, keys)
                    pending |= _moved_kinds(marks, current_marks)
                    # Waiting presence expires in Redis without any write.
                    if "chat" not in pending and await _chat_waiting_changed(
                        redis, viewer_dids=viewer_dids, held=chat_waiting
                    ):
                        pending.add("chat")

            emitted: list[dict[str, Any]] = []
            if pending and monotonic() >= retry_at:
                kinds = set(pending)
                try:
                    snapshot_marks = (
                        await _read_stream_marks(redis, keys) if subscription is not None else None
                    )
                    current = await snapshot(kinds)
                except Exception:
                    logger.exception("event-stream snapshot error for agent %s", agent_id)
                    now = monotonic()
                    if failure_started_at is None:
                        failure_started_at = now
                        retry_delay = EVENTS_SNAPSHOT_RETRY_INITIAL
                    elif now - failure_started_at > EVENTS_SNAPSHOT_FAILURE_WINDOW:
                        yield f"event: error\ndata: {json.dumps({'type': 'error', 'detail': 'poll failure'})}\n\n"
                        break
                    else:
                        retry_delay = min(retry_delay * 2, EVENTS_SNAPSHOT_MAX_BACKOFF)
                    retry_at = now + retry_delay
                else:
                    # Reset only after the complete snapshot, not a successful first query.
                    failure_started_at = None
                    retry_delay = EVENTS_SNAPSHOT_RETRY_INITIAL
                    retry_at = 0.0
                    pending -= kinds
                    if snapshot_marks is not None:
                        marks = snapshot_marks
                    emitted = changes(current)

            reason = await guard.reason()
            if reason:
                yield grant_terminal_sse(reason)
                return

            if datetime.now(timezone.utc) >= deadline:
                break

            delivered = False
            for evt in emitted:
                if evt["type"] == "actionable_room_post" and not room_authority.fresh():
                    # Never emit room content on authority older than 60 s.
                    previous["room"].pop(str(evt["message_id"]), None)
                    pending.add("room")
                    continue
                if agent_event_allowed(identity, evt):
                    yield _sse_frame(evt)
                    delivered = True

            now = datetime.now(timezone.utc)
            if delivered:
                last_heartbeat_at = now
            elif (now - last_heartbeat_at).total_seconds() >= EVENTS_HEARTBEAT_INTERVAL:
                yield ": keepalive\n\n"
                last_heartbeat_at = now

        reason = await guard.reason()
        if reason:
            yield grant_terminal_sse(reason)


@router.post("/app", response_model=AppEventEmitResponse)
async def emit_app_event_route(
    request: Request,
    payload: AppEventEmitRequest,
    db=Depends(get_db),
) -> AppEventEmitResponse:
    aweb_db = db.get_manager("aweb")
    try:
        auth = await verify_app_event_auth(request, aweb_db)
        with agent_wake_scope(agent_wake_publisher(request.app.state)):
            record = await emit_app_event(
                aweb_db,
                auth=auth,
                event_type=payload.type,
                resource_ref=payload.resource_ref,
                producer_delivery_intent=payload.delivery_intent,
                payload=payload.payload,
            )
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return _app_event_response(record)


@router.post("/subscriptions", response_model=AppEventSubscriptionResponse)
async def upsert_app_event_subscription_route(
    request: Request,
    payload: AppEventSubscriptionRequest,
    db=Depends(get_db),
) -> AppEventSubscriptionResponse:
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")
    try:
        with agent_wake_scope(agent_wake_publisher(request.app.state)):
            subscription = await upsert_app_event_subscription(
                aweb_db,
                team_id=identity.team_id,
                agent_id=identity.agent_id,
                event_type=payload.type,
                resource_ref=payload.resource_ref,
                delivery_intent=payload.delivery_intent,
            )
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return _subscription_response(subscription)


@router.get("/subscriptions", response_model=AppEventSubscriptionsResponse)
async def list_app_event_subscriptions_route(
    request: Request,
    db=Depends(get_db),
) -> AppEventSubscriptionsResponse:
    team_id, agent_id = await _subscription_read_identity(request, db)
    aweb_db = db.get_manager("aweb")
    subscriptions = await list_app_event_subscriptions(aweb_db, team_id=team_id, agent_id=agent_id)
    return AppEventSubscriptionsResponse(
        subscriptions=[_subscription_response(item) for item in subscriptions]
    )


@router.delete("/subscriptions/{subscription_id}")
async def delete_app_event_subscription_route(
    subscription_id: str,
    request: Request,
    db=Depends(get_db),
) -> dict[str, str]:
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")
    with agent_wake_scope(agent_wake_publisher(request.app.state)):
        deleted = await delete_app_event_subscription(
            aweb_db,
            team_id=identity.team_id,
            agent_id=identity.agent_id,
            subscription_id=subscription_id,
        )
    if not deleted:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return {"subscription_id": subscription_id, "status": "deleted"}


@router.get("/stream")
async def event_stream(
    request: Request,
    deadline: str = Query(..., min_length=1),
    db=Depends(get_db),
    redis=Depends(get_redis),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("events.read")),
):
    """Per-agent SSE event stream. Emits lightweight wake events when the agent
    has new mail, chat messages, or available work."""

    try:
        deadline_dt = _parse_deadline(deadline)
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Invalid deadline format")

    # Cap deadline so clients cannot hold connections open indefinitely.
    max_deadline = datetime.now(timezone.utc) + timedelta(seconds=MAX_STREAM_DURATION)
    if deadline_dt > max_deadline:
        deadline_dt = max_deadline
    deadline_dt = clamp_deadline_to_grant(deadline_dt, identity)

    await require_valid_stream_grant(request, db, identity)

    return StreamingResponse(
        _sse_agent_events(
            request=request,
            db=db,
            redis=redis,
            team_id=identity.team_id,
            agent_id=identity.agent_id,
            identity=identity,
            deadline=deadline_dt,
            wake_hub=getattr(request.app.state, "agent_wake_hub", None),
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

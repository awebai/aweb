"""MCP tools for real-time chat messaging."""

from __future__ import annotations

import asyncio
import json
import time
import uuid as uuid_mod
from datetime import datetime, timezone
from uuid import UUID

from aweb.messaging.chat import (
    HANG_ON_EXTENSION_SECONDS,
    ensure_session,
    get_agent_by_alias,
    get_message_history,
    get_pending_conversations,
    mark_messages_read,
    resolve_agent_by_did,
    send_in_session,
)
from aweb.messaging.alias_targets import (
    AmbiguousLocalAddressError,
    derive_team_address,
    get_agent_by_namespace_alias,
    namespace_exists,
)
from aweb.messaging.messages import evaluate_messaging_policy
from aweb.messaging.waiting import register_waiting, unregister_waiting
from aweb.mcp.auth import auth_dids, get_auth, primary_auth_did
from aweb.mcp.signing import (
    HostedMessageSigner,
    HostedMessageSigningError,
    sign_hosted_message,
)
from aweb.service_errors import ServiceError

MAX_TOTAL_WAIT_SECONDS = 600


def _actor_dids() -> list[str]:
    return auth_dids(get_auth())


def _actor_did() -> str:
    return primary_auth_did(get_auth())


def _actor_alias(actor_agent: dict | None) -> str:
    auth = get_auth()
    return (
        (auth.alias or "").strip()
        or (auth.address or "").strip()
        or ((actor_agent or {}).get("alias") or "").strip()
        or ((actor_agent or {}).get("address") or "").strip()
        or _actor_did()
    )


def _signed_timestamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_target_list(values: list[str]) -> str:
    cleaned = sorted({value.strip() for value in values if value and value.strip()})
    return ",".join(cleaned)


def _signed_from(auth, actor_alias: str) -> str:
    return (
        (actor_alias or "").strip()
        or (auth.address or "").strip()
        or (auth.did_aw or "").strip()
        or (auth.did_key or "").strip()
    )


def _sender_address(auth) -> str | None:
    return (auth.address or "").strip() or derive_team_address(auth.team_id, auth.alias) or None


async def _local_agent_by_address(db_infra, *, domain: str, name: str) -> dict | None:
    try:
        return await get_agent_by_namespace_alias(db_infra, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise ServiceError(str(exc)) from exc


def _with_requested_address(row: dict, address: str) -> dict:
    copied = dict(row)
    copied["address"] = (copied.get("address") or "").strip() or address
    return copied


def _recipient_signed_fields(rows: list[dict]) -> tuple[str, str, str]:
    to_values: list[str] = []
    to_dids: list[str] = []
    to_stable_ids: list[str] = []
    for row in rows:
        if row.get("external") and row.get("address"):
            to_values.append(row["address"])
        else:
            to_values.append(
                (
                    row.get("alias")
                    or row.get("address")
                    or row.get("did_aw")
                    or row.get("did_key")
                    or row.get("did")
                    or ""
                )
            )
        if row.get("did_key"):
            to_dids.append(row["did_key"])
        elif row.get("did") and str(row["did"]).startswith("did:key:"):
            to_dids.append(row["did"])
        if row.get("did_aw"):
            to_stable_ids.append(row["did_aw"])
        elif row.get("did") and str(row["did"]).startswith("did:aw:"):
            to_stable_ids.append(row["did"])
    return (
        _canonical_target_list(to_values),
        _canonical_target_list(to_dids),
        _canonical_target_list(to_stable_ids),
    )


def _target_did(row: dict) -> str:
    return (row.get("did_aw") or row.get("did_key") or row.get("did") or "").strip()


def _target_did_refs(row: dict) -> set[str]:
    return {
        value
        for value in (
            str(row.get("did_aw") or "").strip(),
            str(row.get("did_key") or "").strip(),
            str(row.get("did") or "").strip(),
        )
        if value
    }


async def _session_recipient_rows(db_infra, *, session_id: UUID, actor_dids: list[str]) -> list[dict]:
    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT p.did, p.alias, p.address AS participant_address, a.did_key, a.did_aw, a.address
        FROM {{tables.chat_participants}} p
        LEFT JOIN {{tables.agents}} a ON a.agent_id = p.agent_id
        WHERE p.session_id = $1
          AND p.did <> ALL($2::text[])
        ORDER BY p.alias ASC, p.did ASC
        """,
        session_id,
        actor_dids,
    )
    result: list[dict] = []
    for row in rows:
        item = dict(row)
        participant_address = (item.get("participant_address") or "").strip()
        item["address"] = (item.get("address") or "").strip() or participant_address
        item["external"] = bool(participant_address and not (item.get("did_aw") or item.get("did_key")))
        result.append(item)
    return result


async def _resolve_actor_agent(db_infra, actor_dids: list[str]) -> dict | None:
    for did in actor_dids:
        if not did:
            continue
        actor_agent = await resolve_agent_by_did(db_infra, did)
        if actor_agent is not None:
            return actor_agent
    return None


async def _resolve_session_actor_did(db_infra, *, session_id: UUID, actor_dids: list[str]) -> str:
    if not actor_dids:
        return ""
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT did
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
          AND did = ANY($2::text[])
        ORDER BY CASE WHEN did = $3 THEN 0 ELSE 1 END
        LIMIT 1
        """,
        session_id,
        actor_dids,
        actor_dids[0],
    )
    return (row.get("did") or "").strip() if row else ""


async def _wait_for_replies(
    aweb_db,
    redis,
    *,
    session_id: UUID,
    participant_did: str,
    after: datetime,
    wait_seconds: int,
) -> tuple[list[dict], bool]:
    session_id_str = str(session_id)
    start = time.monotonic()
    absolute_deadline = start + MAX_TOTAL_WAIT_SECONDS
    deadline = start + wait_seconds

    await register_waiting(redis, session_id_str, participant_did)
    last_refresh = time.monotonic()
    last_seen_at = after

    try:
        while time.monotonic() < deadline:
            now_mono = time.monotonic()
            if now_mono - last_refresh >= 30:
                await register_waiting(redis, session_id_str, participant_did)
                last_refresh = now_mono

            new_msgs = await aweb_db.fetch_all(
                """
                SELECT message_id, from_did, from_alias, body, created_at,
                       sender_leaving, hang_on
                FROM {{tables.chat_messages}}
                WHERE session_id = $1
                  AND from_did <> $2
                  AND created_at > $3
                ORDER BY created_at ASC
                LIMIT 50
                """,
                session_id,
                participant_did,
                last_seen_at,
            )

            if new_msgs:
                replies = []
                for row in new_msgs:
                    last_seen_at = max(last_seen_at, row["created_at"])
                    is_hang_on = bool(row["hang_on"])
                    if is_hang_on:
                        extended = time.monotonic() + HANG_ON_EXTENSION_SECONDS
                        deadline = min(max(deadline, extended), absolute_deadline)
                    replies.append(
                        {
                            "message_id": str(row["message_id"]),
                            "from_alias": row["from_alias"],
                            "from_did": row["from_did"],
                            "body": row["body"],
                            "hang_on": is_hang_on,
                            "sender_leaving": bool(row["sender_leaving"]),
                            "timestamp": row["created_at"].isoformat(),
                        }
                    )
                if any(not reply["hang_on"] for reply in replies):
                    return replies, False

            await asyncio.sleep(0.5)

        return [], True
    finally:
        await unregister_waiting(redis, session_id_str, participant_did)


async def chat_send(
    db_infra,
    redis,
    *,
    registry_client,
    hosted_signer: HostedMessageSigner | None = None,
    message: str,
    to_alias: str = "",
    to_did: str = "",
    to_address: str = "",
    session_id: str = "",
    wait: bool = False,
    wait_seconds: int = 120,
    leaving: bool = False,
    hang_on: bool = False,
) -> str:
    auth = get_auth()
    actor_dids = _actor_dids()
    actor_did = (auth.did_key or "").strip() if auth.trusted_proxy else (actor_dids[0] if actor_dids else "")
    actor_agent = await _resolve_actor_agent(db_infra, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)
    actor_alias = _actor_alias(actor_agent)
    sender_address = _sender_address(auth)
    aweb_db = db_infra.get_manager("aweb")

    recipient_modes = int(bool(to_alias.strip())) + int(bool(to_did.strip())) + int(bool(to_address.strip()))
    if not session_id and recipient_modes != 1:
        return json.dumps({"error": "Provide exactly one of to_alias, to_did, or to_address"})
    if session_id and recipient_modes != 0:
        return json.dumps({"error": "Provide session_id or a recipient, not both"})

    if not actor_did:
        return json.dumps({"error": "Authenticated identity is missing a routing DID"})

    if not session_id:
        if to_alias:
            if auth.team_id is None:
                return json.dumps({"error": "to_alias requires team context"})
            target = await get_agent_by_alias(db_infra, team_id=auth.team_id, alias=to_alias.strip())
            if not target:
                return json.dumps({"error": f"Agent '{to_alias}' not found in team"})
        elif to_did:
            target = await resolve_agent_by_did(db_infra, to_did.strip())
            if not target:
                return json.dumps({"error": f"Recipient '{to_did}' not found"})
        else:
            if "/" not in to_address:
                return json.dumps({"error": "to_address must be domain/name"})
            domain, name = to_address.split("/", 1)
            resolved = None
            if registry_client is not None:
                resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            if resolved is not None and resolved.did_aw:
                target = await resolve_agent_by_did(db_infra, resolved.did_aw)
                if not target:
                    target = {
                        "agent_id": None,
                        "team_id": None,
                        "alias": name,
                        "address": to_address.strip(),
                        "did_aw": resolved.did_aw.strip(),
                        "did_key": (getattr(resolved, "current_did_key", "") or "").strip(),
                        "messaging_policy": None,
                        "external": True,
                    }
            else:
                try:
                    target = await _local_agent_by_address(db_infra, domain=domain, name=name)
                except ServiceError as exc:
                    return json.dumps({"error": exc.detail})
                if not target:
                    if await namespace_exists(db_infra, domain):
                        return json.dumps({"error": f"Recipient '{to_address}' not connected"})
                    if registry_client is None:
                        return json.dumps({"error": "AWID registry unavailable"})
                    return json.dumps({"error": f"Recipient address '{to_address}' not found"})
                target = _with_requested_address(target, to_address.strip())
                if not _target_did(target):
                    return json.dumps({"error": f"Recipient '{to_address}' not connected"})

        target_did = _target_did(target)
        if not target_did:
            return json.dumps({"error": f"Recipient '{to_address or to_did or to_alias}' not connected"})
        if _target_did_refs(target) & set(actor_dids):
            return json.dumps({"error": "Cannot chat with yourself"})
        if not target.get("external"):
            try:
                await evaluate_messaging_policy(
                    db_infra,
                    registry_client=registry_client,
                    recipient_agent=target,
                    sender_did=actor_did,
                    sender_address=sender_address,
                )
            except ServiceError as exc:
                return json.dumps({"error": exc.detail})

        try:
            sid = await ensure_session(
                db_infra,
                team_id=auth.team_id,
                participant_rows=[
                    {
                        "did": actor_did,
                        "did_key": auth.did_key,
                        "agent_id": actor_agent_id,
                        "alias": actor_alias,
                        "address": sender_address,
                    },
                    {
                        "did": target_did,
                        "did_key": (target.get("did_key") or "").strip() or None,
                        "agent_id": str(target["agent_id"]) if target.get("agent_id") else None,
                        "alias": (target.get("alias") or target.get("address") or target_did).strip(),
                        "address": (target.get("address") or "").strip() or None,
                    },
                ],
                created_by=actor_alias,
            )
        except ServiceError:
            return json.dumps({"error": "Failed to create chat session"})

        msg_created_at = datetime.now(timezone.utc).replace(microsecond=0)
        pre_message_id = uuid_mod.uuid4()
        to_value, to_current_did, to_stable_id = _recipient_signed_fields([target])
        signed_fields = {
            "body": message,
            "from": _signed_from(auth, actor_alias),
            "from_did": (auth.did_key or "").strip(),
            "message_id": str(pre_message_id),
            "subject": "",
            "timestamp": _signed_timestamp(msg_created_at),
            "to": to_value,
            "to_did": to_current_did,
            "type": "chat",
        }
        if to_stable_id:
            signed_fields["to_stable_id"] = to_stable_id
        if auth.did_aw:
            signed_fields["from_stable_id"] = auth.did_aw
        if wait:
            signed_fields["wait_seconds"] = wait_seconds
        if leaving:
            signed_fields["sender_leaving"] = True
        try:
            signed = await sign_hosted_message(
                auth=auth,
                signer=hosted_signer,
                message_type="chat",
                payload=signed_fields,
            )
        except HostedMessageSigningError as exc:
            return json.dumps({"error": str(exc)})
        msg = await send_in_session(
            db_infra,
            session_id=sid,
            sender_did=signed.from_did if signed else actor_did,
            sender_agent_id=actor_agent_id,
            sender_address=sender_address,
            body=message,
            leaving=leaving,
            hang_on=hang_on,
            signature=signed.signature if signed else None,
            signed_payload=signed.signed_payload if signed else None,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
        if msg is None:
            return json.dumps({"error": "Failed to send message"})
    else:
        try:
            sid = UUID(session_id.strip())
        except Exception:
            return json.dumps({"error": "Invalid session_id format"})

        sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", sid)
        if not sess:
            return json.dumps({"error": "Session not found"})

        session_actor_did = await _resolve_session_actor_did(
            db_infra,
            session_id=sid,
            actor_dids=[actor_did] if auth.trusted_proxy else actor_dids,
        )
        if not session_actor_did:
            return json.dumps({"error": "Not a participant in this session"})

        msg_created_at = datetime.now(timezone.utc).replace(microsecond=0)
        pre_message_id = uuid_mod.uuid4()
        recipient_rows = await _session_recipient_rows(db_infra, session_id=sid, actor_dids=actor_dids)
        to_value, to_current_did, to_stable_id = _recipient_signed_fields(recipient_rows)
        signed_fields = {
            "body": message,
            "from": _signed_from(auth, actor_alias),
            "from_did": (auth.did_key or "").strip(),
            "message_id": str(pre_message_id),
            "subject": "",
            "timestamp": _signed_timestamp(msg_created_at),
            "to": to_value,
            "to_did": to_current_did,
            "type": "chat",
        }
        if to_stable_id:
            signed_fields["to_stable_id"] = to_stable_id
        if auth.did_aw:
            signed_fields["from_stable_id"] = auth.did_aw
        if hang_on:
            signed_fields["hang_on"] = True
        if wait:
            signed_fields["wait_seconds"] = wait_seconds
        if leaving:
            signed_fields["sender_leaving"] = True
        try:
            signed = await sign_hosted_message(
                auth=auth,
                signer=hosted_signer,
                message_type="chat",
                payload=signed_fields,
            )
        except HostedMessageSigningError as exc:
            return json.dumps({"error": str(exc)})

        msg = await send_in_session(
            db_infra,
            session_id=sid,
            sender_did=signed.from_did if signed else session_actor_did,
            sender_agent_id=actor_agent_id,
            sender_address=sender_address,
            body=message,
            leaving=leaving,
            hang_on=hang_on,
            signature=signed.signature if signed else None,
            signed_payload=signed.signed_payload if signed else None,
            created_at=msg_created_at,
            message_id=pre_message_id,
        )
        if msg is None:
            return json.dumps({"error": "Not a participant in this session"})

    result: dict = {
        "session_id": str(sid),
        "message_id": str(msg["message_id"]),
        "delivered": True,
    }
    if wait:
        wait_participant_did = session_actor_did if session_id else actor_did
        replies, timed_out = await _wait_for_replies(
            aweb_db,
            redis,
            session_id=sid,
            participant_did=wait_participant_did,
            after=msg["created_at"],
            wait_seconds=wait_seconds,
        )
        result["replies"] = replies
        result["timed_out"] = timed_out
    return json.dumps(result)


async def chat_pending(db_infra, redis) -> str:
    auth = get_auth()
    actor_dids = _actor_dids()
    actor_agent = await _resolve_actor_agent(db_infra, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)

    conversations_by_session: dict[str, dict] = {}
    for actor_did in actor_dids:
        rows = await get_pending_conversations(
            db_infra,
            participant_did=actor_did,
            participant_agent_id=actor_agent_id,
        )
        for row in rows:
            conversations_by_session.setdefault(row["session_id"], row)
    conversations = list(conversations_by_session.values())
    pending = [
        {
            "session_id": row["session_id"],
            "participants": row["participants"],
            "participant_addresses": row.get("participant_addresses") or [],
            "last_message": row["last_message"],
            "last_from": row["last_from"],
            "unread_count": row["unread_count"],
            "last_activity": row["last_activity"].isoformat() if row["last_activity"] else "",
        }
        for row in conversations
    ]
    return json.dumps({"pending": pending})


async def chat_history(
    db_infra,
    *,
    session_id: str,
    unread_only: bool = False,
    limit: int = 50,
) -> str:
    actor_dids = _actor_dids()
    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})

    aweb_db = db_infra.get_manager("aweb")
    sess = await aweb_db.fetch_one("SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1", session_uuid)
    if not sess:
        return json.dumps({"error": "Session not found"})

    actor_did = await _resolve_session_actor_did(
        db_infra,
        session_id=session_uuid,
        actor_dids=actor_dids,
    )
    if not actor_did:
        return json.dumps({"error": "Session not found"})

    try:
        messages = await get_message_history(
            db_infra,
            session_id=session_uuid,
            participant_did=actor_did,
            unread_only=unread_only,
            limit=min(limit, 200),
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    return json.dumps(
        {
            "session_id": str(session_uuid),
            "messages": [
                {
                    "message_id": msg["message_id"],
                    "from_alias": msg["from_alias"],
                    "from_did": msg.get("from_did"),
                    "body": msg["body"],
                    "sender_leaving": msg["sender_leaving"],
                    "timestamp": msg["created_at"].isoformat(),
                }
                for msg in messages
            ],
        }
    )


async def chat_read(db_infra, *, session_id: str, up_to_message_id: str) -> str:
    auth = get_auth()
    actor_dids = _actor_dids()
    actor_agent = await _resolve_actor_agent(db_infra, actor_dids)
    actor_agent_id = auth.agent_id or (str(actor_agent["agent_id"]) if actor_agent else None)

    try:
        session_uuid = UUID(session_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid session_id format"})
    try:
        UUID(up_to_message_id.strip())
    except Exception:
        return json.dumps({"error": "Invalid message_id format"})

    actor_did = await _resolve_session_actor_did(
        db_infra,
        session_id=session_uuid,
        actor_dids=actor_dids,
    )
    if not actor_did:
        return json.dumps({"error": "Session not found"})

    try:
        result = await mark_messages_read(
            db_infra,
            session_id=session_uuid,
            participant_did=actor_did,
            participant_agent_id=actor_agent_id,
            up_to_message_id=up_to_message_id.strip(),
        )
    except ServiceError as exc:
        return json.dumps({"error": exc.detail})

    return json.dumps(
        {
            "session_id": result["session_id"],
            "messages_marked": result["messages_marked"],
            "status": "read",
        }
    )

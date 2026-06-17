"""App-emitted event auth, subscriptions, and matching."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request

from awid.dns_auth import enforce_timestamp_skew, require_timestamp
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature

from aweb.app_registry import (
    get_active_app_emit_key,
    get_installed_app_event_type,
    normalize_app_event_type,
    normalize_delivery_intent,
    normalize_local_event_type,
    validate_team_id,
)
from aweb.config import get_settings
from aweb.service_errors import ForbiddenError, ValidationError
from aweb.team_auth_envelope import decode_signed_payload_header, raw_request_target

APP_EVENT_AUTH_PREFIX = "AWEB-App DIDKey "
APP_EVENT_AUTH_VERSION = 1
APP_EVENT_AUTH_KIND = "app-event"
APP_EVENT_LOOKBACK_SECONDS = 300

INTENT_RANK = {"ambient": 0, "wake": 1, "steer": 2}


@dataclass(frozen=True)
class AppEventAuth:
    team_id: str
    app_id: str
    kid: str
    did_key: str


@dataclass(frozen=True)
class AppEventRecord:
    event_id: str
    team_id: str
    app_id: str
    event_type: str
    resource_ref: str | None
    delivery_intent: str
    producer_delivery_intent: str
    payload: dict[str, Any]
    created_at: str


@dataclass(frozen=True)
class AppEventSubscription:
    subscription_id: str
    team_id: str
    agent_id: str
    event_type: str
    resource_ref: str | None
    delivery_intent: str
    created_at: str
    updated_at: str


def _b64decode_signature(value: str) -> bytes:
    try:
        return base64.b64decode(value)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid app event signature") from exc


def _app_event_allowed_audiences(request: Request) -> set[str]:
    configured = str(getattr(request.app.state, "public_origin", "") or "").strip()
    return {canonical_server_origin(configured or get_settings().public_origin)}


async def verify_app_event_auth(request: Request, db) -> AppEventAuth:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth.startswith(APP_EVENT_AUTH_PREFIX):
        raise HTTPException(status_code=401, detail="Missing app event Authorization header")
    rest = auth[len(APP_EVENT_AUTH_PREFIX):].strip()
    parts = rest.split()
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail="Malformed app event Authorization header")
    did_key, signature_b64 = parts

    app_id = (request.headers.get("X-AWEB-App-ID") or "").strip().lower()
    kid = (request.headers.get("X-AWEB-App-Key-ID") or "").strip()
    team_id = validate_team_id((request.headers.get("X-AWEB-Team-ID") or "").strip())
    timestamp = require_timestamp(request)
    try:
        enforce_timestamp_skew(timestamp)
    except HTTPException:
        raise

    body_sha256 = getattr(request.state, "body_sha256", None)
    if body_sha256 is None:
        import hashlib as _hashlib
        body_sha256 = _hashlib.sha256(getattr(request.state, "cached_body", b"") or b"").hexdigest()

    try:
        canonical = decode_signed_payload_header(str(request.headers.get("X-AWEB-Signed-Payload") or "").strip())
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid app event signed payload") from exc
    try:
        payload = json.loads(canonical)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid app event signed payload") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != canonical:
        raise HTTPException(status_code=401, detail="Invalid app event signed payload")

    expected = {
        "v": APP_EVENT_AUTH_VERSION,
        "auth": APP_EVENT_AUTH_KIND,
        "method": request.method.upper(),
        "path": raw_request_target(request),
        "team_id": team_id,
        "app_id": app_id,
        "kid": kid,
        "did_key": did_key,
        "body_sha256": body_sha256,
        "timestamp": timestamp,
    }
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            raise HTTPException(status_code=401, detail="App event signed payload does not match request")

    aud = str(payload.get("aud") or "").strip()
    try:
        canonical_aud = canonical_server_origin(aud)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="App event signed payload audience is invalid") from exc
    if canonical_aud not in _app_event_allowed_audiences(request):
        raise HTTPException(status_code=401, detail="App event signed payload audience is not allowed")

    try:
        verify_did_key_signature(
            did_key=did_key,
            payload=canonical,
            signature_b64=signature_b64,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid app event signature") from exc

    row = await get_active_app_emit_key(db, app_id=app_id, kid=kid, did_key=did_key)
    if row is None:
        raise HTTPException(status_code=403, detail="App emit key is not registered")

    return AppEventAuth(team_id=team_id, app_id=app_id, kid=kid, did_key=did_key)


def _to_jsonable_payload(payload: dict[str, Any] | None) -> str:
    try:
        return json.dumps(payload or {}, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("payload must be JSON serializable") from exc


def _row_timestamp(value) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value or "")


def _payload_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}
    return {}


async def emit_app_event(
    db,
    *,
    auth: AppEventAuth,
    event_type: str,
    resource_ref: str | None,
    producer_delivery_intent: str | None,
    payload: dict[str, Any] | None,
) -> AppEventRecord:
    body_app_id, local_type = normalize_app_event_type(event_type)
    if body_app_id != auth.app_id:
        raise ForbiddenError("App may only emit its own event namespace")
    installed_event = await get_installed_app_event_type(
        db,
        team_id=auth.team_id,
        app_id=auth.app_id,
        local_event_type=local_type,
    )
    if installed_event is None:
        raise ForbiddenError("App is not installed for this team or event is not declared")
    intent = normalize_delivery_intent(
        producer_delivery_intent,
        default=installed_event.get("default_delivery_intent") or "ambient",
    )
    payload_json = _to_jsonable_payload(payload)
    row = await db.fetch_one(
        """
        INSERT INTO {{tables.app_events}} (
            team_id, app_id, event_type, resource_ref, producer_delivery_intent,
            payload, producer_key_id, producer_did_key
        )
        VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6::jsonb, $7, $8)
        RETURNING event_id, team_id, app_id, event_type, resource_ref,
                  producer_delivery_intent, payload, created_at
        """,
        auth.team_id,
        auth.app_id,
        f"{auth.app_id}/{local_type}",
        (resource_ref or "").strip(),
        intent,
        payload_json,
        auth.kid,
        auth.did_key,
    )
    return AppEventRecord(
        event_id=str(row["event_id"]),
        team_id=row["team_id"],
        app_id=row["app_id"],
        event_type=row["event_type"],
        resource_ref=row.get("resource_ref"),
        delivery_intent=intent,
        producer_delivery_intent=row["producer_delivery_intent"],
        payload=_payload_dict(row.get("payload")),
        created_at=_row_timestamp(row["created_at"]),
    )


async def default_delivery_intent_for_subscription(db, *, team_id: str, event_type: str) -> str:
    app_id, local_type = normalize_app_event_type(event_type)
    row = await get_installed_app_event_type(
        db,
        team_id=team_id,
        app_id=app_id,
        local_event_type=local_type,
    )
    if row is None:
        raise ValidationError("event type is not declared by an installed app")
    return row.get("default_delivery_intent") or "ambient"


async def upsert_app_event_subscription(
    db,
    *,
    team_id: str,
    agent_id: str,
    event_type: str,
    resource_ref: str | None,
    delivery_intent: str | None,
) -> AppEventSubscription:
    team_id = validate_team_id(team_id)
    app_id, local_type = normalize_app_event_type(event_type)
    full_event_type = f"{app_id}/{local_type}"
    default_intent = await default_delivery_intent_for_subscription(db, team_id=team_id, event_type=full_event_type)
    intent = normalize_delivery_intent(delivery_intent, default=default_intent)
    row = await db.fetch_one(
        """
        INSERT INTO {{tables.app_event_subscriptions}} (
            team_id, agent_id, event_type, resource_ref, delivery_intent, updated_at
        )
        VALUES ($1, $2::UUID, $3, NULLIF($4, ''), $5, NOW())
        ON CONFLICT (team_id, agent_id, event_type, (COALESCE(resource_ref, '')))
        DO UPDATE SET delivery_intent = EXCLUDED.delivery_intent, updated_at = NOW()
        RETURNING subscription_id, team_id, agent_id, event_type, resource_ref,
                  delivery_intent, created_at, updated_at
        """,
        team_id,
        agent_id,
        full_event_type,
        (resource_ref or "").strip(),
        intent,
    )
    return _subscription_from_row(row)


async def list_app_event_subscriptions(db, *, team_id: str, agent_id: str) -> list[AppEventSubscription]:
    rows = await db.fetch_all(
        """
        SELECT subscription_id, team_id, agent_id, event_type, resource_ref,
               delivery_intent, created_at, updated_at
        FROM {{tables.app_event_subscriptions}}
        WHERE team_id = $1 AND agent_id = $2::UUID
        ORDER BY event_type ASC, resource_ref ASC NULLS FIRST
        """,
        validate_team_id(team_id),
        agent_id,
    )
    return [_subscription_from_row(row) for row in rows]


async def delete_app_event_subscription(db, *, team_id: str, agent_id: str, subscription_id: str) -> bool:
    result = await db.fetch_one(
        """
        DELETE FROM {{tables.app_event_subscriptions}}
        WHERE team_id = $1 AND agent_id = $2::UUID AND subscription_id = $3::UUID
        RETURNING subscription_id
        """,
        validate_team_id(team_id),
        agent_id,
        subscription_id,
    )
    return result is not None


def _subscription_from_row(row) -> AppEventSubscription:
    return AppEventSubscription(
        subscription_id=str(row["subscription_id"]),
        team_id=row["team_id"],
        agent_id=str(row["agent_id"]),
        event_type=row["event_type"],
        resource_ref=row.get("resource_ref"),
        delivery_intent=row["delivery_intent"],
        created_at=_row_timestamp(row["created_at"]),
        updated_at=_row_timestamp(row["updated_at"]),
    )


async def current_app_events_for_agent(
    db,
    *,
    team_id: str,
    agent_id: str,
    since: datetime | None = None,
) -> list[dict[str, Any]]:
    since = since or (datetime.now(timezone.utc) - timedelta(seconds=APP_EVENT_LOOKBACK_SECONDS))
    rows = await db.fetch_all(
        """
        WITH matches AS (
            SELECT
                e.event_id,
                e.team_id,
                e.app_id,
                e.event_type,
                e.resource_ref,
                e.producer_delivery_intent,
                e.payload,
                e.created_at,
                s.delivery_intent,
                CASE s.delivery_intent
                    WHEN 'steer' THEN 3
                    WHEN 'wake' THEN 2
                    ELSE 1
                END AS intent_rank
            FROM {{tables.app_events}} AS e
            JOIN {{tables.app_event_subscriptions}} AS s
              ON s.team_id = e.team_id
             AND s.event_type = e.event_type
             AND (s.resource_ref IS NULL OR s.resource_ref = e.resource_ref)
            WHERE e.team_id = $1
              AND s.agent_id = $2::UUID
              AND e.created_at >= $3
        ),
        ranked AS (
            SELECT *, ROW_NUMBER() OVER (
                PARTITION BY event_id
                ORDER BY intent_rank DESC, delivery_intent ASC
            ) AS rn
            FROM matches
        )
        SELECT event_id, team_id, app_id, event_type, resource_ref,
               producer_delivery_intent, payload, created_at, delivery_intent
        FROM ranked
        WHERE rn = 1
        ORDER BY created_at ASC, event_id ASC
        """,
        validate_team_id(team_id),
        agent_id,
        since,
    )
    return [
        {
            "type": "app_event",
            "event_id": str(row["event_id"]),
            "app_id": row["app_id"],
            "app_event_type": row["event_type"],
            "resource_ref": row.get("resource_ref") or "",
            "delivery_intent": row["delivery_intent"],
            "producer_delivery_intent": row["producer_delivery_intent"],
            "payload": _payload_dict(row.get("payload")),
            "created_at": _row_timestamp(row["created_at"]),
        }
        for row in rows
    ]

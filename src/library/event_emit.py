"""Best-effort app-event emit, ported from the pattern folio proved live.

library declares no events at v0, so nothing wires this yet — but the machinery
is kept (a generic emitter over the shared app-emit credential) so a future
library event is a small addition, not a rebuild. Signing reuses
``app_emit.sign_app_emit_credential`` and the shared awid canonical-JSON
primitive; library emits nothing unless an emit key is configured. Emitting is
best-effort: a failed or misconfigured emit is logged and swallowed so it can
never break the operation that triggered it.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from awid.signing import canonical_json_bytes

from library.app_emit import sign_app_emit_credential
from library.config import Settings

logger = logging.getLogger(__name__)

_EMIT_PATH = "/v1/events/app"


def app_event_body(*, event_type: str, resource_ref: str, delivery_intent: str, payload: dict[str, Any]) -> bytes:
    """Canonical app-event body (metadata only — never secrets)."""
    return canonical_json_bytes(
        {
            "type": event_type,
            "resource_ref": resource_ref,
            "delivery_intent": delivery_intent,
            "payload": payload,
        }
    )


def _utc_timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_emit_request(
    *,
    settings: Settings,
    team_id: str,
    event_type: str,
    resource_ref: str,
    delivery_intent: str,
    payload: dict[str, Any],
    timestamp: str,
) -> tuple[str, bytes, dict[str, str]] | None:
    """Build the (url, body, headers) for an app-event emit, or None if library
    has no emit key configured (in which case it emits nothing)."""
    if not (settings.app_events_origin and settings.app_emit_kid and settings.app_emit_key_seed_hex):
        return None
    body = app_event_body(
        event_type=event_type, resource_ref=resource_ref, delivery_intent=delivery_intent, payload=payload
    )
    target = f"{settings.app_events_origin.rstrip('/')}{_EMIT_PATH}"
    credential = sign_app_emit_credential(
        private_key=bytes.fromhex(settings.app_emit_key_seed_hex),
        method="POST",
        target=target,
        team_id=team_id,
        app_id=settings.app_id,
        key_id=settings.app_emit_kid,
        body=body,
        timestamp=timestamp,
    )
    headers = {**credential.headers, "Content-Type": "application/json"}
    return target, body, headers


async def emit_app_event(
    *,
    settings: Settings,
    team_id: str,
    event_type: str,
    resource_ref: str,
    delivery_intent: str,
    payload: dict[str, Any],
    timestamp: str | None = None,
) -> None:
    """Emit an app event. Never raises: a failed or misconfigured emit is logged
    and swallowed so it cannot break the operation that triggered it. The
    configured seed is never logged."""
    try:
        request = build_emit_request(
            settings=settings,
            team_id=team_id,
            event_type=event_type,
            resource_ref=resource_ref,
            delivery_intent=delivery_intent,
            payload=payload,
            timestamp=timestamp or _utc_timestamp(),
        )
        if request is None:
            return
        target, body, headers = request
        async with httpx.AsyncClient(timeout=settings.app_emit_timeout_seconds) as client:
            response = await client.post(target, content=body, headers=headers)
        if response.status_code >= 400:
            logger.warning("app event emit rejected (%s): %s", response.status_code, response.text[:200])
    except Exception as exc:  # best-effort: an operation must succeed even if emit is broken
        logger.warning("app event emit failed: %s", type(exc).__name__)

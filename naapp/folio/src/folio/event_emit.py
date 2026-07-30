"""Emit folio/doc.changed app events so an owning agent WAKES when its document
is updated, instead of polling.

Best-effort by design: a failed or unconfigured emit never breaks the document
write. The event carries metadata only (slug, version, edit source) — never the
document body or any secret. Signing reuses the shared app-emit credential
(``app_emit.sign_app_emit_credential``) and the shared awid canonical-JSON
primitive; folio emits nothing unless an emit key is configured.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import httpx
from awid.signing import canonical_json_bytes

from folio.app_emit import sign_app_emit_credential
from folio.config import Settings

logger = logging.getLogger(__name__)

DOC_CHANGED_EVENT_TYPE = "folio/doc.changed"
_EMIT_PATH = "/v1/events/app"


def doc_changed_event_body(*, slug: str, version: int, source: str) -> bytes:
    """Canonical metadata-only body for a folio/doc.changed event."""
    return canonical_json_bytes(
        {
            "type": DOC_CHANGED_EVENT_TYPE,
            "resource_ref": slug,
            "delivery_intent": "wake",
            "payload": {"version": str(version), "source": source},
        }
    )


def _utc_timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_emit_request(
    *,
    settings: Settings,
    team_id: str,
    slug: str,
    version: int,
    source: str,
    timestamp: str,
) -> tuple[str, bytes, dict[str, str]] | None:
    """Build the (url, body, headers) for a doc.changed emit, or None if folio
    has no emit key configured (in which case it emits nothing)."""
    if not (settings.app_events_origin and settings.app_emit_kid and settings.app_emit_key_seed_hex):
        return None
    body = doc_changed_event_body(slug=slug, version=version, source=source)
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


async def emit_doc_changed(
    *,
    settings: Settings,
    team_id: str,
    slug: str,
    version: int,
    source: str,
    timestamp: str | None = None,
) -> None:
    """Emit a folio/doc.changed event. Never raises: a failed or misconfigured
    emit is logged and swallowed so it cannot break the document write that
    triggered it. Request construction (which can raise on an invalid emit key or
    origin) is inside the best-effort boundary; the configured seed is never
    logged."""
    try:
        request = build_emit_request(
            settings=settings,
            team_id=team_id,
            slug=slug,
            version=version,
            source=source,
            timestamp=timestamp or _utc_timestamp(),
        )
        if request is None:
            return
        target, body, headers = request
        async with httpx.AsyncClient(timeout=settings.app_emit_timeout_seconds) as client:
            response = await client.post(target, content=body, headers=headers)
        if response.status_code >= 400:
            logger.warning(
                "folio/doc.changed emit rejected (%s): %s", response.status_code, response.text[:200]
            )
    except Exception as exc:  # best-effort: a doc update must succeed even if emit is broken
        logger.warning("folio/doc.changed emit failed: %s", type(exc).__name__)

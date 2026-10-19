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
import time
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
from awid.signing import canonical_json_bytes

from folio.app_emit import sign_app_emit_credential
from folio.config import Settings

logger = logging.getLogger(__name__)

DOC_CHANGED_EVENT_TYPE = "folio/doc.changed"
_EMIT_PATH = "/v1/events/app"
# The aweb server's refusal when the team has not installed folio's emit key.
_NOT_REGISTERED_DETAIL = "App emit key is not registered"


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


class UninstalledTeams:
    """Teams whose aweb server has refused folio's emit key as not registered.

    folio skips their emits until the entry expires, then tries once more, so a
    team that never installed folio costs one emit attempt and one log line per
    TTL instead of one rejected POST per write."""

    def __init__(self, *, ttl_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._until: dict[str, float] = {}

    @property
    def ttl_seconds(self) -> float:
        return self._ttl_seconds

    def is_skipped(self, team_id: str) -> bool:
        until = self._until.get(team_id)
        if until is None:
            return False
        if self._clock() >= until:
            del self._until[team_id]
            return False
        return True

    def mark(self, team_id: str) -> None:
        self._until[team_id] = self._clock() + self._ttl_seconds


def _is_not_registered(response: httpx.Response) -> bool:
    if response.status_code != 403:
        return False
    try:
        payload = response.json()
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("detail") == _NOT_REGISTERED_DETAIL


async def emit_doc_changed(
    *,
    settings: Settings,
    uninstalled: UninstalledTeams,
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
    logged. A team that has not installed folio's emit key is skipped for the
    uninstalled cache's TTL after its first refusal."""
    try:
        request = build_emit_request(
            settings=settings,
            team_id=team_id,
            slug=slug,
            version=version,
            source=source,
            timestamp=timestamp or _utc_timestamp(),
        )
        if request is None or uninstalled.is_skipped(team_id):
            return
        target, body, headers = request
        async with httpx.AsyncClient(timeout=settings.app_emit_timeout_seconds) as client:
            response = await client.post(target, content=body, headers=headers)
        if _is_not_registered(response):
            uninstalled.mark(team_id)
            logger.info(
                "folio/doc.changed: team %s has not installed folio's emit key; skipping its emits for %ss",
                team_id,
                int(uninstalled.ttl_seconds),
            )
        elif response.status_code >= 400:
            logger.warning(
                "folio/doc.changed emit rejected (%s): %s", response.status_code, response.text[:200]
            )
    except Exception as exc:  # best-effort: a doc update must succeed even if emit is broken
        logger.warning("folio/doc.changed emit failed: %s", type(exc).__name__)

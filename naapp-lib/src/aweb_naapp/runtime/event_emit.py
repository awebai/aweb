"""App-event emits, delivered through the shared outbox.

An app emits its events through :meth:`AppEvents.emit`, so an owning agent wakes
when something it cares about changes instead of polling. The emit is enqueued
in the caller's transaction, so the event commits with the change it reports or
not at all; the runtime's drain then delivers it to the core app-events origin,
retrying until the core accepts or finally refuses it. Each attempt is signed
afresh with the app-event key over the stored body, through
``app_emit.sign_app_emit_credential``.

An app without an app-events origin emits nothing. One with an origin must hold
the app-event key its manifest declares, or it does not start. Event bodies
carry metadata only, never secrets.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from awid.signing import canonical_json_bytes
from pgdbm.core import TransactionManager

from aweb_naapp.outbox import (
    Acked,
    OutboxEvent,
    Outcome,
    Permanent,
    Resolver,
    Retryable,
    RetryPolicy,
    StoredEvent,
    Target,
    Transport,
    enqueue,
    mint_event_id,
)
from aweb_naapp.runtime.app_emit import sign_app_emit_credential
from aweb_naapp.runtime.app_keys import APP_EVENT, AppKey, AppKeyError, load_app_key
from aweb_naapp.runtime.settings import NaappSettings

APP_EVENTS_CHANNEL = "app-events"
_TARGET = Target("app-events")
_EMIT_PATH = "/v1/events/app"


def app_event_body(
    *, event_type: str, resource_ref: str, delivery_intent: str, payload: dict[str, Any]
) -> bytes:
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
    *, origin: str, app_id: str, key: AppKey, team_id: str, body: bytes, timestamp: str
) -> tuple[str, dict[str, str]]:
    """The URL and signed headers that post ``body`` as the app's event for ``team_id``."""
    target = f"{origin.rstrip('/')}{_EMIT_PATH}"
    credential = sign_app_emit_credential(
        private_key=bytes(key.signing_key),
        method="POST",
        target=target,
        team_id=team_id,
        app_id=app_id,
        key_id=key.kid,
        body=body,
        timestamp=timestamp,
    )
    return target, {**credential.headers, "Content-Type": "application/json"}


class AppEventTransport:
    """Posts each app-event delivery to the core and classifies its answer."""

    def __init__(self, *, origin: str, app_id: str, key: AppKey, client: httpx.AsyncClient) -> None:
        self._origin = origin
        self._app_id = app_id
        self._key = key
        self._client = client

    async def deliver(self, event: StoredEvent, target: Target) -> Outcome:
        url, headers = build_emit_request(
            origin=self._origin,
            app_id=self._app_id,
            key=self._key,
            team_id=event.team_id,
            body=event.payload,
            timestamp=_utc_timestamp(),
        )
        try:
            response = await self._client.post(url, content=event.payload, headers=headers)
        except httpx.HTTPError as exc:
            return Retryable(type(exc).__name__)
        status = response.status_code
        if 200 <= status < 300:
            return Acked("delivered", receipt=response.content or None)
        if status == 429 or status >= 500:
            return Retryable(f"http_{status}")
        return Permanent(f"http_{status}")


async def _resolve(event: StoredEvent) -> Sequence[Target]:
    return [_TARGET]


class DrainOptions(TypedDict):
    channel: str
    resolver: Resolver
    transport: Transport
    policy: RetryPolicy


class AppEvents:
    """The app's app-event emits. ``key`` is None when the app emits nothing."""

    def __init__(
        self, *, app_id: str, origin: str | None, key: AppKey | None, policy: RetryPolicy
    ) -> None:
        self.app_id = app_id
        self.origin = origin
        self.key = key
        self.policy = policy

    @classmethod
    def from_settings(cls, settings: NaappSettings, manifest: Any) -> AppEvents:
        """The app's emits as configured, or an error that stops the app starting."""
        prefix = settings.model_config.get("env_prefix", "")
        policy = RetryPolicy(
            stalled_after=timedelta(seconds=settings.app_events_stalled_after_seconds)
        )
        origin = settings.app_events_origin
        if origin is None:
            if settings.app_emit_kid is not None or settings.app_emit_key_seed_hex is not None:
                raise AppKeyError(
                    f"an app-event key is configured without {prefix}APP_EVENTS_ORIGIN"
                )
            return cls(app_id=settings.app_id, origin=None, key=None, policy=policy)
        parts = urlsplit(origin)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(f"{prefix}APP_EVENTS_ORIGIN must be an http or https origin")
        key = load_app_key(settings, manifest, APP_EVENT)
        return cls(app_id=settings.app_id, origin=origin, key=key, policy=policy)

    async def emit(
        self,
        tx: TransactionManager,
        *,
        team_id: str,
        event_type: str,
        resource_ref: str,
        delivery_intent: str,
        payload: dict[str, Any],
    ) -> UUID | None:
        """Enqueue the event in ``tx`` and return its id, or None when the app
        emits nothing."""
        if self.key is None:
            return None
        event_id = mint_event_id()
        await enqueue(
            tx,
            OutboxEvent(
                event_id=event_id,
                team_id=team_id,
                kind=event_type,
                occurred_at=datetime.now(UTC),
                payload=app_event_body(
                    event_type=event_type,
                    resource_ref=resource_ref,
                    delivery_intent=delivery_intent,
                    payload=payload,
                ),
                channel=APP_EVENTS_CHANNEL,
            ),
        )
        return event_id

    def drain_options(self, client: httpx.AsyncClient) -> DrainOptions:
        """The outbox drain arguments that deliver these events through ``client``."""
        if self.key is None or self.origin is None:
            raise RuntimeError("this app emits no app events")
        return DrainOptions(
            channel=APP_EVENTS_CHANNEL,
            resolver=_resolve,
            transport=AppEventTransport(
                origin=self.origin, app_id=self.app_id, key=self.key, client=client
            ),
            policy=self.policy,
        )

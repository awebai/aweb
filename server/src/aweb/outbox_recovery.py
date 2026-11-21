"""Recovery of outbox rows that their writers' after-commit replay left behind.

Writers deliver their own outbox rows right after commit: lifecycle side
effects in lifecycle.py, federation mutations in routes/federation.py. Rows
remain only when a delivery failed or the process stopped between commit and
delivery. This loop retries them on a fixed cycle, so no request pays for it.

The aweb lifespans start the loop. A mounted app receives no lifespan, so its
first request starts it instead (OutboxRecoveryStarter): later requests only
see it running. A host that runs recover_outboxes from its own scheduler
creates the app with host_runs_outbox_recovery=True and no request starts it.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
from typing import Any

from .application_state import RegistryClientUnavailable, application_registry_client
from .hooks import MutationCallback

from .federation.delivery import deliver_federation_mutation_outbox
from .lifecycle import replay_lifecycle_side_effects

logger = logging.getLogger(__name__)

OUTBOX_RECOVERY_INTERVAL_SECONDS = 15
_LIFECYCLE_BATCH_SIZE = 100
_LIFECYCLE_MAX_BATCHES = 10
_FEDERATION_BATCH_SIZE = 100


async def recover_outboxes(
    *,
    aweb_db: Any,
    redis: Any,
    on_mutation: MutationCallback | None,
) -> None:
    """Deliver undelivered lifecycle and federation outbox rows, in bounded batches."""
    for _ in range(_LIFECYCLE_MAX_BATCHES):
        result = await replay_lifecycle_side_effects(
            aweb_db, redis, limit=_LIFECYCLE_BATCH_SIZE
        )
        if result.attempted_count < _LIFECYCLE_BATCH_SIZE:
            break
    if on_mutation is not None:
        await deliver_federation_mutation_outbox(
            aweb_db, on_mutation, limit=_FEDERATION_BATCH_SIZE
        )


async def _run_outbox_recovery(app: Any, interval_seconds: float) -> None:
    # Maintenance calls recover_outboxes; defer this import to avoid the cycle.
    from .maintenance import run_native_maintenance

    while True:
        try:
            registry = application_registry_client(app.state)
        except RegistryClientUnavailable:
            registry = None
        try:
            await run_native_maintenance(
                db_infra=app.state.db,
                redis=app.state.redis,
                registry_client=registry,
                on_mutation=getattr(app.state, "on_mutation", None),
            )
        except Exception:
            logger.warning("Native maintenance failed", exc_info=True)
        await asyncio.sleep(interval_seconds)


def start_outbox_recovery(app: Any, *, interval_seconds: float | None = None) -> None:
    # A fresh context: the loop outlives whatever request or startup started it.
    """Start periodic native maintenance under the released recovery task name."""
    app.state.outbox_recovery_task = asyncio.create_task(
        _run_outbox_recovery(
            app,
            OUTBOX_RECOVERY_INTERVAL_SECONDS
            if interval_seconds is None
            else interval_seconds,
        ),
        context=contextvars.Context(),
    )


def ensure_outbox_recovery(app: Any) -> None:
    """Start the loop unless it runs, once the app has its database and Redis."""
    resources = getattr(app.state, "native_resources", None)
    if resources is not None and not resources.readiness.ready:
        return
    task = getattr(app.state, "outbox_recovery_task", None)
    if task is not None and not task.done():
        return
    if (
        getattr(app.state, "db", None) is None
        or getattr(app.state, "redis", None) is None
    ):
        return
    start_outbox_recovery(app)


class OutboxRecoveryStarter:
    """Start outbox recovery on a request to an app whose lifespan did not."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope.get("app") is not None:
            ensure_outbox_recovery(scope["app"])
        await self.app(scope, receive, send)


async def stop_outbox_recovery(app: Any) -> None:
    """Stop the periodic recovery task owned by this application."""
    task = getattr(app.state, "outbox_recovery_task", None)
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

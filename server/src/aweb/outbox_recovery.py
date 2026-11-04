"""Recovery of outbox rows that their writers' after-commit replay left behind.

Writers deliver their own outbox rows right after commit: lifecycle side
effects in lifecycle.py, federation mutations in routes/federation.py. Rows
remain only when a delivery failed or the process stopped between commit and
delivery. This loop retries them on a fixed cycle, so no request pays for it.
A host that does not run the aweb lifespan (an embedding application) runs
recover_outboxes from its own scheduler instead.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Optional

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
    on_mutation: Optional[Callable[[str, dict], Awaitable[None]]],
) -> None:
    """Deliver undelivered lifecycle and federation outbox rows, in bounded batches."""
    for _ in range(_LIFECYCLE_MAX_BATCHES):
        result = await replay_lifecycle_side_effects(aweb_db, redis, limit=_LIFECYCLE_BATCH_SIZE)
        if result.attempted_count < _LIFECYCLE_BATCH_SIZE:
            break
    if on_mutation is not None:
        await deliver_federation_mutation_outbox(aweb_db, on_mutation, limit=_FEDERATION_BATCH_SIZE)


async def _run_outbox_recovery(app: Any, interval_seconds: float) -> None:
    while True:
        try:
            await recover_outboxes(
                aweb_db=app.state.db.get_manager("aweb"),
                redis=app.state.redis,
                on_mutation=getattr(app.state, "on_mutation", None),
            )
        except Exception:
            logger.warning("Outbox recovery failed", exc_info=True)
        await asyncio.sleep(interval_seconds)


def start_outbox_recovery(app: Any, *, interval_seconds: float = OUTBOX_RECOVERY_INTERVAL_SECONDS) -> None:
    app.state.outbox_recovery_task = asyncio.create_task(_run_outbox_recovery(app, interval_seconds))


async def stop_outbox_recovery(app: Any) -> None:
    task = getattr(app.state, "outbox_recovery_task", None)
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

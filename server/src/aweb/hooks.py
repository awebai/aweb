"""Fire-and-forget mutation callbacks for embedding applications."""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

from fastapi import Request

logger = logging.getLogger(__name__)

MutationCallback = Callable[[str, dict], Awaitable[None]]


async def fire_mutation_hook(request: Request, event_type: str, context: dict) -> None:
    """Call app.state.on_mutation if registered. Never raises."""
    await fire_mutation_callback(getattr(request.app.state, "on_mutation", None), event_type, context)


async def fire_mutation_callback(callback: MutationCallback | None, event_type: str, context: dict) -> None:
    """Call an embedding application's on_mutation callback if there is one. Never raises."""
    if callback is None:
        return
    try:
        await callback(event_type, context)
    except Exception:
        logger.warning("on_mutation callback failed for %s", event_type, exc_info=True)

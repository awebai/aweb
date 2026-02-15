"""Fire-and-forget mutation callbacks for embedding applications."""

from __future__ import annotations

import logging

from fastapi import Request

logger = logging.getLogger(__name__)


async def fire_mutation_hook(request: Request, event_type: str, context: dict) -> None:
    """Call app.state.on_mutation if registered. Never raises."""
    callback = getattr(request.app.state, "on_mutation", None)
    if callback is None:
        return
    try:
        await callback(event_type, context)
    except Exception:
        logger.warning("on_mutation callback failed for %s", event_type, exc_info=True)

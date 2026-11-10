"""Fire-and-forget mutation callbacks for embedding applications."""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

from fastapi import Request

logger = logging.getLogger(__name__)

MutationCallback = Callable[[str, dict], Awaitable[None]]


def mutation_callback(request: Request) -> MutationCallback | None:
    """Return the on_mutation callback of the application serving this request."""
    return getattr(request.app.state, "on_mutation", None)


async def fire_mutation_hook(request: Request, event_type: str, context: dict) -> None:
    """Call app.state.on_mutation if registered. Never raises."""
    await fire_mutation_callback(mutation_callback(request), event_type, context)


async def fire_mutation_callback(callback: MutationCallback | None, event_type: str, context: dict) -> None:
    """Call an embedding application's on_mutation callback if there is one. Never raises."""
    if callback is None:
        return
    try:
        await callback(event_type, context)
    except Exception:
        logger.warning("on_mutation callback failed for %s", event_type, exc_info=True)


class HeldMutationEvents:
    """Mutation events a service records inside the caller's transaction, fired once it commits.

    The task services fire their events through the on_mutation callback they are
    given. A caller that runs one inside its own transaction passes ``record`` as
    that callback and calls ``fire`` after its transaction commits; when the
    transaction rolls back, ``fire`` is never reached and nothing is delivered.
    """

    def __init__(self) -> None:
        self._events: list[tuple[str, dict]] = []

    async def record(self, event_type: str, context: dict) -> None:
        self._events.append((event_type, context))

    async def fire(self, on_mutation: MutationCallback | None) -> None:
        """Deliver the recorded events in order; a failing callback is logged, never raised."""
        for event_type, context in self._events:
            await fire_mutation_callback(on_mutation, event_type, context)

"""Best-effort mutation callbacks with explicit delivery outcomes."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Awaitable, Protocol

from fastapi import Request

from aweb.application_state import native_application_state

logger = logging.getLogger(__name__)


class MutationDeliveryStatus(StrEnum):
    """Whether the serving callback ran and completed its native work."""

    DELIVERED = "delivered"
    DEFERRED = "deferred"
    NOT_CONFIGURED = "not_configured"
    FAILED = "failed"


class MutationDeliveryStage(StrEnum):
    """Failure boundaries a caller can distinguish without parsing a log."""

    CALLBACK = "callback"
    CONTEXT_ENRICHMENT = "context_enrichment"
    AGENT_CASCADE = "agent_cascade"
    TASK_STATUS_CASCADE = "task_status_cascade"
    PUBLICATION = "publication"


@dataclass(frozen=True, kw_only=True)
class MutationDeliveryOutcome:
    """Post-commit callback result; it never changes whether the mutation committed."""

    status: MutationDeliveryStatus
    failed_stages: tuple[MutationDeliveryStage, ...] = ()

    def require_delivery(self) -> None:
        """Keep a durable outbox pending unless its callback completed."""
        if self.status is not MutationDeliveryStatus.DELIVERED:
            raise MutationDeliveryFailed(self)


class MutationDeliveryFailed(RuntimeError):
    """Typed callback failure for explicit durable-delivery consumers."""

    def __init__(self, outcome: MutationDeliveryOutcome) -> None:
        self.outcome = outcome
        super().__init__(
            "Mutation delivery is incomplete. Retry the pending delivery or cleanup operation."
        )


class MutationCallback(Protocol):
    """An embedding callback accepting positional event/context and an awaitable result."""

    def __call__(
        self,
        event_type: str,
        context: dict,
        /,
    ) -> Awaitable[MutationDeliveryOutcome | None]:
        """Complete native work or retain the compatible None-returning host result."""
        ...


def mutation_callback(request: Request) -> MutationCallback | None:
    """Return the on_mutation callback of the application serving this request."""
    return getattr(native_application_state(request.app.state), "on_mutation", None)


async def fire_mutation_hook(
    request: Request, event_type: str, context: dict
) -> MutationDeliveryOutcome:
    """Call app.state.on_mutation if registered. Never raises."""
    return await fire_mutation_callback(mutation_callback(request), event_type, context)


async def fire_mutation_callback(
    callback: MutationCallback | None, event_type: str, context: dict
) -> MutationDeliveryOutcome:
    """Call an embedding application's on_mutation callback if there is one. Never raises."""
    if callback is None:
        return MutationDeliveryOutcome(status=MutationDeliveryStatus.NOT_CONFIGURED)
    try:
        result = await callback(event_type, context)
        if isinstance(result, MutationDeliveryOutcome):
            return result
        return MutationDeliveryOutcome(status=MutationDeliveryStatus.DELIVERED)
    except Exception:
        logger.warning("on_mutation callback failed for %s", event_type, exc_info=True)
        return MutationDeliveryOutcome(
            status=MutationDeliveryStatus.FAILED,
            failed_stages=(MutationDeliveryStage.CALLBACK,),
        )


class HeldMutationEvents:
    """Mutation events a service records inside the caller's transaction, fired once it commits.

    The task services fire their events through the on_mutation callback they are
    given. A caller that runs one inside its own transaction passes ``record`` as
    that callback and calls ``fire`` after its transaction commits; when the
    transaction rolls back, ``fire`` is never reached and nothing is delivered.
    """

    def __init__(self) -> None:
        self._events: list[tuple[str, dict]] = []

    async def record(self, event_type: str, context: dict) -> MutationDeliveryOutcome:
        """Hold a mutation for outer commit, without claiming its callback executed."""
        self._events.append((event_type, context))
        return MutationDeliveryOutcome(status=MutationDeliveryStatus.DEFERRED)

    async def fire(self, on_mutation: MutationCallback | None) -> None:
        """Deliver the recorded events in order; a failing callback is logged, never raised."""
        for event_type, context in self._events:
            await fire_mutation_callback(on_mutation, event_type, context)

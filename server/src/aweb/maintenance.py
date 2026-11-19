"""One periodic operation for native and host-owned serving maintenance.

Presence requires the complete registry-aware R2 grant component. Unknown
membership evidence remains a failure, never an offline observation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import logging
from typing import TYPE_CHECKING

from awid.registry import RegistryClient
from redis.asyncio import Redis

from aweb.application_state import RegistryClientUnavailable
from aweb.hooks import MutationCallback
from aweb.outbox_recovery import recover_outboxes
from aweb.presence_transitions import PresenceReconciliationResult, reconcile_presence

if TYPE_CHECKING:
    from aweb.embedding import DatabaseInfrastructure


logger = logging.getLogger(__name__)


class NativeMaintenanceStage(StrEnum):
    OUTBOX_RECOVERY = "outbox_recovery"
    PRESENCE_RECONCILIATION = "presence_reconciliation"


@dataclass(frozen=True, kw_only=True)
class NativeMaintenanceFailure:
    stage: NativeMaintenanceStage
    error: Exception


@dataclass(frozen=True, kw_only=True)
class NativeMaintenanceResult:
    presence: PresenceReconciliationResult


class NativeMaintenanceError(RuntimeError):
    """All stages were attempted; named failures remain visible and retryable."""

    def __init__(
        self,
        *,
        failures: tuple[NativeMaintenanceFailure, ...],
        completed_stages: frozenset[NativeMaintenanceStage],
    ):
        self.failures = failures
        self.completed_stages = completed_stages
        stages = ", ".join(failure.stage.value for failure in failures)
        super().__init__(
            f"Native maintenance failed at {stages}. Restore the named stage's database, "
            "registry or publisher dependency and retry maintenance; inspect failures for the cause."
        )


async def run_native_maintenance(
    *,
    db_infra: DatabaseInfrastructure,
    redis: Redis,
    registry_client: RegistryClient | None,
    on_mutation: MutationCallback | None,
) -> NativeMaintenanceResult:
    """Attempt outbox recovery and unattended presence before reporting failure.

    Pass the exact application_registry_client selected by the serving owner.
    A missing configuration is accepted only to report a named presence failure
    while preserving mounted servers' existing automatic outbox progress. It
    never selects a shadow client, skips authority checks or publishes offline.
    Hosts invoke this at their existing outbox_recovery interval; NATIVE-owned
    resources use the same function. No connections are constructed or closed.
    """
    failures = []
    completed = set()
    try:
        await recover_outboxes(
            aweb_db=db_infra.get_manager("aweb"),
            redis=redis,
            on_mutation=on_mutation,
        )
        completed.add(NativeMaintenanceStage.OUTBOX_RECOVERY)
    except Exception as exc:
        logger.exception("Native maintenance outbox recovery failed")
        failures.append(
            NativeMaintenanceFailure(
                stage=NativeMaintenanceStage.OUTBOX_RECOVERY, error=exc
            )
        )
    try:
        if registry_client is None:
            raise RegistryClientUnavailable()
        presence = await reconcile_presence(
            db_infra, redis, registry_client=registry_client
        )
        completed.add(NativeMaintenanceStage.PRESENCE_RECONCILIATION)
    except Exception as exc:
        logger.exception("Native maintenance presence reconciliation failed")
        failures.append(
            NativeMaintenanceFailure(
                stage=NativeMaintenanceStage.PRESENCE_RECONCILIATION, error=exc
            )
        )
    if failures:
        raise NativeMaintenanceError(
            failures=tuple(failures), completed_stages=frozenset(completed)
        )
    return NativeMaintenanceResult(presence=presence)

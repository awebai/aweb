"""Reservation release eligibility and notifications shared by HTTP callers."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from .events import ReservationReleasedEvent
from .hooks import MutationCallback, fire_mutation_callback


class ReservationReleaseOutcome(StrEnum):
    RELEASED = "released"


@dataclass(frozen=True, kw_only=True)
class HolderRelease:
    resource_key: str
    holder_agent_id: UUID


@dataclass(frozen=True, kw_only=True)
class EmergencyRelease:
    prefix: str


@dataclass(frozen=True, kw_only=True)
class ReleasedReservation:
    resource_key: str
    holder_agent_id: UUID
    holder_alias: str
    expires_at: datetime


@dataclass(frozen=True, kw_only=True)
class ReservationReleaseConflict:
    reservation: ReleasedReservation


async def release_reservations_on(
    tx,
    *,
    team_id: str,
    selection: HolderRelease | EmergencyRelease,
    now: datetime,
) -> tuple[ReleasedReservation, ...] | ReservationReleaseConflict:
    """Release a holder's lock or an explicit team-member emergency selection.

    Implements docs/aweb-sot.md:1219–1225. Ordinary
    release protects another active holder; emergency revoke retains the
    team's existing any-member authority. Lock and delete use one transaction.
    """
    if isinstance(selection, HolderRelease):
        rows = await tx.fetch_all(
            """SELECT resource_key, holder_agent_id, holder_alias, expires_at
               FROM {{tables.reservations}}
               WHERE team_id=$1 AND resource_key=$2 FOR UPDATE""",
            team_id,
            selection.resource_key,
        )
    else:
        rows = await tx.fetch_all(
            """SELECT resource_key, holder_agent_id, holder_alias, expires_at
               FROM {{tables.reservations}}
               WHERE team_id=$1 AND expires_at > $2 AND starts_with(resource_key, $3)
               ORDER BY resource_key FOR UPDATE""",
            team_id,
            now,
            selection.prefix,
        )
    reservations = tuple(
        ReleasedReservation(
            resource_key=row["resource_key"],
            holder_agent_id=row["holder_agent_id"],
            holder_alias=row["holder_alias"],
            expires_at=row["expires_at"],
        )
        for row in rows
    )
    if isinstance(selection, HolderRelease):
        for reservation in reservations:
            if (
                reservation.expires_at > now
                and reservation.holder_agent_id != selection.holder_agent_id
            ):
                return ReservationReleaseConflict(reservation=reservation)
    if reservations:
        await tx.execute(
            "DELETE FROM {{tables.reservations}} WHERE team_id=$1 AND resource_key=ANY($2::text[])",
            team_id,
            [reservation.resource_key for reservation in reservations],
        )
    return reservations


async def publish_reservation_releases(
    *,
    callback: MutationCallback | None,
    team_id: str,
    actor_agent_id: str,
    reservations: tuple[ReleasedReservation, ...],
) -> None:
    """Notify holders through the release contract (docs/aweb-sot.md:1221–1224)."""
    for reservation in reservations:
        await fire_mutation_callback(
            callback,
            ReservationReleasedEvent.type,
            {
                "team_id": team_id,
                "actor_agent_id": actor_agent_id,
                "holder_agent_id": str(reservation.holder_agent_id),
                "alias": reservation.holder_alias,
                "resource_key": reservation.resource_key,
            },
        )

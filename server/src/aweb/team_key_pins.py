"""The team key this server admitted is the team's key until a signed act moves it.

``teams.team_did_key`` is written when the server admits a team. A registry
answer is used only when it names that key; a different key is accepted only
with the namespace controller's act, checked by ``awid.team_key_acts`` against
the controller DNS names, and the pin and the act's signing time
(``teams.team_key_act_at``) then move in one compare-and-swap. A team this
server has not admitted has no row; admission writes it.

Enforcement is staged (``aweb.config.enforce_team_key_pins``): until
``AWEB_ENFORCE_TEAM_KEY_PINS`` is on, a mismatch is logged as
``team_key_pin_mismatch ... enforced=false`` and the registry's key is served.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from awid.external_authority import SystemTXTOutcomeResolver
from awid.team_ids import parse_team_id
from awid.team_key_acts import (
    TEAM_KEY_UNVERIFIED_DETAIL,
    TeamKeyMemo,
    TeamKeyPin,
    TeamKeyUnverified,
)
from awid.team_key_acts import (
    pinned_team_key as pin_team_key,
)
from fastapi import HTTPException

from aweb.config import enforce_team_key_pins

TEAM_KEY_UNVERIFIED = "team_key_unverified"
_SYSTEM_TXT_RESOLVER = SystemTXTOutcomeResolver()

__all__ = [
    "TEAM_KEY_UNVERIFIED",
    "AdmittedTeamKeys",
    "TeamKeyUnverified",
    "pinned_team_key",
    "team_key_unverified_exception",
    "txt_resolver_for",
]


class AdmittedTeamKeys:
    """The pins are the ``teams`` rows: written at admission, moved only by an act."""

    def __init__(self, db: Any) -> None:
        self._db = db

    async def pin(self, team_id: str) -> TeamKeyPin | None:
        row = await self._db.fetch_one(
            "SELECT team_did_key, team_key_act_at, created_at FROM {{tables.teams}} WHERE team_id = $1",
            team_id,
        )
        return (
            None
            if row is None
            else TeamKeyPin(
                row["team_did_key"],
                row["team_key_act_at"],
                admitted_at=row["created_at"],
            )
        )

    async def first_sight(self, team_id: str, team_did_key: str) -> TeamKeyPin:
        # Admission (connect, service registration) writes the row.
        return TeamKeyPin(team_did_key, None, admitted_at=datetime.now(timezone.utc))

    async def move(self, team_id: str, *, expected: TeamKeyPin, new: TeamKeyPin) -> bool:
        moved = await self._db.fetch_value(
            """
            UPDATE {{tables.teams}}
            SET team_did_key = $2, team_key_act_at = $3
            WHERE team_id = $1 AND team_did_key = $4
              AND team_key_act_at IS NOT DISTINCT FROM $5
              AND ($6::timestamptz IS NULL OR created_at = $6)
            RETURNING team_id
            """,
            team_id,
            new.team_did_key,
            new.act_at,
            expected.team_did_key,
            expected.act_at,
            expected.admitted_at,
        )
        return moved is not None


def txt_resolver_for(state: Any) -> Any:
    """The app's DNS resolver for ``_awid`` records; system DNS when the app
    state has none (an embedding host that mounts aweb's auth in its own app)."""
    resolver = getattr(state, "awid_txt_resolver", None)
    return resolver if resolver is not None else _SYSTEM_TXT_RESOLVER


def team_key_unverified_exception() -> HTTPException:
    return HTTPException(status_code=401, detail=TEAM_KEY_UNVERIFIED_DETAIL)


async def pinned_team_key(
    *,
    db: Any,
    registry_client: Any,
    txt_resolver: Any,
    team_id: str,
    served_key: str,
    pin_memo: TeamKeyMemo | None = None,
) -> str:
    """``served_key`` when it is the admitted key or an act moves the pin to it;
    otherwise ``team_key_pin_mismatch`` is logged and, while
    ``AWEB_ENFORCE_TEAM_KEY_PINS`` is on, TeamKeyUnverified is raised."""
    if pin_memo is not None:
        remembered = pin_memo.get(team_id, served_key)
        if remembered is not None:
            return remembered
    domain, name = parse_team_id(team_id)
    key = await pin_team_key(
        team_id,
        served_key,
        pins=AdmittedTeamKeys(db),
        fetch_act=lambda: registry_client.get_team_key_act(domain, name),
        resolver=txt_resolver,
        enforce=enforce_team_key_pins(),
    )
    if pin_memo is not None:
        pin_memo.put(team_id, served_key, key)
    return key

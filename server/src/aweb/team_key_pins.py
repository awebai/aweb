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

import logging
from typing import Any

from fastapi import HTTPException, Request

from awid.team_ids import parse_team_id
from awid.team_key_acts import TeamKeyPin, TeamKeyUnverified, pinned_team_key as pin_team_key

from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS, awid_dependency_http_exception
from aweb.config import enforce_team_key_pins

logger = logging.getLogger(__name__)

TEAM_KEY_UNVERIFIED = "team_key_unverified"

__all__ = [
    "TEAM_KEY_UNVERIFIED",
    "AdmittedTeamKeys",
    "TeamKeyUnverified",
    "pinned_team_key",
    "pinned_team_key_for_request",
    "team_key_unverified_exception",
]


class AdmittedTeamKeys:
    """The pins are the ``teams`` rows: written at admission, moved only by an act."""

    def __init__(self, db: Any) -> None:
        self._db = db

    async def pin(self, team_id: str) -> TeamKeyPin | None:
        row = await self._db.fetch_one(
            "SELECT team_did_key, team_key_act_at FROM {{tables.teams}} WHERE team_id = $1", team_id,
        )
        return None if row is None else TeamKeyPin(row["team_did_key"], row["team_key_act_at"])

    async def first_sight(self, team_id: str, team_did_key: str) -> TeamKeyPin:
        # Admission (connect, service registration) writes the row.
        return TeamKeyPin(team_did_key, None)

    async def move(self, team_id: str, *, expected: TeamKeyPin, new: TeamKeyPin) -> bool:
        moved = await self._db.fetch_value(
            """
            UPDATE {{tables.teams}}
            SET team_did_key = $2, team_key_act_at = $3
            WHERE team_id = $1 AND team_did_key = $4
              AND team_key_act_at IS NOT DISTINCT FROM $5
            RETURNING team_id
            """,
            team_id, new.team_did_key, new.act_at, expected.team_did_key, expected.act_at,
        )
        return moved is not None


def team_key_unverified_exception() -> HTTPException:
    return HTTPException(status_code=401, detail=TEAM_KEY_UNVERIFIED)


async def pinned_team_key(
    *, db: Any, registry_client: Any, txt_resolver: Any, team_id: str, served_key: str,
) -> str:
    """``served_key`` when it is the admitted key or an act moves the pin to it;
    otherwise ``team_key_pin_mismatch`` is logged and, while
    ``AWEB_ENFORCE_TEAM_KEY_PINS`` is on, TeamKeyUnverified is raised."""
    domain, name = parse_team_id(team_id)
    return await pin_team_key(
        team_id,
        served_key,
        pins=AdmittedTeamKeys(db),
        fetch_act=lambda: registry_client.get_team_key_act(domain, name),
        resolver=txt_resolver,
        enforce=enforce_team_key_pins(),
    )


async def pinned_team_key_for_request(request: Request, team_id: str, served_key: str) -> str:
    """``pinned_team_key`` with the app's database, registry and DNS resolver;
    an unverified key is the 401 ``team_key_unverified`` and a failed act read
    is the registry dependency error."""
    state = request.app.state
    try:
        return await pinned_team_key(
            db=state.db.get_manager("aweb"),
            registry_client=state.awid_registry_client,
            txt_resolver=state.awid_txt_resolver,
            team_id=team_id,
            served_key=served_key,
        )
    except TeamKeyUnverified:
        raise team_key_unverified_exception() from None
    except AWID_DEPENDENCY_ERRORS as exc:
        logger.warning("AWID registry dependency failed for the team key act of %s", team_id, exc_info=True)
        raise awid_dependency_http_exception(exc, operation="AWID team key act read") from exc

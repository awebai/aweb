"""Team-key pins kept in the app's database, so they outlive the process."""

from __future__ import annotations

from collections.abc import Callable

from awid.team_key_acts import TeamKeyPin
from pgdbm import AsyncDatabaseManager


class DatabaseTeamKeyPins:
    """``awid.team_key_acts.TeamKeyPinStore`` over the shared ``team_key_pins``
    table. ``db`` returns the app's database when a pin is first read, so the
    store can be built before the database connects."""

    def __init__(self, db: Callable[[], AsyncDatabaseManager]) -> None:
        self._db = db

    async def pin(self, team_id: str) -> TeamKeyPin | None:
        row = await self._db().fetch_one(
            "SELECT team_did_key, team_key_act_at FROM {{tables.team_key_pins}} WHERE team_id = $1",
            team_id,
        )
        return None if row is None else TeamKeyPin(row["team_did_key"], row["team_key_act_at"])

    async def first_sight(self, team_id: str, team_did_key: str) -> TeamKeyPin:
        db = self._db()
        await db.execute(
            "INSERT INTO {{tables.team_key_pins}} (team_id, team_did_key) VALUES ($1, $2) "
            "ON CONFLICT (team_id) DO NOTHING",
            team_id,
            team_did_key,
        )
        pin = await self.pin(team_id)
        if pin is None:
            raise RuntimeError(f"team key pin for {team_id} vanished after it was written")
        return pin

    async def move(self, team_id: str, *, expected: TeamKeyPin, new: TeamKeyPin) -> bool:
        moved = await self._db().fetch_value(
            """
            UPDATE {{tables.team_key_pins}}
            SET team_did_key = $2, team_key_act_at = $3, pinned_at = NOW()
            WHERE team_id = $1 AND team_did_key = $4
              AND team_key_act_at IS NOT DISTINCT FROM $5
            RETURNING team_id
            """,
            team_id,
            new.team_did_key,
            new.act_at,
            expected.team_did_key,
            expected.act_at,
        )
        return moved is not None

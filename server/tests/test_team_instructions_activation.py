"""Activating a team instructions version against real PostgreSQL."""

from __future__ import annotations

import asyncio

import pytest

from aweb.coordination.routes.team_instructions import (
    activate_team_instructions,
    create_team_instructions_version,
)

TEAM_ID = "backend:acme.com"


async def _create_versions(db, count: int) -> list[str]:
    ids = []
    for number in range(count):
        version = await create_team_instructions_version(
            db,
            team_id=TEAM_ID,
            base_instructions_id=None,
            document={"body_md": f"version {number + 1}", "format": "markdown"},
            created_by_alias=None,
        )
        ids.append(version.id)
    return ids


async def _active_ids(db) -> list[str]:
    rows = await db.fetch_all(
        """
        SELECT id FROM {{tables.team_instructions}}
        WHERE team_id = $1 AND is_active = true
        """,
        TEAM_ID,
    )
    return [str(row["id"]) for row in rows]


async def _wait_for_lock_waiters(db, count: int) -> None:
    for _ in range(200):
        waiting = await db.fetch_value(
            """
            SELECT COUNT(*) FROM pg_stat_activity
            WHERE datname = current_database() AND wait_event_type = 'Lock'
            """
        )
        if waiting >= count:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"expected {count} sessions waiting on a lock")


@pytest.mark.asyncio
async def test_concurrent_activations_leave_exactly_one_active(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    first, second, third = await _create_versions(db, 3)
    await activate_team_instructions(db, team_id=TEAM_ID, instructions_id=first)

    # Holding the active row makes both activations wait at the same point, so
    # they are in flight together when the row is released.
    async with db.transaction() as holder:
        await holder.execute(
            "SELECT id FROM {{tables.team_instructions}} WHERE id = $1 FOR UPDATE",
            first,
        )
        activations = [
            asyncio.create_task(
                activate_team_instructions(db, team_id=TEAM_ID, instructions_id=target)
            )
            for target in (second, third)
        ]
        await _wait_for_lock_waiters(db, 2)

    await asyncio.gather(*activations)

    active = await _active_ids(db)
    assert len(active) == 1, active
    assert active[0] in (second, third)


@pytest.mark.asyncio
async def test_failed_activation_leaves_previous_version_active(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    first, second = await _create_versions(db, 2)
    await activate_team_instructions(db, team_id=TEAM_ID, instructions_id=first)

    await db.execute(
        """
        CREATE FUNCTION aweb.refuse_instructions_activation() RETURNS trigger AS $$
        BEGIN
            IF NEW.is_active AND NOT OLD.is_active THEN
                RAISE EXCEPTION 'activation refused by test trigger';
            END IF;
            RETURN NEW;
        END
        $$ LANGUAGE plpgsql
        """
    )
    await db.execute(
        """
        CREATE TRIGGER refuse_instructions_activation
        BEFORE UPDATE ON {{tables.team_instructions}}
        FOR EACH ROW EXECUTE FUNCTION aweb.refuse_instructions_activation()
        """
    )

    with pytest.raises(Exception, match="activation refused by test trigger"):
        await activate_team_instructions(db, team_id=TEAM_ID, instructions_id=second)

    assert await _active_ids(db) == [first]

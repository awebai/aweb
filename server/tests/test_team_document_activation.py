"""Activating a version of a team's instructions or roles against real PostgreSQL."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import pytest

from aweb.coordination.routes.team_instructions import (
    activate_team_instructions,
    create_team_instructions_version,
)
from aweb.coordination.routes.team_roles import activate_team_roles, create_team_roles_version

TEAM_ID = "backend:acme.com"


@dataclass(frozen=True)
class TeamDocument:
    name: str
    table: str
    create: Callable[[Any, int], Awaitable[str]]
    activate: Callable[[Any, str], Awaitable[Any]]


async def _create_instructions(db, number: int) -> str:
    version = await create_team_instructions_version(
        db,
        team_id=TEAM_ID,
        base_instructions_id=None,
        document={"body_md": f"version {number}", "format": "markdown"},
        created_by_alias=None,
    )
    return version.id


async def _create_roles(db, number: int) -> str:
    version = await create_team_roles_version(
        db,
        team_id=TEAM_ID,
        base_roles_id=None,
        bundle={"roles": {"dev": {"title": f"version {number}", "playbook_md": ""}}, "adapters": {}},
        created_by_alias=None,
    )
    return version.id


INSTRUCTIONS = TeamDocument(
    name="instructions",
    table="team_instructions",
    create=_create_instructions,
    activate=lambda db, version_id: activate_team_instructions(db, team_id=TEAM_ID, instructions_id=version_id),
)
ROLES = TeamDocument(
    name="roles",
    table="team_roles",
    create=_create_roles,
    activate=lambda db, version_id: activate_team_roles(db, team_id=TEAM_ID, roles_id=version_id),
)
DOCUMENTS = pytest.mark.parametrize("document", [INSTRUCTIONS, ROLES], ids=lambda document: document.name)


async def _create_versions(db, document: TeamDocument, count: int) -> list[str]:
    return [await document.create(db, number + 1) for number in range(count)]


async def _active_ids(db, document: TeamDocument) -> list[str]:
    rows = await db.fetch_all(
        f"""
        SELECT id FROM {{{{tables.{document.table}}}}}
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


@DOCUMENTS
@pytest.mark.asyncio
async def test_concurrent_activations_leave_exactly_one_active(aweb_cloud_db, document):
    db = aweb_cloud_db.aweb_db
    first, second, third = await _create_versions(db, document, 3)
    await document.activate(db, first)

    # Holding the active row makes both activations wait at the same point, so
    # they are in flight together when the row is released.
    async with db.transaction() as holder:
        await holder.execute(
            f"SELECT id FROM {{{{tables.{document.table}}}}} WHERE id = $1 FOR UPDATE",
            first,
        )
        activations = [
            asyncio.create_task(document.activate(db, target))
            for target in (second, third)
        ]
        await _wait_for_lock_waiters(db, 2)

    await asyncio.gather(*activations)

    active = await _active_ids(db, document)
    assert len(active) == 1, active
    assert active[0] in (second, third)


@DOCUMENTS
@pytest.mark.asyncio
async def test_failed_activation_leaves_previous_version_active(aweb_cloud_db, document):
    db = aweb_cloud_db.aweb_db
    first, second = await _create_versions(db, document, 2)
    await document.activate(db, first)

    await db.execute(
        """
        CREATE FUNCTION aweb.refuse_activation() RETURNS trigger AS $$
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
        f"""
        CREATE TRIGGER refuse_activation
        BEFORE UPDATE ON {{{{tables.{document.table}}}}}
        FOR EACH ROW EXECUTE FUNCTION aweb.refuse_activation()
        """
    )

    with pytest.raises(Exception, match="activation refused by test trigger"):
        await document.activate(db, second)

    assert await _active_ids(db, document) == [first]

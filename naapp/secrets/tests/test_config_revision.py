"""The configuration revision a change set is drafted against (decision 54), on real PostgreSQL."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_secrets.change import ChangeRefused, check_confirmable
from aweb_secrets.revisions import (
    apply_revision_migrations,
    bump_config_revision,
    config_revision,
)

INSTALLATION = "inst_1"
OTHER = "inst_2"


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="secrets_revisions")
    await apply_revision_migrations(database)
    yield database


async def _bump(db: AsyncDatabaseManager, installation_id: str) -> int:
    async with db.transaction() as tx:
        return await bump_config_revision(tx, installation_id)


async def test_an_installation_starts_at_revision_zero(db: AsyncDatabaseManager) -> None:
    assert await config_revision(db, INSTALLATION) == 0


async def test_each_bump_moves_one_installation_on(db: AsyncDatabaseManager) -> None:
    assert await _bump(db, INSTALLATION) == 1
    assert await _bump(db, INSTALLATION) == 2
    assert await config_revision(db, INSTALLATION) == 2
    assert await config_revision(db, OTHER) == 0


async def test_a_bump_rolls_back_with_its_transaction(db: AsyncDatabaseManager) -> None:
    class Abandoned(Exception):
        pass

    with pytest.raises(Abandoned):
        async with db.transaction() as tx:
            await bump_config_revision(tx, INSTALLATION)
            raise Abandoned
    assert await config_revision(db, INSTALLATION) == 0


async def test_concurrent_bumps_each_get_their_own_revision(db: AsyncDatabaseManager) -> None:
    revisions = await asyncio.gather(*(_bump(db, INSTALLATION) for _ in range(5)))
    assert sorted(revisions) == [1, 2, 3, 4, 5]


def _change(base_revision: int) -> dict[str, Any]:
    return {
        "v": 1,
        "type": "aweb.secrets.change",
        "change_id": "chg_1",
        "installation_id": INSTALLATION,
        "install_generation": 1,
        "team_id": "backend:acme.com",
        "drafter": {"via": "console", "scope": "secrets.owner.x", "subject": "approver-1"},
        "base_revision": base_revision,
        "changes": [
            {
                "kind": "secret_value",
                "op": "create",
                "ref": "payments-live",
                "after": {"v": 1, "secret_ref": "payments-live", "version": 2},
            }
        ],
        "reason": "",
        "issued_at": "2026-10-20T12:00:00Z",
        "expires_at": "2026-10-20T12:15:00Z",
    }


async def test_a_draft_computed_before_a_narrowing_act_is_stale_after_it(
    db: AsyncDatabaseManager,
) -> None:
    drafted = _change(await config_revision(db, INSTALLATION))
    await _bump(db, INSTALLATION)  # a revoke, disable or remove (S8, §12)
    with pytest.raises(ChangeRefused) as refused:
        check_confirmable(
            drafted,
            installation_id=INSTALLATION,
            install_generation=1,
            team_id="backend:acme.com",
            current_revision=await config_revision(db, INSTALLATION),
            now=datetime(2026, 10, 20, 12, 5, tzinfo=UTC),
        )
    assert refused.value.code == "base_revision_stale"

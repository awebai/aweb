"""Pause the real rotation writer and observe its actual PostgreSQL lock graph.

The trigger takes only an advisory lock. It cannot supply the team-row lock
whose ownership is asserted here, or replace any production write.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from uuid import UUID, uuid4

import httpx
from pgdbm import AsyncDatabaseManager

RequestOperation = Callable[[], Awaitable[httpx.Response]]


async def _blocked_backend(
    db: AsyncDatabaseManager,
    *,
    blocked_by: int,
    request: asyncio.Task[httpx.Response],
) -> int:
    async with asyncio.timeout(10):
        while True:
            if request.done():
                response = request.result()
                raise AssertionError(
                    f"request finished before its lock barrier: {response.status_code} {response.text}"
                )
            row = await db.fetch_one(
                """
                SELECT pid FROM pg_stat_activity
                 WHERE datname = current_database()
                   AND $1 = ANY(pg_blocking_pids(pid))
                """,
                blocked_by,
            )
            if row is not None:
                pid = row["pid"]
                if not isinstance(pid, int):
                    raise AssertionError("PostgreSQL did not return a backend PID")
                return pid
            # PostgreSQL exposes lock waits as state, without a notification
            # event. Poll only this test's blocker, within the bounded timeout.
            await asyncio.sleep(0.01)


@dataclass(frozen=True)
class RotationBarrier:
    db: AsyncDatabaseManager
    tasks: asyncio.TaskGroup
    rotation: asyncio.Task[httpx.Response]
    backend_pid: int

    async def start_competing(
        self, operation: RequestOperation
    ) -> asyncio.Task[httpx.Response]:
        request = self.tasks.create_task(operation())
        await _blocked_backend(self.db, blocked_by=self.backend_pid, request=request)
        return request


@asynccontextmanager
async def paused_rotation(
    db: AsyncDatabaseManager,
    *,
    domain: str,
    name: str,
    rotate: RequestOperation,
) -> AsyncIterator[RotationBarrier]:
    """Hold a real route at its UPDATE after witnessing its prior row lock.

    Removing rotation's SELECT FOR UPDATE fails the RowShareLock assertion;
    removing a competing route's lock makes that request finish before the
    correlated lock-wait witness. All effects still run through HTTP routes.
    """
    team = await db.fetch_one(
        "SELECT team_uuid FROM {{tables.teams}} WHERE domain = $1 AND name = $2",
        domain,
        name,
    )
    if team is None:
        raise AssertionError("rotation fixture has no team")
    team_uuid = UUID(str(team["team_uuid"]))
    suffix = uuid4().hex
    function = f"r13_rotation_pause_{suffix}"
    trigger = f"r13_rotation_trigger_{suffix}"
    lock_id = uuid4().int & ((1 << 63) - 1)
    # Identifiers and trigger arguments are generated UUID/integer values;
    # the domain and team selectors above remain bound parameters.
    await db.execute(
        f"""
        CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $body$
        BEGIN
            PERFORM pg_advisory_xact_lock(TG_ARGV[0]::bigint);
            RETURN NEW;
        END;
        $body$
        """
    )
    try:
        await db.execute(
            f"""
            CREATE TRIGGER {trigger} BEFORE UPDATE ON {{{{tables.teams}}}}
            FOR EACH ROW WHEN (OLD.team_uuid = '{team_uuid}'::uuid)
            EXECUTE FUNCTION {function}('{lock_id}')
            """
        )
        try:
            async with asyncio.TaskGroup() as tasks:
                async with db.transaction() as holder:
                    await holder.execute("SELECT pg_advisory_xact_lock($1)", lock_id)
                    owner = await holder.fetch_one("SELECT pg_backend_pid() AS pid")
                    if owner is None or not isinstance(owner["pid"], int):
                        raise AssertionError("no advisory-lock owner PID")
                    rotation = tasks.create_task(rotate())
                    pid = await _blocked_backend(
                        db, blocked_by=owner["pid"], request=rotation
                    )
                    held = await db.fetch_one(
                        """
                        SELECT EXISTS (
                            SELECT 1 FROM pg_locks
                             WHERE pid = $1 AND granted
                               AND relation = '{{tables.teams}}'::regclass
                               AND mode = 'RowShareLock'
                        ) AS row_lock_held
                        """,
                        pid,
                    )
                    if held is None or held["row_lock_held"] is not True:
                        raise AssertionError(
                            "real rotation did not acquire its SELECT FOR UPDATE team lock"
                        )
                    yield RotationBarrier(db, tasks, rotation, pid)
                # Release the advisory barrier before TaskGroup joins requests.
        finally:
            await db.execute(f"DROP TRIGGER {trigger} ON {{{{tables.teams}}}}")
    finally:
        await db.execute(f"DROP FUNCTION {function}()")

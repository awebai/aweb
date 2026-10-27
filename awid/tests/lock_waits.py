"""Wait until a concurrent request is blocked on a PostgreSQL row lock."""

from __future__ import annotations

import asyncio

STALL_SECONDS = 10.0
POLL_SECONDS = 0.01


async def wait_until_blocked_on_lock(db, task: asyncio.Task, *, waiters: int = 1) -> None:
    """Return once ``waiters`` backends in this database wait on a lock.

    Fails if ``task`` finishes first, which means it never waited, or if no
    backend is blocked within the stall bound.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + STALL_SECONDS
    while loop.time() < deadline:
        if task.done():
            task.result()
            raise AssertionError("the request finished without waiting on a lock")
        blocked = await db.fetch_value(
            """
            SELECT COUNT(*)::int
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND wait_event_type = 'Lock'
            """
        )
        if blocked >= waiters:
            return
        await asyncio.sleep(POLL_SECONDS)
    raise AssertionError(f"no request blocked on a lock within {STALL_SECONDS}s")

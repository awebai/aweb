"""A drain process for the outbox crash test: it materializes one target, then
blocks inside the send until the test kills it.

Usage: drain_child.py <database dsn> <file to create once sending>
"""

from __future__ import annotations

import asyncio
import sys
from datetime import timedelta
from pathlib import Path

from pgdbm import AsyncDatabaseManager, DatabaseConfig

from aweb_naapp.outbox import RetryPolicy, StoredEvent, Target, drain


async def main(dsn: str, sending: Path) -> None:
    db = AsyncDatabaseManager(DatabaseConfig(connection_string=dsn))
    await db.connect()

    async def resolver(event: StoredEvent) -> list[Target]:
        return [Target("a")]

    class Blocking:
        async def deliver(self, event: StoredEvent, target: Target):
            sending.write_text(str(event.event_id))
            await asyncio.Event().wait()

    await drain(
        db,
        resolver=resolver,
        transport=Blocking(),
        policy=RetryPolicy(stalled_after=timedelta(hours=1)),
    )


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], Path(sys.argv[2])))

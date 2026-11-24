"""Bound the event-controlled certificate read schedules used by server tests."""

import asyncio
from contextlib import asynccontextmanager


@asynccontextmanager
async def scheduled_certificate_readers():
    """Stop a broken schedule even if a reader never reaches its event."""
    async with asyncio.timeout(30), asyncio.TaskGroup() as readers:
        yield readers

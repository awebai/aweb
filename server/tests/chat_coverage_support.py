"""Run the shipped data migration on a historical session fixture."""

from pathlib import Path

import aweb


async def migrate_chat_conversation_coverage(database) -> None:
    migration = (
        Path(aweb.__file__).parent
        / "migrations/aweb/055_chat_conversation_coverage.sql"
    )
    async with database.transaction() as transaction:
        await transaction.execute(migration.read_text())

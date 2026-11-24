"""The real migration rolls back on a held writer and can be retried."""

import asyncio
import hashlib

import asyncpg
import pytest
from pgdbm.errors import MigrationError

from tests.product_migration_support import MIGRATIONS, stage_aweb_upgrade


MIGRATION = "057_legacy_mail_index.sql"
INDEX = "aweb.idx_messages_legacy_created_id"


@pytest.mark.asyncio
async def test_legacy_mail_index_times_out_cleanly_and_retries(
    shared_test_pool, tmp_path
):
    async with stage_aweb_upgrade(
        shared_test_pool, tmp_path / "legacy-index", MIGRATION
    ) as upgrade:
        db = upgrade.infra.get_manager()
        assert await db.fetch_value("SELECT to_regclass($1)", INDEX) is None
        async with shared_test_pool.acquire() as writer, writer.transaction():
            await writer.execute("LOCK TABLE aweb.messages IN ROW EXCLUSIVE MODE")
            async with asyncio.timeout(10):
                with pytest.raises(MigrationError) as failed:
                    await upgrade.apply()
            assert failed.value.details["migration_file"] == MIGRATION
            assert isinstance(failed.value.__cause__, asyncpg.LockNotAvailableError)
            assert await db.fetch_value("SELECT to_regclass($1)", INDEX) is None
            assert MIGRATION not in await upgrade.manager.get_applied_migrations()

        assert await upgrade.apply() == [MIGRATION]
        definition = await db.fetch_one(
            """SELECT indisvalid, indisready, pg_get_indexdef(indexrelid) AS definition,
                      pg_get_expr(indpred, indrelid) AS predicate
               FROM pg_index WHERE indexrelid = to_regclass($1)""",
            INDEX,
        )
        assert definition is not None
        assert definition["indisvalid"] and definition["indisready"]
        assert "(created_at DESC, message_id DESC)" in definition["definition"]
        assert definition["predicate"] == "(conversation_id IS NULL)"
        receipt = (await upgrade.manager.get_applied_migrations())[MIGRATION]
        assert (
            receipt.checksum
            == hashlib.sha256(
                (MIGRATIONS / MIGRATION).read_text().strip().encode("utf-8")
            ).hexdigest()
        )
        assert await upgrade.apply() == []

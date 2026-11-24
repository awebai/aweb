"""The real migration rolls back after lock or build timeout and can be retried."""

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


@pytest.mark.asyncio
async def test_legacy_mail_index_build_timeout_is_local_and_can_retry(
    shared_test_pool, tmp_path
):
    async with stage_aweb_upgrade(
        shared_test_pool, tmp_path / "legacy-build-timeout", MIGRATION
    ) as upgrade:
        db = upgrade.infra.get_manager()
        # Force the real CREATE INDEX to spend time in its command-end event
        # trigger. PostgreSQL must arm the timeout for that statement even
        # though pgdbm sends SET LOCAL and CREATE INDEX together.
        await db.execute("""
            CREATE FUNCTION aweb.delay_legacy_index_build() RETURNS event_trigger
            LANGUAGE plpgsql AS $body$
            BEGIN
                PERFORM pg_sleep(0.2);
            END
            $body$;
            CREATE EVENT TRIGGER delay_legacy_index_build ON ddl_command_end
            WHEN TAG IN ('CREATE INDEX')
            EXECUTE FUNCTION aweb.delay_legacy_index_build()
        """)
        session = """
            SELECT pg_backend_pid() AS pid, current_setting('statement_timeout') AS timeout
        """
        before = await db.fetch_one(session)
        source = (MIGRATIONS / MIGRATION).read_text()
        production_bound = "SET LOCAL statement_timeout = '5s';"
        assert source.count(production_bound) == 1
        (upgrade.staged / MIGRATION).write_text(
            source.replace(production_bound, "SET LOCAL statement_timeout = '25ms';")
        )
        async with asyncio.timeout(10):
            with pytest.raises(MigrationError) as failed:
                await upgrade.manager.apply_pending_migrations()
        assert failed.value.details["migration_file"] == MIGRATION
        cause = failed.value.__cause__
        assert isinstance(cause, asyncpg.QueryCanceledError)
        assert "statement timeout" in str(cause)
        assert "delay_legacy_index_build" in cause.context
        assert await db.fetch_one(session) == before
        assert await db.fetch_value("SELECT to_regclass($1)", INDEX) is None
        assert MIGRATION not in await upgrade.manager.get_applied_migrations()

        assert await upgrade.apply() == [MIGRATION]
        assert await db.fetch_one(session) == before
        assert await db.fetch_value(
            "SELECT indisvalid FROM pg_index WHERE indexrelid=to_regclass($1)", INDEX
        )

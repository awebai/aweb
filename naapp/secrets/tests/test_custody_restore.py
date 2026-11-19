"""A real content-only rollback cannot make erased ciphertext serve again."""

import asyncio
import os
import subprocess

import pytest
from aweb_secrets.schema import service_schema_fingerprint

from aweb_secrets.erasure import ErasureFailure, ErasureUnavailable, check_erasure_store
from tests.custody.test_erasure import erasedb as erasedb
from tests.custody.test_erasure import staged


async def postgres_tool(db, *arguments):
    config = db.config
    environment = {
        **os.environ,
        "PGHOST": config.host,
        "PGPORT": str(config.port),
        "PGUSER": config.user,
        "PGPASSWORD": config.password,
        "PGDATABASE": await db.fetch_value("SELECT current_database()"),
    }
    assert environment["PGDATABASE"].startswith("test_")
    result = await asyncio.to_thread(
        subprocess.run, arguments, env=environment, capture_output=True, check=False
    )
    if result.returncode:
        raise AssertionError(f"{arguments[0]} failed with exit {result.returncode}")


async def test_real_content_rollback_is_refused_by_retained_erasure_authority(erasedb, tmp_path):
    operator, service, _, custody = erasedb
    context = await staged(custody, service)
    backup = tmp_path / "secrets-content.dump"
    # Only this schema is restorable content; secrets_erasure is NEVER dumped.
    await postgres_tool(
        operator,
        "pg_dump",
        "--format=custom",
        "--schema",
        operator.schema,
        "--file",
        str(backup),
    )
    backup.chmod(0o400)
    async with service.transaction() as tx:
        await custody.destroy(tx, context)
    ledger_identity = await operator.fetch_value("SELECT identity FROM secrets_erasure.store")
    # All writers are quiescent. Preserve ownership, ACLs and the live ledger.
    # There are no service tasks or requests in this world. The idle runtime
    # pool has no open transaction and does no DDL when a connection is reused.
    await postgres_tool(
        operator,
        "pg_restore",
        "--clean",
        "--if-exists",
        "--exit-on-error",
        "--dbname",
        await operator.fetch_value("SELECT current_database()"),
        str(backup),
    )
    assert (
        await operator.fetch_value("SELECT identity FROM secrets_erasure.store") == ledger_identity
    )
    assert await operator.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1
    with pytest.raises(ErasureUnavailable) as refusal:
        await check_erasure_store(service, expected_schema_digest=service_schema_fingerprint())
    assert refusal.value.reason is ErasureFailure.INCOMPLETE
    assert "restore is not supported" in str(refusal.value)

"""Erasure is atomic with plain SQL writers and cannot be bypassed by the service role."""

import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from urllib.parse import quote, urlsplit
from uuid import uuid4

import asyncpg
import pytest
from pgdbm import AsyncDatabaseManager

from aweb_secrets.custody import Custody, LocalKeyFileProvider, SealContext, encode_value
from aweb_secrets.custody.onepassword import project_item
from aweb_secrets.custody.run_pins import RunPins
from aweb_secrets.erasure import (
    ErasureFailure,
    ErasureUnavailable,
    check_erasure_store,
    initialize_erasure_store,
    map_erasure_failure,
    operator_receipts,
)
from aweb_secrets.run_pin_store import retain
from aweb_secrets.schema import service_schema_fingerprint
from aweb_secrets.secret import SecretRecord
from tests.custody.conftest import initial_record
from tests.custody.test_onepassword import field, reference, sdk_item


class PrivilegeSource(StrEnum):
    PUBLIC = "public"
    INHERITED = "inherited"
    TABLE_GRANT_OPTION = "table_grant_option"
    COLUMN_GRANT_OPTION = "column_grant_option"


@pytest.fixture
async def erasedb(test_db_factory, tmp_path):
    db = await test_db_factory.create_db(suffix="secrets_erasure")
    role = "erasure_test_" + uuid4().hex
    password = secrets.token_urlsafe(32)
    async with db.transaction() as tx:
        await tx.execute("SELECT set_config('aweb_test.role_password',$1,true)", password)
        # A real runtime login, not an administrator session using SET ROLE.
        # The generated credential stays in this private database world.
        await tx.execute(
            "DO $$ BEGIN EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L',"
            f" '{role}',current_setting('aweb_test.role_password')); END $$"
        )
    try:
        await initialize_erasure_store(db, application_role=role, max_backup_age=timedelta(days=7))
        key = tmp_path / "custody-key"
        key.write_text(secrets.token_hex(32))
        key.chmod(0o600)
        original = urlsplit(db.config.get_dsn())
        runtime_dsn = original._replace(
            netloc=f"{quote(role, safe='')}:{quote(password, safe='')}@{original.netloc.rsplit('@', 1)[-1]}"
        ).geturl()
        config = db.config.model_copy(
            update={
                "connection_string": runtime_dsn,
                "min_connections": 1,
                "max_connections": 2,
                "server_settings": None,
            }
        )
        pool = await AsyncDatabaseManager.create_shared_pool(config)
        service = AsyncDatabaseManager(pool=pool, schema=db.schema)
        try:
            yield db, service, role, Custody(LocalKeyFileProvider(key), service)
        finally:
            await pool.close()
    finally:
        await db.execute(f'DROP OWNED BY "{role}"')
        await db.execute(f'DROP ROLE "{role}"')


async def staged(custody, db):
    record = initial_record("sec_" + uuid4().hex)
    async with db.transaction() as tx:
        version = await custody.sealer.ingest(
            tx,
            installation_id="erasure-installation",
            team_id="erasure:test",
            secret_id=record.secret_id,
            value=encode_value("bearer", {"value": secrets.token_urlsafe(32)}),
            initial=record,
        )
    return SealContext("erasure-installation", "erasure:test", record.secret_id, version)


async def test_uninitialised_store_has_actionable_failure(test_db_factory):
    db = await test_db_factory.create_db(suffix="erasure_uninitialised")
    with pytest.raises(ErasureUnavailable) as refusal:
        await check_erasure_store(db, expected_schema_digest=service_schema_fingerprint())
    assert refusal.value.reason is ErasureFailure.UNINITIALISED
    assert "init-erasure" in str(refusal.value)


async def test_initialisation_is_idempotent_and_preserves_binding(erasedb):
    operator, service, role, _ = erasedb
    before = await operator.fetch_value("SELECT identity FROM secrets_erasure.store")
    await initialize_erasure_store(
        operator, application_role=role, max_backup_age=timedelta(days=7)
    )
    assert await operator.fetch_value("SELECT identity FROM secrets_erasure.store") == before
    await check_erasure_store(service, expected_schema_digest=service_schema_fingerprint())


@pytest.mark.parametrize(
    "grant",
    [
        *(
            f"TRUNCATE ON {{{{tables.{table}}}}}"
            for table in (
                "custody_secrets",
                "sealed_versions",
                "onepassword_versions",
                "run_redaction_pins",
                "erasure_store_identity",
            )
        ),
        "ALL ON ALL TABLES IN SCHEMA {{schema}}",
        "DELETE ON {{tables.custody_secrets}}",
        "UPDATE ON {{tables.sealed_versions}}",
        "UPDATE ON {{tables.run_redaction_pins}}",
        "UPDATE ON {{tables.onepassword_versions}}",
        "INSERT ON {{tables.erasure_store_identity}}",
        "REFERENCES ON {{tables.sealed_versions}}",
        "TRIGGER ON {{tables.onepassword_versions}}",
        "UPDATE(wrapped_key) ON {{tables.sealed_versions}}",
        "UPDATE(secret_id) ON {{tables.run_redaction_pins}}",
        "UPDATE(secret_id) ON {{tables.onepassword_versions}}",
        "INSERT(identity) ON {{tables.erasure_store_identity}}",
        "UPDATE(last_version) ON secrets_erasure.allocations",
    ],
)
async def test_startup_refuses_grants_added_after_valid_initialisation(erasedb, grant):
    operator, service, role, custody = erasedb
    await staged(custody, service)
    await check_erasure_store(service, expected_schema_digest=service_schema_fingerprint())
    await operator.execute(f'GRANT {grant} TO "{role}"')

    with pytest.raises(ErasureUnavailable) as refusal:
        await check_erasure_store(service, expected_schema_digest=service_schema_fingerprint())
    assert refusal.value.reason is ErasureFailure.ROLE_UNSAFE


@pytest.mark.parametrize("source", list(PrivilegeSource))
async def test_startup_checks_effective_and_delegatable_privileges(
    erasedb, source: PrivilegeSource
):
    operator, service, role, _ = erasedb
    parent = "erasure_grantee_" + uuid4().hex
    await check_erasure_store(service, expected_schema_digest=service_schema_fingerprint())
    if source is PrivilegeSource.INHERITED:
        await operator.execute(f'CREATE ROLE "{parent}" NOLOGIN')
        await operator.execute(f'GRANT "{parent}" TO "{role}"')
    try:
        if source in (PrivilegeSource.PUBLIC, PrivilegeSource.INHERITED):
            grantee = "PUBLIC" if source is PrivilegeSource.PUBLIC else f'"{parent}"'
            grant = "TRUNCATE ON {{tables.sealed_versions}}"
            option = ""
        else:
            grantee = f'"{role}"'
            grant = (
                "SELECT ON {{tables.sealed_versions}}"
                if source is PrivilegeSource.TABLE_GRANT_OPTION
                else "SELECT(secret_id) ON {{tables.sealed_versions}}"
            )
            option = " WITH GRANT OPTION"
        await operator.execute(f"GRANT {grant} TO {grantee}{option}")
        with pytest.raises(ErasureUnavailable) as refusal:
            await check_erasure_store(service, expected_schema_digest=service_schema_fingerprint())
        assert refusal.value.reason is ErasureFailure.ROLE_UNSAFE

        revoke = "GRANT OPTION FOR " if option else ""
        await operator.execute(f"REVOKE {revoke}{grant} FROM {grantee}")
        await check_erasure_store(service, expected_schema_digest=service_schema_fingerprint())
    finally:
        if source is PrivilegeSource.INHERITED:
            await operator.execute(f'DROP OWNED BY "{parent}"')
            await operator.execute(f'DROP ROLE "{parent}"')


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE {{tables.sealed_versions}} DISABLE TRIGGER ALL",
        "DROP TRIGGER secrets_record_erasure ON {{tables.sealed_versions}}",
        "INSERT INTO secrets_erasure.erasures DEFAULT VALUES",
        "DELETE FROM secrets_erasure.erasures",
        "TRUNCATE secrets_erasure.erasures",
        "ALTER FUNCTION secrets_erasure.record_erasure() RENAME TO bypass_erasure",
        "DROP SCHEMA secrets_erasure CASCADE",
        "DROP SCHEMA {{schema}} CASCADE",
        "TRUNCATE {{tables.sealed_versions}} CASCADE",
        "SET session_replication_role=replica",
    ],
)
async def test_runtime_role_cannot_remove_the_invariant(erasedb, statement):
    _, db, _, _ = erasedb
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.transaction() as tx:
            await tx.execute(statement)
    await check_erasure_store(db, expected_schema_digest=service_schema_fingerprint())


async def test_lost_ledger_cannot_be_reinitialised_over_content(erasedb):
    operator, db, role, custody = erasedb
    await staged(custody, db)
    await operator.execute("DROP SCHEMA secrets_erasure CASCADE")
    with pytest.raises(ErasureUnavailable) as refusal:
        await initialize_erasure_store(
            operator, application_role=role, max_backup_age=timedelta(days=7)
        )
    assert refusal.value.reason is ErasureFailure.RESTORE_WITHOUT_LEDGER
    with pytest.raises(ErasureUnavailable) as refusal:
        await check_erasure_store(db, expected_schema_digest=service_schema_fingerprint())
    assert refusal.value.reason is ErasureFailure.RESTORE_WITHOUT_LEDGER
    assert "Do not initialise" in str(refusal.value)


@pytest.mark.parametrize("carrier", ["sealed", "reference_clear", "reference_delete", "pin"])
async def test_every_plain_destructive_statement_is_atomic_with_its_tombstone(
    erasedb, tmp_path, carrier
):
    _, db, _, custody = erasedb
    context = await staged(custody, db)
    if carrier.startswith("reference"):
        async with db.transaction() as tx:
            credential = await custody.stage_backend_credential(
                tx,
                installation_id=context.installation_id,
                team_id=context.team_id,
                value=encode_value("bearer", {"value": secrets.token_urlsafe(32)}),
            )
        record = SecretRecord.from_after(
            {
                **initial_record("sec_" + uuid4().hex).after,
                "backend": "onepassword",
            }
        )
        observed = project_item(
            reference(),
            sdk_item([field("credential", secrets.token_urlsafe(32))]),
            credential_context=credential,
        )
        async with db.transaction() as tx:
            candidate = await custody.stage_onepassword_reference(
                tx,
                installation_id=context.installation_id,
                team_id=context.team_id,
                secret_id=record.secret_id,
                observed=observed,
                initial=record,
            )
        context = candidate.context
        table = "onepassword_versions"
        statement = (
            "UPDATE {{tables.onepassword_versions}} SET binding=NULL,destroyed_at=clock_timestamp()"
            if carrier == "reference_clear"
            else "DELETE FROM {{tables.onepassword_versions}}"
        )
        live = "binding IS NOT NULL"
    elif carrier == "pin":
        value = await custody.opener.open(context)
        pin = await RunPins(LocalKeyFileProvider(tmp_path / "custody-key")).prepare(
            context, uuid4(), value, observation=None, grant_id="grt_synthetic0001"
        )
        async with db.transaction() as tx:
            await retain(tx, [pin], deadline=datetime.now(UTC) + timedelta(hours=1))
        table, statement, live = (
            "run_redaction_pins",
            "DELETE FROM {{tables.run_redaction_pins}}",
            "true",
        )
    else:
        table, statement, live = "sealed_versions", "DELETE FROM {{tables.sealed_versions}}", "true"

    saved = await db.fetch_one(f"SELECT * FROM {{{{tables.{table}}}}}")

    # Transaction rollback is the acceptance proof, not an application callback.
    class Abandon(Exception):
        pass

    with pytest.raises(Abandon):
        async with db.transaction() as tx:
            await tx.execute(statement)
            [receipt] = await operator_receipts(tx)
            assert receipt.context == context
            raise Abandon
    assert await operator_receipts(db) == ()
    assert await db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}} WHERE {live}") == 1
    await db.execute(statement)
    [receipt] = await operator_receipts(db)
    assert receipt.context == context
    assert receipt.recoverable_until - receipt.destroyed_at == timedelta(days=7)
    assert await db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}} WHERE {live}") == 0
    if carrier == "pin":
        assert receipt.dispatch_id == str(pin.dispatch_id)
    assert receipt.recoverable_until.isoformat() in receipt.explanation
    await db.execute(statement)
    assert await operator_receipts(db) == (receipt,)
    await check_erasure_store(db, expected_schema_digest=service_schema_fingerprint())
    columns = ",".join(saved.keys())
    placeholders = ",".join(f"${i}" for i in range(1, len(saved) + 1))
    with pytest.raises(asyncpg.PostgresError) as resurrection:
        async with db.transaction() as tx:
            await tx.execute(
                f"INSERT INTO {{{{tables.{table}}}}} ({columns}) VALUES({placeholders})",
                *saved.values(),
            )
    assert map_erasure_failure(resurrection.value).reason is ErasureFailure.INCOMPLETE


async def test_changing_schema_cannot_initialise_over_existing_unbound_content(erasedb):
    operator, db, role, custody = erasedb
    await staged(custody, db)
    await operator.execute("DROP SCHEMA secrets_erasure CASCADE")
    await operator.execute("DROP TABLE {{tables.erasure_store_identity}}")
    other = AsyncDatabaseManager(
        operator.config.model_copy(update={"schema_name": "other_content"})
    )
    await other.connect()
    try:
        with pytest.raises(ErasureUnavailable) as refusal:
            await initialize_erasure_store(
                other, application_role=role, max_backup_age=timedelta(days=7)
            )
        assert refusal.value.reason is ErasureFailure.RESTORE_WITHOUT_LEDGER
        assert not await operator.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='secrets_erasure')"
        )
    finally:
        await other.disconnect()


async def test_allocation_floor_rolls_back_and_refuses_context_reuse(erasedb):
    operator, db, _, custody = erasedb
    context = await staged(custody, db)
    assert await db.fetch_value("SELECT last_version FROM secrets_erasure.allocations") == 1
    async with db.transaction() as tx:
        await tx.execute("SAVEPOINT allocation")
        await tx.execute("UPDATE {{tables.custody_secrets}} SET last_version=last_version+1")
        assert await tx.fetch_value("SELECT last_version FROM secrets_erasure.allocations") == 2
        await tx.execute("ROLLBACK TO SAVEPOINT allocation")
        assert await tx.fetch_value("SELECT last_version FROM secrets_erasure.allocations") == 1
    # Simulate content rollback by an operator while retaining the newer floor.
    await operator.execute(
        "ALTER TABLE {{tables.custody_secrets}} DISABLE TRIGGER secrets_record_allocation"
    )
    await operator.execute("UPDATE {{tables.custody_secrets}} SET last_version=0")
    await operator.execute(
        "ALTER TABLE {{tables.custody_secrets}} ENABLE TRIGGER secrets_record_allocation"
    )
    with pytest.raises(ErasureUnavailable) as refusal:
        await check_erasure_store(db, expected_schema_digest=service_schema_fingerprint())
    assert refusal.value.reason is ErasureFailure.ALLOCATION_REGRESSED
    with pytest.raises(asyncpg.PostgresError) as trigger_error:
        async with db.transaction() as tx:
            await tx.execute("UPDATE {{tables.custody_secrets}} SET last_version=1")
    assert map_erasure_failure(trigger_error.value).reason is ErasureFailure.ALLOCATION_REGRESSED
    assert (
        await operator.fetch_value("SELECT last_version FROM secrets_erasure.allocations")
        == context.version
    )


async def test_trigger_failure_rolls_back_deletion_and_has_named_mapping(erasedb):
    operator, db, _, custody = erasedb
    await staged(custody, db)
    await operator.execute("ALTER TABLE secrets_erasure.erasures RENAME TO unavailable_erasures")
    with pytest.raises(asyncpg.PostgresError) as failure:
        async with db.transaction() as tx:
            await tx.execute("DELETE FROM {{tables.sealed_versions}}")
    assert map_erasure_failure(failure.value).reason is ErasureFailure.UNAVAILABLE
    assert await operator.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1


@pytest.mark.parametrize("fault", ["identity", "schema", "floor", "trigger", "readability"])
async def test_startup_refuses_tampered_or_unreadable_authority(erasedb, fault):
    operator, db, role, custody = erasedb
    await staged(custody, db)
    statements = {
        "identity": "UPDATE secrets_erasure.store SET identity=gen_random_uuid()",
        "schema": "UPDATE secrets_erasure.store SET schema_digest='sha256:'||repeat('0',64)",
        "floor": "DELETE FROM secrets_erasure.allocations",
        "trigger": "ALTER TABLE {{tables.sealed_versions}} DISABLE TRIGGER secrets_record_erasure",
        "readability": f'REVOKE SELECT ON secrets_erasure.store FROM "{role}"',
    }
    expected = {
        "identity": ErasureFailure.IDENTITY_MISMATCH,
        "schema": ErasureFailure.SCHEMA_MISMATCH,
        "floor": ErasureFailure.ALLOCATION_REGRESSED,
        "trigger": ErasureFailure.ROLE_UNSAFE,
        "readability": ErasureFailure.UNAVAILABLE,
    }
    await operator.execute(statements[fault])
    with pytest.raises(ErasureUnavailable) as refusal:
        await check_erasure_store(db, expected_schema_digest=service_schema_fingerprint())
    assert refusal.value.reason is expected[fault]

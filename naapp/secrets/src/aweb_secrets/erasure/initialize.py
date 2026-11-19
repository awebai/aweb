"""Offline first-install preparation; service startup never calls this module."""

import re
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

from pgdbm import AsyncDatabaseManager, TransactionManager

from .errors import ErasureFailure, ErasureUnavailable
from .store import (
    OWNER_ROLE,
    PROTECTED_TABLES,
    content_exists,
    require_matching_binding,
    runtime_table_grants,
    store_present,
    verify_carriers,
    verify_role_and_triggers,
)

_IDENTIFIER = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,62}\Z")
_SQL_PATH = Path(__file__).with_name("schema.sql")


def quoted_identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError("the database role and schema must be plain PostgreSQL identifiers")
    return '"' + value + '"'


def backup_age_seconds(age: timedelta) -> int:
    seconds = age.total_seconds()
    if not seconds.is_integer() or not 0 < seconds <= 2147483647:
        raise ValueError(
            "declare a positive whole-second backup lifetime no greater than 2147483647"
        )
    return int(seconds)


async def _prepare_content(db: AsyncDatabaseManager) -> str:
    # Operator-owned DDL is completed before ownership is reduced to service DML.
    from aweb_secrets.schema import prepare_service_schema

    return await prepare_service_schema(db)


async def _matching_store(
    db: AsyncDatabaseManager | TransactionManager,
    application_role: str,
    age_seconds: int,
    *,
    content_schema: str,
    expected_schema_digest: str,
) -> UUID:
    row = await require_matching_binding(db, content_schema=content_schema)
    if row["schema_digest"] != expected_schema_digest:
        raise ErasureUnavailable(ErasureFailure.SCHEMA_MISMATCH)
    if row["application_role"] != application_role or row["max_backup_age_seconds"] != age_seconds:
        raise ErasureUnavailable(ErasureFailure.IDENTITY_MISMATCH)
    return row["identity"]


async def _prepare_owner(tx: TransactionManager, application_role: str) -> None:
    if not await tx.fetch_value("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"):
        raise ValueError("run init-erasure with the database administrator, not the runtime role")
    role = await tx.fetch_one("SELECT * FROM pg_roles WHERE rolname=$1", application_role)
    if role is None or role["rolsuper"] or role["rolcreaterole"] or application_role == OWNER_ROLE:
        raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)
    await tx.execute(
        "DO $$ BEGIN CREATE ROLE secrets_erasure_owner NOLOGIN NOINHERIT;"
        " EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    owner = await tx.fetch_one("SELECT * FROM pg_roles WHERE rolname=$1", OWNER_ROLE)
    if (
        owner is None
        or owner["rolcanlogin"]
        or owner["rolsuper"]
        or owner["rolcreaterole"]
        or await tx.fetch_value(
            "SELECT pg_has_role($1::name,$2::name,'MEMBER')", application_role, OWNER_ROLE
        )
    ):
        raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)


async def _install_store(
    tx: TransactionManager,
    *,
    content_schema: str,
    application_role: str,
    age_seconds: int,
    schema_digest: str,
) -> UUID:
    schema, role = quoted_identifier(content_schema), quoted_identifier(application_role)
    await tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended('aweb.secrets.erasure.init/1',0))"
    )
    # Recheck under the initializer lock: concurrent matching commands are
    # idempotent too, and never replace a partially present authority.
    marker = await tx.fetch_value(
        "SELECT to_regclass($1) IS NOT NULL", f'"{content_schema}".erasure_store_identity'
    )
    ledger = await tx.fetch_value("SELECT to_regclass('secrets_erasure.store') IS NOT NULL")
    if marker and ledger:
        identity = await _matching_store(
            tx,
            application_role,
            age_seconds,
            content_schema=content_schema,
            expected_schema_digest=schema_digest,
        )
        await verify_carriers(tx)
        await verify_role_and_triggers(tx, application_role, content_schema=content_schema)
        return identity
    if (
        marker
        or ledger
        or await tx.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='secrets_erasure')"
        )
    ):
        raise ErasureUnavailable(ErasureFailure.RESTORE_WITHOUT_LEDGER)
    for table in PROTECTED_TABLES:
        await tx.execute(f"LOCK TABLE {schema}.{table} IN ACCESS EXCLUSIVE MODE")
        if await tx.fetch_value(f"SELECT EXISTS(SELECT 1 FROM {schema}.{table})"):
            raise ErasureUnavailable(ErasureFailure.RESTORE_WITHOUT_LEDGER)
    await _prepare_owner(tx, application_role)
    await tx.execute(f"CREATE SCHEMA secrets_erasure AUTHORIZATION {OWNER_ROLE}")
    await tx.execute(_SQL_PATH.read_text())
    identity = uuid4()
    await tx.execute(
        "INSERT INTO secrets_erasure.store"
        " (identity,content_schema,application_role,max_backup_age_seconds,schema_digest)"
        " VALUES($1,$2,$3,$4,$5)",
        identity,
        content_schema,
        application_role,
        age_seconds,
        schema_digest,
    )
    await tx.execute(
        "INSERT INTO {{tables.erasure_store_identity}} (identity) VALUES($1)", identity
    )
    # Bind completed preparation before the atomic ownership transfer.
    database = await tx.fetch_value("SELECT pg_catalog.quote_ident(current_database())")
    await tx.execute(f"ALTER DATABASE {database} OWNER TO {OWNER_ROLE}")
    await tx.execute(f"REVOKE CREATE ON DATABASE {database} FROM {role},PUBLIC")
    await tx.execute(f"GRANT CONNECT ON DATABASE {database} TO {role}")
    await tx.execute(f"ALTER SCHEMA {schema} OWNER TO {OWNER_ROLE}")
    await tx.execute(f"REVOKE CREATE ON SCHEMA {schema} FROM {role},PUBLIC")
    await tx.execute(f"GRANT USAGE ON SCHEMA {schema} TO {role}")
    await tx.execute(
        f"GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}"
    )
    await tx.execute(f"GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role}")
    for table in (*PROTECTED_TABLES, "erasure_store_identity"):
        await tx.execute(f"ALTER TABLE {schema}.{table} OWNER TO {OWNER_ROLE}")
        await tx.execute(f"REVOKE ALL ON {schema}.{table} FROM {role},PUBLIC")
    for table in ("store", "allocations", "erasures"):
        await tx.execute(f"ALTER TABLE secrets_erasure.{table} OWNER TO {OWNER_ROLE}")
        await tx.execute(f"REVOKE ALL ON secrets_erasure.{table} FROM {role},PUBLIC")
    for function in ("record_erasure", "record_allocation", "refuse_resurrection"):
        await tx.execute(f"ALTER FUNCTION secrets_erasure.{function}() OWNER TO {OWNER_ROLE}")
    await tx.execute(f"GRANT USAGE ON SCHEMA secrets_erasure TO {role}")
    for grants in runtime_table_grants(content_schema):
        await tx.execute(
            f"GRANT {','.join(grants.privileges)} ON {grants.qualified_name} TO {role}"
        )
        if grants.update_columns:
            await tx.execute(
                f"GRANT UPDATE({','.join(grants.update_columns)})"
                f" ON {grants.qualified_name} TO {role}"
            )
    await verify_role_and_triggers(tx, application_role, content_schema=content_schema)
    return identity


async def initialize_erasure_store(
    db: AsyncDatabaseManager, *, application_role: str, max_backup_age: timedelta
) -> UUID:
    """Create the ledger only for empty first-install content, never a restore.

    Repeating the command preserves an existing identity and policy. A missing
    side of the binding or existing content refuses before any DDL or repair.
    """
    from aweb_secrets.schema import service_schema_fingerprint

    quoted_identifier(application_role)
    schema = db.schema or "public"
    quoted_identifier(schema)
    age_seconds = backup_age_seconds(max_backup_age)
    marker, ledger = await store_present(db)
    if marker and ledger:
        identity = await _matching_store(
            db,
            application_role,
            age_seconds,
            content_schema=schema,
            expected_schema_digest=service_schema_fingerprint(),
        )
        await verify_carriers(db)
        await verify_role_and_triggers(db, application_role, content_schema=schema)
        return identity
    if (
        marker
        or ledger
        or await content_exists(db)
        or await db.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='secrets_erasure')"
        )
    ):
        raise ErasureUnavailable(ErasureFailure.RESTORE_WITHOUT_LEDGER)
    if not await db.fetch_value("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"):
        raise ValueError("run init-erasure with the database administrator, not the runtime role")
    schema_digest = await _prepare_content(db)
    async with db.transaction() as tx:
        return await _install_store(
            tx,
            content_schema=schema,
            application_role=application_role,
            age_seconds=age_seconds,
            schema_digest=schema_digest,
        )

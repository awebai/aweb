"""Read-only integrity checks and identifier-only operator destruction receipts."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

import asyncpg
from pgdbm import AsyncDatabaseManager, TransactionManager
from pgdbm.errors import QueryError

from aweb_secrets.custody.sealing import SealContext

from .errors import ErasureFailure, ErasureUnavailable

LEDGER_SCHEMA = "secrets_erasure"
OWNER_ROLE = "secrets_erasure_owner"
PROTECTED_TABLES = (
    "custody_secrets",
    "sealed_versions",
    "onepassword_versions",
    "run_redaction_pins",
)


@dataclass(frozen=True, kw_only=True)
class RuntimeTableGrants:
    schema: str
    table: str
    privileges: tuple[str, ...]
    update_columns: tuple[str, ...] = ()

    @property
    def qualified_name(self) -> str:
        return f'"{self.schema}".{self.table}'


def runtime_table_grants(content_schema: str) -> tuple[RuntimeTableGrants, ...]:
    """Accepted erasure rule 390577b1: one policy for offline grants and startup checks."""
    return (
        RuntimeTableGrants(
            schema=content_schema,
            table="custody_secrets",
            privileges=("SELECT", "INSERT", "UPDATE"),
        ),
        RuntimeTableGrants(
            schema=content_schema,
            table="sealed_versions",
            privileges=("SELECT", "INSERT", "DELETE"),
        ),
        RuntimeTableGrants(
            schema=content_schema,
            table="run_redaction_pins",
            privileges=("SELECT", "INSERT", "DELETE"),
        ),
        RuntimeTableGrants(
            schema=content_schema,
            table="onepassword_versions",
            privileges=("SELECT", "INSERT", "DELETE"),
            update_columns=("binding", "destroyed_at"),
        ),
        RuntimeTableGrants(
            schema=content_schema, table="erasure_store_identity", privileges=("SELECT",)
        ),
        *(
            RuntimeTableGrants(schema=LEDGER_SCHEMA, table=table, privileges=("SELECT",))
            for table in ("store", "allocations", "erasures")
        ),
    )


class Carrier(StrEnum):
    SEALED = "sealed"
    REFERENCE = "reference"
    PIN = "pin"


@dataclass(frozen=True)
class ErasureReceipt:
    context: SealContext
    carrier: Carrier
    dispatch_id: str
    operation_ref: str
    destroyed_at: datetime
    recoverable_until: datetime

    @property
    def explanation(self) -> str:
        return (
            "Last possible recovery deadline under the operator's declared backup "
            f"expiry policy: {self.recoverable_until.isoformat()}. The operator must "
            "enforce expiry of content backups, WAL, snapshots and retained keys; "
            "live deletion is not immediate cryptographic erasure."
        )


async def content_exists(db: AsyncDatabaseManager) -> bool:
    """A missing marker or a changed schema setting is not a fresh database."""
    tables = await db.fetch_all(
        "SELECT c.relname,format('%I.%I',n.nspname,c.relname) AS qualified_name"
        " FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace"
        " WHERE c.relkind IN ('r','p') AND c.relname=ANY($1::text[])",
        [*PROTECTED_TABLES, "secrets", "installation_fences", "erasure_store_identity"],
    )
    for table in tables:
        if table["relname"] == "erasure_store_identity" or await db.fetch_value(
            f"SELECT EXISTS(SELECT 1 FROM {table['qualified_name']})"
        ):
            return True
    return False


async def store_present(db: AsyncDatabaseManager) -> tuple[bool, bool]:
    marker = await db.fetch_value(
        "SELECT to_regclass($1) IS NOT NULL", f'"{db.schema or "public"}".erasure_store_identity'
    )
    ledger = await db.fetch_value("SELECT to_regclass('secrets_erasure.store') IS NOT NULL")
    return bool(marker), bool(ledger)


async def require_matching_binding(
    db: AsyncDatabaseManager | TransactionManager, *, content_schema: str
) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT s.*,c.identity AS content_identity"
        " FROM secrets_erasure.store s CROSS JOIN {{tables.erasure_store_identity}} c"
    )
    if (
        row is None
        or row["identity"] != row["content_identity"]
        or row["content_schema"] != content_schema
    ):
        raise ErasureUnavailable(ErasureFailure.IDENTITY_MISMATCH)
    return row


async def verify_carriers(db: AsyncDatabaseManager | TransactionManager) -> None:
    for table, carrier in (
        ("sealed_versions", Carrier.SEALED),
        ("onepassword_versions", Carrier.REFERENCE),
        ("run_redaction_pins", Carrier.PIN),
    ):
        condition = " AND v.binding IS NOT NULL" if carrier is Carrier.REFERENCE else ""
        dispatch = " AND e.dispatch_id=v.dispatch_id::text" if carrier is Carrier.PIN else ""
        if await db.fetch_value(
            f"SELECT EXISTS(SELECT 1 FROM {{{{tables.{table}}}}} v"
            " JOIN secrets_erasure.erasures e USING(installation_id,team_id,secret_id,version)"
            f" WHERE e.carrier=$1{condition}{dispatch})",
            carrier.value,
        ):
            raise ErasureUnavailable(ErasureFailure.INCOMPLETE)
    if await db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM secrets_erasure.allocations f"
        " FULL JOIN {{tables.custody_secrets}} c USING(installation_id,team_id,secret_id)"
        " WHERE c.last_version IS NULL OR f.last_version IS NULL"
        " OR c.last_version<>f.last_version)"
    ):
        raise ErasureUnavailable(ErasureFailure.ALLOCATION_REGRESSED)


async def verify_role_and_triggers(
    db: AsyncDatabaseManager | TransactionManager, application_role: str, *, content_schema: str
) -> None:
    safe = await db.fetch_value(
        "SELECT NOT (r.rolsuper OR r.rolcreaterole OR "
        "pg_has_role(r.rolname,$1::name,'MEMBER')) FROM pg_roles r WHERE rolname=$2",
        OWNER_ROLE,
        application_role,
    )
    if not safe:
        raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)
    if await db.fetch_value(
        "SELECT pg_has_role($1::name,datdba,'MEMBER')"
        " OR has_database_privilege($1::name,oid,'CREATE') FROM pg_database"
        " WHERE datname=current_database()",
        application_role,
    ):
        raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)
    for schema in (content_schema, LEDGER_SCHEMA):
        if await db.fetch_value(
            "SELECT pg_has_role($1::name,nspowner,'MEMBER')"
            " OR has_schema_privilege($1::name,oid,'CREATE') FROM pg_namespace WHERE nspname=$2",
            application_role,
            schema,
        ):
            raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)
    for grants in runtime_table_grants(content_schema):
        if await db.fetch_value(
            "SELECT pg_has_role($2::name,c.relowner,'MEMBER')"
            " FROM pg_class c WHERE c.oid=to_regclass($1)",
            grants.qualified_name,
            application_role,
        ):
            raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)
        # Enumerate this server's table privilege vocabulary, then ask for
        # effective rights (including PUBLIC/inheritance), not just direct ACLs.
        if not await db.fetch_value(
            "SELECT bool_and("
            " has_table_privilege($1::name,c.oid,p.privilege_type)"
            " = (p.privilege_type=ANY($3::text[]))"
            " AND NOT has_table_privilege($1::name,c.oid,p.privilege_type||' WITH GRANT OPTION'))"
            " FROM pg_class c CROSS JOIN LATERAL aclexplode(acldefault('r',c.relowner)) p"
            " WHERE c.oid=to_regclass($2)",
            application_role,
            grants.qualified_name,
            list(grants.privileges),
        ):
            raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)
        # Column grants are additive: a table-only check misses immutable-field
        # UPDATE and ledger writes granted on individual columns.
        if not await db.fetch_value(
            "SELECT bool_and("
            " has_column_privilege($1::name,a.attrelid,a.attnum,p.privilege)"
            " = (p.privilege=ANY($3::text[])"
            "    OR (p.privilege='UPDATE' AND a.attname=ANY($4::text[])))"
            " AND NOT has_column_privilege($1::name,a.attrelid,a.attnum,"
            " p.privilege||' WITH GRANT OPTION'))"
            " FROM pg_attribute a CROSS JOIN"
            " (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)"
            " WHERE a.attrelid=to_regclass($2) AND a.attnum>0 AND NOT a.attisdropped",
            application_role,
            grants.qualified_name,
            list(grants.privileges),
            list(grants.update_columns),
        ):
            raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)
    expected = (
        ("custody_secrets", "secrets_record_allocation"),
        *(
            (table, name)
            for table in PROTECTED_TABLES[1:]
            for name in ("secrets_record_erasure", "secrets_refuse_resurrection")
        ),
    )
    for table, name in expected:
        if not await db.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid"
            " JOIN pg_roles r ON r.oid=p.proowner WHERE t.tgrelid=to_regclass($1)"
            " AND t.tgname=$2 AND t.tgenabled IN ('O','A')"
            " AND p.prosecdef AND r.rolname=$3 AND p.proconfig=ARRAY['search_path=pg_catalog'])",
            f'"{content_schema}".{table}',
            name,
            OWNER_ROLE,
        ):
            raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)


async def check_erasure_store(db: AsyncDatabaseManager, *, expected_schema_digest: str) -> None:
    """Verify only. No CREATE, repair, replay or replacement on service startup."""
    try:
        marker, ledger = await store_present(db)
        if not marker or not ledger:
            partial = await db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='secrets_erasure')"
            )
            reason = (
                ErasureFailure.RESTORE_WITHOUT_LEDGER
                if marker or ledger or partial or await content_exists(db)
                else ErasureFailure.UNINITIALISED
            )
            raise ErasureUnavailable(reason)
        binding = await require_matching_binding(db, content_schema=db.schema or "public")
        if not expected_schema_digest or binding["schema_digest"] != expected_schema_digest:
            raise ErasureUnavailable(ErasureFailure.SCHEMA_MISMATCH)
        await verify_carriers(db)
        application_role = binding["application_role"]
        if await db.fetch_value("SELECT current_user") != application_role:
            raise ErasureUnavailable(ErasureFailure.ROLE_UNSAFE)
        await verify_role_and_triggers(db, application_role, content_schema=db.schema or "public")
    except (QueryError, asyncpg.PostgresError):
        raise ErasureUnavailable(ErasureFailure.UNAVAILABLE) from None


async def operator_receipts(
    db: AsyncDatabaseManager | TransactionManager,
) -> tuple[ErasureReceipt, ...]:
    rows = await db.fetch_all(
        "SELECT * FROM secrets_erasure.erasures"
        " ORDER BY destroyed_at,carrier,installation_id,team_id,secret_id,version,dispatch_id"
    )
    return tuple(
        ErasureReceipt(
            SealContext(row["installation_id"], row["team_id"], row["secret_id"], row["version"]),
            Carrier(row["carrier"]),
            row["dispatch_id"],
            row["operation_ref"],
            row["destroyed_at"],
            row["recoverable_until"],
        )
        for row in rows
    )

"""PostgreSQL page transactions. Content and deletion-ledger databases are separate."""

from __future__ import annotations

import copy
import hashlib
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from jsonschema import Draft202012Validator
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_naapp.idempotency import (
    IdempotencyConflict,
    IdempotencyExpired,
    apply_idempotency_migrations,
    claim,
)
from aweb_naapp.outbox import OutboxEvent, apply_outbox_migrations, enqueue
from aweb_naapp.page_store.lifecycle import LifecycleMixin
from aweb_naapp.page_store.link_records import LinkRecordContext
from aweb_naapp.page_store.models import Access, RetentionPolicy, Scope, StoreError
from aweb_naapp.page_store.support import canonical, decoded, identity, validated, widgets
from aweb_naapp.pages import PAGE_SCHEMA, inline_schema_errors, inline_value_valid

if TYPE_CHECKING:
    from aweb_naapp.runtime.team_auth import Principal

ROOT = Path(__file__).parent
MAX_REV = 2**53 - 1
KNOWN_WIDGET_TYPES = {
    definition["properties"]["type"]["const"]
    for name, definition in PAGE_SCHEMA["$defs"].items()
    if name.startswith("widget_") and "const" in definition.get("properties", {}).get("type", {})
}

# Shared by widget queries and bounded live/snapshot-creation projections.
AUTHORIZED_RECORDS = """WITH authorized AS MATERIALIZED (
    SELECT (record-'value') || jsonb_build_object('value', COALESCE(
        (SELECT jsonb_object_agg(key,value) FROM jsonb_each(record->'value')
         WHERE $5::boolean OR key=ANY($4::text[])), '{}'::jsonb)) AS record
    FROM {{tables.page_records}}
    WHERE scope=$1 AND collection=$2 AND record IS NOT NULL
      AND NOT(record_id=ANY($3::text[]))
      AND ($6::text[] IS NULL OR record_id=ANY($6::text[]))
) """


def _require_transaction(tx) -> None:
    if not isinstance(tx, TransactionManager):
        raise TypeError("a caller-owned TransactionManager is required")


def _projection_names(values, *, minimum, maximum) -> None:
    if (
        not isinstance(values, (list, tuple))
        or not minimum <= len(values) <= maximum
        or any(not isinstance(v, str) or not v or v == "*" for v in values)
        or len(set(values)) != len(values)
    ):
        raise StoreError("schema_invalid")


async def apply_page_store_migrations(
    db: AsyncDatabaseManager, ledger: AsyncDatabaseManager
) -> None:
    if db is ledger:
        raise ValueError("the deletion ledger must be outside the content restore database")
    # Distinct managers pointing at the same database are also refused.
    content_id = await db.fetch_value("SELECT current_database()")
    ledger_id = await ledger.fetch_value("SELECT current_database()")
    if content_id == ledger_id:
        raise ValueError("the deletion ledger must use a separate database")
    await apply_idempotency_migrations(db)
    await apply_idempotency_migrations(ledger)
    await apply_outbox_migrations(db)
    for manager, directory, module in (
        (db, "migrations", "aweb_naapp_pages"),
        (ledger, "ledger_migrations", "aweb_naapp_page_deletions"),
    ):
        await AsyncMigrationManager(
            manager, migrations_path=str(ROOT / directory), module_name=module
        ).apply_pending_migrations()


class PageStore(LifecycleMixin):
    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        ledger: AsyncDatabaseManager,
        retention: RetentionPolicy | None,
        lifecycle=None,
        lifecycle_authorizer=None,
        record_validator=None,
    ):
        self.db, self.ledger, self.retention = db, ledger, retention
        self.lifecycle = lifecycle
        self.lifecycle_authorizer = lifecycle_authorizer
        self.record_validator = record_validator
        self._ready = False

    async def start(self) -> None:
        """Reapply erasure fences before serving a restored content database."""
        self._ready = False
        await self.db.execute(
            "INSERT INTO {{tables.page_store_generation}} VALUES(TRUE,$1) ON CONFLICT(singleton) DO UPDATE SET generation=$1",
            uuid4(),
        )
        for row in await self.ledger.fetch_all(
            "SELECT scope, tombstone_rev FROM {{tables.page_deletions}}"
        ):
            await self._purge_content(Scope(*row["scope"]), row["tombstone_rev"])
        self._ready = True

    def _policy(self) -> RetentionPolicy:
        if self.retention is None:
            raise StoreError("retention_policy_required", 503)
        return self.retention

    async def _fence(self, scope: Scope) -> None:
        if not self._ready:
            raise StoreError("restore_not_ready", 503)
        if await self.ledger.fetch_value(
            "SELECT 1 FROM {{tables.page_deletions}} WHERE scope=$1", scope.key
        ):
            raise StoreError("resource_not_found", 404)

    async def _load(self, tx, scope: Scope, principal: Principal, operation="read"):
        actor = identity(principal, scope)
        return await self._load_actor(tx, scope, actor, operation)

    async def _load_actor(self, tx, scope, actor, operation="read", *, shared=False):
        await self._fence(scope)
        row = await tx.fetch_one(
            "SELECT document, access, deleted FROM {{tables.pages}} WHERE scope=$1 FOR "
            + ("SHARE" if shared else "UPDATE"),
            scope.key,
        )
        if row is None or row["deleted"]:
            raise StoreError("resource_not_found", 404)
        access = Access.from_dict(decoded(row["access"]))
        access.require_scope(scope)
        if not access.permits(actor, operation, team_id=scope.team_id):
            raise StoreError("resource_not_found", 404)
        return decoded(row["document"]), access, actor

    async def _records(self, tx, scope, collection):
        rows = await tx.fetch_all(
            "SELECT record FROM {{tables.page_records}} WHERE scope=$1 AND collection=$2 AND record IS NOT NULL ORDER BY record_id",
            scope.key,
            collection,
        )
        return [decoded(row["record"]) for row in rows]

    async def _claim(
        self, tx, scope, principal, key, request, *, retention=None, request_actor=None
    ):
        if not isinstance(key, str) or not key or len(key) > 256:
            raise StoreError("precondition_required", 428)
        request_key = [
            scope.installation_id,
            scope.team_id,
            identity(principal, scope) if request_actor is None else request_actor,
            key,
        ]
        request_hash = hashlib.sha256(canonical({"scope": scope.key, **request}).encode()).digest()
        horizon = timedelta(days=(retention or self._policy()).retry_horizon_days)
        # Serialize this key until the content transaction commits. The metadata
        # lock also makes startup wait for in-flight transactions before advancing
        # generation, rather than misclassifying a committing request as lost.
        await tx.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,1))", canonical(request_key)
        )
        generation = await tx.fetch_value(
            "SELECT generation FROM {{tables.page_store_generation}} WHERE singleton FOR SHARE"
        )
        if generation is None:
            raise StoreError("restore_not_ready", 503)
        try:
            async with self.ledger.transaction() as ledger_tx:
                external = await claim(
                    ledger_tx,
                    key=request_key,
                    request_hash=request_hash,
                    receipt_ref=str(uuid4()),
                    retention=horizon,
                )
                if external.created:
                    await ledger_tx.execute(
                        "INSERT INTO {{tables.page_request_claims}} VALUES($1,$2,$3)",
                        request_key,
                        scope.key,
                        generation,
                    )
                    await ledger_tx.execute(
                        "UPDATE {{tables.idempotency_keys}} SET expires_at='infinity' WHERE key=$1",
                        request_key,
                    )
                claim_generation = await ledger_tx.fetch_value(
                    "SELECT content_generation FROM {{tables.page_request_claims}} WHERE key=$1",
                    request_key,
                )
            transaction = UUID(external.receipt_ref)
            receipt = await tx.fetch_value(
                "SELECT receipt FROM {{tables.page_receipts}} WHERE transaction_id=$1 AND scope=$2",
                transaction,
                scope.key,
            )
            if receipt is not None:
                return transaction, decoded(receipt)
            if claim_generation != generation:
                raise StoreError("request_lost_in_restore", 409)
            # Same-generation claims without a receipt never committed. Reuse
            # their original transaction ID, including after a worker rollback.
            local = await claim(
                tx,
                key=request_key,
                request_hash=request_hash,
                receipt_ref=str(transaction),
                retention=horizon,
            )
            if local.receipt_ref != str(transaction):
                raise StoreError("request_lost_in_restore", 409)
            if local.created:
                await tx.execute(
                    "UPDATE {{tables.idempotency_keys}} SET expires_at='infinity' WHERE key=$1",
                    request_key,
                )
            return transaction, None
        except (IdempotencyConflict, IdempotencyExpired) as error:
            raise StoreError(error.code, error.status) from error

    async def _commit(
        self,
        tx,
        scope,
        principal,
        transaction,
        document,
        old_rev,
        changed,
        record_revs=None,
        receipt_details=None,
        link_context=None,
    ):
        if link_context is not None:
            await link_context.revalidate(tx)
        if old_rev >= MAX_REV:
            raise StoreError("revision_exhausted", 409)
        document["rev"] = old_rev + 1
        receipt = {
            "transaction_id": str(transaction),
            "page_rev": document["rev"],
            "record_revs": record_revs or {},
            "audit_id": str(transaction),
            **(receipt_details or {}),
        }
        await tx.execute(
            "UPDATE {{tables.pages}} SET document=$2::jsonb,policy_version=$3,retention_policy=$4::jsonb WHERE scope=$1",
            scope.key,
            canonical(document),
            self._policy().version,
            canonical(self._policy().as_dict()),
        )
        evidence = (
            link_context.evidence()
            if link_context is not None
            else {
                "principal_id": identity(principal, scope),
                "signer_did": principal.did_key,
                "certificate_id": principal.certificate_id,
                "origin_kind": "member",
            }
        )
        await tx.execute(
            "INSERT INTO {{tables.page_audit}} (transaction_id,scope,old_rev,new_rev,evidence,changed) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb)",
            transaction,
            scope.key,
            old_rev,
            document["rev"],
            canonical(evidence),
            canonical(changed),
        )
        await tx.execute(
            "INSERT INTO {{tables.page_receipts}} VALUES($1,$2,$3::jsonb)",
            transaction,
            scope.key,
            canonical(receipt),
        )
        await enqueue(
            tx,
            OutboxEvent(
                event_id=transaction,
                team_id=scope.team_id,
                kind="aweb.page.changed",
                occurred_at=datetime.now(UTC),
                payload=canonical(
                    {
                        "installation_id": scope.installation_id,
                        "app_id": scope.app_id,
                        "page_id": scope.page_id,
                        "rev": document["rev"],
                        "deleted": False,
                    }
                ).encode(),
            ),
        )
        await self._fence(scope)
        return receipt

    async def create(self, scope, principal, document, *, access: Access, key: str):
        async with self.db.transaction() as tx:
            return await self._create(tx, scope, principal, document, access=access, key=key)

    async def create_on(self, tx, scope, principal, document, *, access, key):
        """Join page creation and app discovery metadata in the caller transaction."""
        _require_transaction(tx)
        async with tx.transaction() as creation_tx:
            return await self._create(
                creation_tx, scope, principal, document, access=access, key=key
            )

    async def _create(
        self, tx, scope, principal, document, *, access: Access, key: str, request_context=None
    ):
        self._policy()
        actor = identity(principal, scope)
        await self._fence(scope)
        access.require_scope(scope)
        if access.owner != actor:
            raise StoreError("action_denied", 403)
        document = copy.deepcopy(document)
        document["owner"] = access.owner
        if (
            document.get("page_id") != scope.page_id
            or document.get("rev") != 1
            or document.get("layout_version") != 1
        ):
            raise StoreError("schema_invalid")
        validated(document)
        # Serialize creations and their idempotency receipts, even before a page exists.
        await tx.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", canonical(scope.key)
        )
        existing = await tx.fetch_value(
            "SELECT access FROM {{tables.pages}} WHERE scope=$1", scope.key
        )
        if existing is not None and not Access.from_dict(decoded(existing)).permits(
            actor, "read", team_id=scope.team_id
        ):
            raise StoreError("resource_not_found", 404)
        transaction, replay = await self._claim(
            tx,
            scope,
            principal,
            key,
            {
                "op": "create",
                "document": document,
                "access": access.as_dict(),
                "context": request_context,
            },
        )
        if replay:
            return replay
        if existing is not None:
            raise StoreError("revision_conflict", 409)
        definitions = copy.deepcopy(document)
        for collection in definitions["collections"]:
            collection["records"] = []
        await tx.execute(
            "INSERT INTO {{tables.pages}} (scope,document,access,policy_version) VALUES($1,$2::jsonb,$3::jsonb,$4)",
            scope.key,
            canonical(definitions),
            canonical(access.as_dict()),
            self._policy().version,
        )
        for collection in document["collections"]:
            for record in collection["records"]:
                self._validate_record(scope, document, collection, record)
                await self._put_record(tx, scope, collection["id"], record)
            definition = {k: v for k, v in collection.items() if k != "records"}
            await tx.execute(
                "INSERT INTO {{tables.page_schemas}} VALUES($1,$2,$3,$4::jsonb)",
                scope.key,
                collection["id"],
                collection["schema_version"],
                canonical(definition),
            )
        await tx.execute(
            "INSERT INTO {{tables.page_layouts}} VALUES($1,1,$2::jsonb)",
            scope.key,
            canonical(document["layout"]),
        )
        await tx.execute(
            "INSERT INTO {{tables.page_layout_context}} VALUES($1,1,$2::jsonb)",
            scope.key,
            canonical(document),
        )
        return await self._commit(tx, scope, principal, transaction, definitions, 0, ["create"])

    async def _put_record(self, tx, scope, collection, record):
        await tx.execute(
            "INSERT INTO {{tables.page_records}} (scope,collection,record_id,rev,record) VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT(scope,collection,record_id) DO UPDATE SET rev=$4,record=$5::jsonb",
            scope.key,
            collection,
            record["id"],
            record["rev"],
            canonical(record),
        )

    async def mutate(self, scope, principal, *, expected_rev, key, records=(), state=None):
        return await self._mutate(
            scope,
            principal,
            expected_rev=expected_rev,
            key=key,
            records=records,
            state=state,
            sync=False,
        )

    async def add_record(self, scope, principal, *, collection, values, key, record_id=None):
        async with self.db.transaction() as tx:
            return await self.add_record_on(
                tx,
                scope,
                principal,
                collection=collection,
                values=values,
                key=key,
                record_id=record_id,
            )

    async def add_record_on(self, tx, scope, principal, *, collection, values, key, record_id=None):
        """Add on the caller's transaction, retaining its installation fence."""
        _require_transaction(tx)
        change = {
            "op": "create",
            "collection": collection,
            "id": record_id,
            "expected_rev": 0,
            "value": values,
        }
        return await self._record_write_on(
            tx,
            scope,
            principal,
            key=key,
            change=change,
            request={
                "op": "add_record",
                "collection": collection,
                "record_id": record_id,
                "values": values,
            },
        )

    async def patch_record(
        self, scope, principal, *, collection, record_id, expected_rev, patch, key
    ):
        async with self.db.transaction() as tx:
            return await self.patch_record_on(
                tx,
                scope,
                principal,
                collection=collection,
                record_id=record_id,
                expected_rev=expected_rev,
                patch=patch,
                key=key,
            )

    async def patch_record_on(
        self, tx, scope, principal, *, collection, record_id, expected_rev, patch, key
    ):
        """Patch on the caller's transaction; a refusal rolls back its savepoint."""
        _require_transaction(tx)
        change = {
            "op": "patch",
            "collection": collection,
            "id": record_id,
            "expected_rev": expected_rev,
            "patch": patch,
        }
        return await self._record_write_on(
            tx,
            scope,
            principal,
            key=key,
            change=change,
            request={
                "op": "patch_record",
                "collection": collection,
                "record_id": record_id,
                "expected_rev": expected_rev,
                "patch": patch,
            },
        )

    async def delete_record(self, scope, principal, *, collection, record_id, expected_rev, key):
        async with self.db.transaction() as tx:
            return await self.delete_record_on(
                tx,
                scope,
                principal,
                collection=collection,
                record_id=record_id,
                expected_rev=expected_rev,
                key=key,
            )

    async def delete_record_on(
        self, tx, scope, principal, *, collection, record_id, expected_rev, key
    ):
        """Tombstone on the caller's transaction without committing it."""
        _require_transaction(tx)
        change = {
            "op": "delete",
            "collection": collection,
            "id": record_id,
            "expected_rev": expected_rev,
        }
        return await self._record_write_on(
            tx,
            scope,
            principal,
            key=key,
            change=change,
            request={
                "op": "delete_record",
                "collection": collection,
                "record_id": record_id,
                "expected_rev": expected_rev,
            },
        )

    async def write_link_record_on(
        self,
        tx,
        scope,
        context: LinkRecordContext,
        *,
        operation,
        collection,
        key,
        record_id=None,
        expected_rev=None,
        values=None,
        patch=None,
    ):
        """Join a checked session to the same member row engine and savepoint.

        The host holds installation/session/document locks and supplies current
        evidence in ``context``. No member Principal is manufactured for a holder.
        """
        _require_transaction(tx)
        if not isinstance(context, LinkRecordContext):
            raise TypeError("a checked LinkRecordContext is required")
        context.require(
            scope,
            operation=operation,
            collection=collection,
            values=values if operation == "add" else patch,
        )
        if operation == "add":
            if expected_rev is not None or patch is not None:
                raise StoreError("schema_invalid")
            change = {
                "op": "create",
                "collection": collection,
                "id": record_id,
                "expected_rev": 0,
                "value": values,
            }
            request = {
                "op": "add_record",
                "collection": collection,
                "record_id": record_id,
                "values": values,
            }
        elif operation == "patch":
            if values is not None:
                raise StoreError("schema_invalid")
            change = {
                "op": "patch",
                "collection": collection,
                "id": record_id,
                "expected_rev": expected_rev,
                "patch": patch,
            }
            request = {
                "op": "patch_record",
                "collection": collection,
                "record_id": record_id,
                "expected_rev": expected_rev,
                "patch": patch,
            }
        else:  # require() has admitted only a declared delete operation here.
            if values is not None or patch is not None:
                raise StoreError("schema_invalid")
            change = {
                "op": "delete",
                "collection": collection,
                "id": record_id,
                "expected_rev": expected_rev,
            }
            request = {
                "op": "delete_record",
                "collection": collection,
                "record_id": record_id,
                "expected_rev": expected_rev,
            }
        return await self._record_write_on(
            tx,
            scope,
            None,
            key=key,
            change=change,
            request=request,
            link_context=context,
        )

    async def _record_write_on(
        self, tx, scope, principal, *, key, change, request, link_context=None
    ):
        if (
            not isinstance(change["collection"], str)
            or not change["collection"]
            or (change["id"] is None and request["op"] != "add_record")
            or (
                change["id"] is not None and (not isinstance(change["id"], str) or not change["id"])
            )
        ):
            raise StoreError("schema_invalid")
        async with tx.transaction() as tx:
            # Keep the current revision under the same lock, but never put this
            # derived revision in the original row request's retry identity.
            if link_context is None:
                document, _, _ = await self._load(tx, scope, principal, "write")
            else:
                document, _, _ = await self._load_actor(tx, scope, link_context.creator_id, "write")
            return await self._mutate_on(
                tx,
                scope,
                principal,
                expected_rev=document["rev"],
                key=key,
                records=[change],
                state=None,
                sync=False,
                request=request,
                link_context=link_context,
            )

    async def sync(self, scope, principal, *, expected_rev, key, records):
        # Sync admission is an owner operation. Apps must also authenticate the source adapter.
        return await self._mutate(
            scope,
            principal,
            expected_rev=expected_rev,
            key=key,
            records=records,
            state=None,
            sync=True,
        )

    @staticmethod
    def _precondition(document, expected_rev):
        if expected_rev is None:
            raise StoreError("precondition_required", 428)
        if type(expected_rev) is not int or expected_rev != document["rev"]:
            raise StoreError("revision_conflict", 409, details={"page_rev": document["rev"]})

    async def mutate_on(self, tx, scope, principal, *, expected_rev, key, records=(), state=None):
        """Apply an owned mutation on the caller's content-database transaction.

        The caller owns commit/rollback and can atomically join action state or
        task-mirror outbox writes. All ordinary page/record/field guards and the
        independent restore-safe request claim apply. Use a transaction from
        this store's database; this method never opens or commits a content
        transaction of its own. A savepoint rolls back all page effects on
        refusal even if the caller catches the error and records a failure.
        """
        _require_transaction(tx)
        async with tx.transaction() as mutation_tx:
            return await self._mutate_on(
                mutation_tx,
                scope,
                principal,
                expected_rev=expected_rev,
                key=key,
                records=records,
                state=state,
                sync=False,
            )

    async def _mutate(self, scope, principal, *, expected_rev, key, records, state, sync):
        self._policy()
        async with self.db.transaction() as tx:
            return await self._mutate_on(
                tx,
                scope,
                principal,
                expected_rev=expected_rev,
                key=key,
                records=records,
                state=state,
                sync=sync,
            )

    async def _mutate_on(
        self,
        tx,
        scope,
        principal,
        *,
        expected_rev,
        key,
        records,
        state,
        sync,
        request=None,
        link_context=None,
    ):
        self._policy()
        if link_context is None:
            document, access, actor = await self._load(
                tx, scope, principal, "owner" if sync else "write"
            )
        else:
            document, access, actor = await self._load_actor(
                tx, scope, link_context.creator_id, "write"
            )
            await link_context.revalidate(tx)
        transaction, replay = await self._claim(
            tx,
            scope,
            principal,
            key,
            request
            if request is not None
            else {
                "op": "sync" if sync else "mutate",
                "expected_rev": expected_rev,
                "records": records,
                "state": state,
            },
            request_actor=link_context.request_actor(request["op"])
            if link_context is not None
            else None,
        )
        if link_context is not None:
            await link_context.revalidate(tx)
        row_request = request is not None
        if replay:
            if row_request:
                definition = next(
                    (c for c in document["collections"] if c["id"] == request["collection"]), None
                )
                if definition is None:
                    raise StoreError("action_denied", 403)
                original = replay.get("record", {}).get("value", {})
                if not access.visible_row(actor, definition["id"], replay["record_id"]) or set(
                    original
                ) - (
                    access.value_fields(actor, definition, original)
                    & (link_context.fields if link_context is not None else set(original))
                ):
                    raise StoreError("action_denied", 403)
            return replay
        self._precondition(document, expected_rev)
        receipt_details = None
        revisions, changed, seen = {}, [], set()
        collections = {c["id"]: c for c in document["collections"]}
        for change in records:
            if not isinstance(change, dict) or set(change) - {
                "op",
                "collection",
                "id",
                "expected_rev",
                "value",
                "source",
                "patch",
            }:
                raise StoreError("schema_invalid")
            cid, rid = change.get("collection"), change.get("id")
            if row_request and request["op"] == "add_record" and rid is None:
                rid = "rec_" + uuid4().hex
            if (cid, rid) in seen:
                raise StoreError("schema_invalid")
            seen.add((cid, rid))
            collection = collections.get(cid)
            if collection is None or not access.visible_row(actor, cid, rid):
                raise StoreError("action_denied", 403)
            if (collection["mode"] == "synced") != sync:
                raise StoreError("synced_write_denied", 403)
            row = await tx.fetch_one(
                "SELECT rev,record FROM {{tables.page_records}} WHERE scope=$1 AND collection=$2 AND record_id=$3",
                scope.key,
                cid,
                rid,
            )
            operation = change.get("op")
            expected = change.get("expected_rev")
            if expected is None:
                raise StoreError("precondition_required", 428)
            if operation not in {"create", "update", "patch", "delete"}:
                raise StoreError("schema_invalid")
            if type(expected) is not int or (
                (operation == "create" and (row is not None or expected != 0))
                or (
                    operation != "create"
                    and (row is None or row["record"] is None or row["rev"] != expected)
                )
            ):
                raise StoreError("revision_conflict", 409)
            rev = 1 if row is None else row["rev"] + 1
            if rev > MAX_REV:
                raise StoreError("revision_exhausted", 409)
            previous = decoded(row["record"])["value"] if row and row["record"] else {}
            if operation == "patch":
                proposed = change.get("patch")
                if not isinstance(proposed, dict) or not proposed or "value" in change or sync:
                    raise StoreError("schema_invalid")
                allowed = access.value_fields(actor, collection, proposed)
                if link_context is not None:
                    allowed &= link_context.fields
            else:
                proposed = change.get("value") if isinstance(change.get("value"), dict) else {}
                allowed = access.value_fields(actor, collection, set(previous) | set(proposed))
                if link_context is not None:
                    allowed &= link_context.fields
                if row and set(previous) - allowed:
                    raise StoreError("action_denied", 403)
            if operation == "delete":
                await tx.execute(
                    "UPDATE {{tables.page_records}} SET rev=$4,record=NULL WHERE scope=$1 AND collection=$2 AND record_id=$3",
                    scope.key,
                    cid,
                    rid,
                    rev,
                )
            else:
                supplied = proposed if operation == "patch" else change.get("value")
                if not isinstance(supplied, dict) or set(supplied) - allowed:
                    raise StoreError("action_denied", 403)
                value = (
                    {**previous, **copy.deepcopy(supplied)} if operation == "patch" else supplied
                )
                record = {"id": rid, "rev": rev, "value": value}
                if sync:
                    record["source"] = change.get("source")
                elif "source" in change:
                    raise StoreError("schema_invalid")
                self._validate_record(scope, document, collection, record)
                await self._put_record(tx, scope, cid, record)
            if row_request:
                receipt_details = {"record_id": rid, "rev": rev}
                if operation == "delete":
                    receipt_details["deleted"] = True
                else:
                    visible = access.value_fields(actor, collection, value)
                    if link_context is not None:
                        visible &= link_context.fields
                    receipt_details["record"] = {
                        "id": rid,
                        "rev": rev,
                        "value": {k: copy.deepcopy(v) for k, v in value.items() if k in visible},
                    }
            revisions[f"{cid}/{rid}"] = rev
            changed.append(
                {
                    "collection": cid,
                    "record_id": rid,
                    "fields": sorted(proposed),
                    "operation": operation,
                }
            )
        if state is not None:
            if not isinstance(state, dict):
                raise StoreError("schema_invalid", details=[{"pointer": "/widget_state"}])
            document["widget_state"].update(copy.deepcopy(state))
            changed.append({"widget_state": sorted(state)})
        await self._project(tx, scope, copy.deepcopy(document), access, access.owner)
        return await self._commit(
            tx,
            scope,
            principal,
            transaction,
            document,
            expected_rev,
            changed,
            revisions,
            receipt_details=receipt_details,
            link_context=link_context,
        )

    def _validate_record(self, scope, document, collection, record):
        probe = {
            **document,
            "layout": [],
            "actions": [],
            "widget_state": {},
            "collections": [{**collection, "records": [record]}],
        }
        validated(probe)
        if self.record_validator is not None:
            self.record_validator(scope, copy.deepcopy(collection), copy.deepcopy(record))

    async def append_layout(
        self, scope, principal, *, expected_rev, key, layout, title=None, locale=None
    ):
        self._policy()
        async with self.db.transaction() as tx:
            document, access, actor = await self._load(tx, scope, principal, "owner")
            transaction, replay = await self._claim(
                tx,
                scope,
                principal,
                key,
                {
                    "op": "layout",
                    "expected_rev": expected_rev,
                    "layout": layout,
                    "title": title,
                    "locale": locale,
                },
            )
            if replay:
                return replay
            self._precondition(document, expected_rev)
            candidate = {**document, "layout": layout, "widget_state": {}}
            for collection in candidate["collections"]:
                collection["records"] = (await self._records(tx, scope, collection["id"]))[:200]
            validated(candidate)
            document["layout"] = copy.deepcopy(layout)
            for collection in document["collections"]:
                collection["records"] = []
            document["layout_version"] += 1
            ids = {w["id"] for w in widgets(layout)}
            document["widget_state"] = {
                wid: state for wid, state in document["widget_state"].items() if wid in ids
            }
            if title is not None:
                document["title"] = title
            if locale is not None:
                document["locale"] = locale
            await self._project(tx, scope, copy.deepcopy(document), access, actor)
            identities = {}
            for row in await tx.fetch_all(
                "SELECT layout FROM {{tables.page_layouts}} WHERE scope=$1", scope.key
            ):
                identities.update({w["id"]: w["type"] for w in widgets(decoded(row["layout"]))})
            for widget in widgets(layout):
                if widget["id"] in identities and identities[widget["id"]] != widget["type"]:
                    raise StoreError("widget_identity_changed", 409)
            context = await self._project(tx, scope, copy.deepcopy(document), access, access.owner)
            context["rev"] = expected_rev + 1
            await tx.execute(
                "INSERT INTO {{tables.page_layout_context}} VALUES($1,$2,$3::jsonb)",
                scope.key,
                document["layout_version"],
                canonical(context),
            )
            await tx.execute(
                "INSERT INTO {{tables.page_layouts}} VALUES($1,$2,$3::jsonb)",
                scope.key,
                document["layout_version"],
                canonical(layout),
            )
            return await self._commit(
                tx, scope, principal, transaction, document, expected_rev, ["layout"]
            )

    async def change_access(self, scope, principal, *, expected_rev, key, access):
        self._policy()
        access.require_scope(scope)
        async with self.db.transaction() as tx:
            document, _, _ = await self._load(tx, scope, principal, "owner")
            transaction, replay = await self._claim(
                tx,
                scope,
                principal,
                key,
                {"op": "access", "expected_rev": expected_rev, "access": access.as_dict()},
            )
            if replay:
                return replay
            self._precondition(document, expected_rev)
            document["owner"] = access.owner
            await tx.execute(
                "UPDATE {{tables.pages}} SET access=$2::jsonb WHERE scope=$1",
                scope.key,
                canonical(access.as_dict()),
            )
            return await self._commit(
                tx, scope, principal, transaction, document, expected_rev, ["access"]
            )

    async def migrate_schema(
        self, scope, principal, *, expected_rev, key, collection, schema, values
    ):
        self._policy()
        async with self.db.transaction() as tx:
            document, _, _ = await self._load(tx, scope, principal, "owner")
            transaction, replay = await self._claim(
                tx,
                scope,
                principal,
                key,
                {
                    "op": "schema",
                    "expected_rev": expected_rev,
                    "collection": collection,
                    "schema": schema,
                    "values": values,
                },
            )
            if replay:
                return replay
            self._precondition(document, expected_rev)
            definition = next((c for c in document["collections"] if c["id"] == collection), None)
            if definition is None:
                raise StoreError("schema_invalid")
            definition["schema_version"] += 1
            definition["schema"] = copy.deepcopy(schema)
            validated({**document, "layout": [], "widget_state": {}, "actions": []})
            revisions = {}
            records = await self._records(tx, scope, collection)
            if set(values) - {r["id"] for r in records}:
                raise StoreError("schema_invalid")
            for record in records:
                if record["id"] in values:
                    record["value"] = values[record["id"]]
                    record["rev"] += 1
                    revisions[f"{collection}/{record['id']}"] = record["rev"]
                self._validate_record(scope, document, definition, record)
                await self._put_record(tx, scope, collection, record)
            await tx.execute(
                "INSERT INTO {{tables.page_schemas}} VALUES($1,$2,$3,$4::jsonb)",
                scope.key,
                collection,
                definition["schema_version"],
                canonical({k: v for k, v in definition.items() if k != "records"}),
            )
            await self._project(
                tx,
                scope,
                copy.deepcopy(document),
                Access(owner=identity(principal, scope)),
                identity(principal, scope),
            )
            return await self._commit(
                tx,
                scope,
                principal,
                transaction,
                document,
                expected_rev,
                [{"schema": collection}],
                revisions,
            )

    async def _project(self, tx, scope, document, access, actor):
        definitions = {c["id"]: c for c in document["collections"]}
        gathered = {cid: {} for cid in definitions}
        for widget in widgets(document["layout"]):
            if widget["type"] != "decision_card":
                continue
            props = widget["props"]
            cid, rid = props["collection"], props["record_id"]
            record = await tx.fetch_value(
                "SELECT record FROM {{tables.page_records}} WHERE scope=$1 AND collection=$2 AND record_id=$3",
                scope.key,
                cid,
                rid,
            )
            if record is not None:
                record = decoded(record)
                gathered[cid][rid] = record
                if props.get("bundle"):
                    for item in record["value"].get("items", []):
                        value = await tx.fetch_value(
                            "SELECT record FROM {{tables.page_records}} WHERE scope=$1 AND collection=$2 AND record_id=$3",
                            scope.key,
                            props["items_collection"],
                            item["record_id"],
                        )
                        if value is not None:
                            gathered[props["items_collection"]][item["record_id"]] = decoded(value)
        for collection in document["collections"]:
            collection["records"] = list(gathered[collection["id"]].values())
        return self._redact_snapshot(document, access, actor, team_id=scope.team_id)

    def _redact_snapshot(
        self,
        document,
        access,
        actor,
        *,
        keep_records=False,
        allowed_action_ids=None,
        allowed_asset_ids=(),
        team_id=None,
    ):
        definitions = {c["id"]: c for c in document["collections"]}
        records = {cid: {r["id"]: r for r in c["records"]} for cid, c in definitions.items()}
        required = {cid: {} for cid in definitions}
        if allowed_action_ids is not None:
            document["actions"] = [
                action
                for action in document["actions"]
                if action["id"] in allowed_action_ids
                and action["kind"] in {"edit", "intent"}
                and (action["kind"] != "edit" or access.permits(actor, "write", team_id=team_id))
            ]
            allowed_action_ids = {a["id"] for a in document["actions"]}
        removed_state = set()
        for widget in widgets(document["layout"]):
            denied = False
            if allowed_action_ids is not None:
                kind, props = widget["type"], widget.get("props", {})
                denied = kind not in KNOWN_WIDGET_TYPES or kind == "decision_card"
                if not denied:
                    if kind in {"image", "video"}:
                        denied = props["asset_id"] not in allowed_asset_ids
                    for name in ("action", "submit_action", "answer_action"):
                        if name in props and props[name] not in allowed_action_ids:
                            denied = True
                    for name in ("row_actions", "actions"):
                        if name in props:
                            props[name] = [a for a in props[name] if a in allowed_action_ids]
                    if widget.get("bind"):
                        # Cursor tokens belong to a live actor/query, never a pinned page.
                        widget["bind"].pop("cursor", None)
            if widget["type"] == "decision_card" and not denied:
                props = widget["props"]
                cid, rid = props["collection"], props["record_id"]
                record = records[cid].get(rid)
                needed = [(cid, record)] if record else []
                if record and props.get("bundle"):
                    needed += [
                        (
                            props["items_collection"],
                            records[props["items_collection"]][item["record_id"]],
                        )
                        for item in record["value"].get("items", [])
                        if item["record_id"] in records[props["items_collection"]]
                    ]
                denied = any(
                    not access.visible_row(actor, cid, row["id"])
                    or set(row["value"])
                    - access.value_fields(actor, definitions[cid], row["value"])
                    for cid, row in needed
                )
                if not denied:
                    for cid, row in needed:
                        required[cid][row["id"]] = row
            binding = widget.get("bind")
            if binding:
                denied = (
                    denied
                    or binding["collection"] not in definitions
                    or bool(
                        self._binding_fields(widget)
                        - access.visible_fields(actor, definitions[binding["collection"]])
                    )
                )
            if denied:
                wid = widget["id"]
                removed_state.add(wid)
                removed_state.update(w["id"] for w in widgets(widget.get("children", [])))
                widget.clear()
                widget.update(id=wid, type="access_unavailable", fallback="Unavailable", props={})
        for collection in document["collections"]:
            collection["records"] = [
                {
                    **r,
                    "value": {
                        k: v
                        for k, v in r["value"].items()
                        if k in access.value_fields(actor, collection, r["value"])
                    },
                }
                for r in (
                    collection["records"] if keep_records else required[collection["id"]].values()
                )
                if access.visible_row(actor, collection["id"], r["id"])
            ]
            collection["schema"] = access.redact_schema(actor, collection)
        for wid in removed_state:
            document["widget_state"].pop(wid, None)
        validated(document)
        return document

    @staticmethod
    def _binding_fields(widget):
        props, bind = widget.get("props", {}), widget.get("bind", {})
        fields = {f["field"] for f in bind.get("all", []) + bind.get("sort", [])}
        fields.update(c["field"] for c in props.get("columns", []))
        fields.update(props.get("fields", {}).values())
        if "field" in props:
            fields.add(props["field"])
        if "x" in props:
            fields.add(props["x"])
        fields.update(props.get("series", []))
        return fields

    async def read(self, scope, principal):
        async with self.db.transaction() as tx:
            document, access, actor = await self._load(tx, scope, principal)
            result = await self._project(tx, scope, document, access, actor)
            await self._fence(scope)
            return result

    @staticmethod
    def _record_access_args(scope, definition, access, actor, *, fields=None, record_ids=None):
        allowed = (
            access.visible_fields(actor, definition)
            if fields is None
            else access.value_fields(actor, definition, fields) & fields
        )
        return [
            scope.key,
            definition["id"],
            sorted(access.hidden_rows.get(actor, {}).get(definition["id"], set()))
            if actor != access.owner
            else [],
            sorted(allowed),
            fields is None and access.all_value_fields(actor, definition),
            record_ids,
        ]

    @staticmethod
    def _projection_entries(projection, *, allow_live=False):
        if not isinstance(projection, Mapping) or set(projection) - {"collections", "assets"}:
            raise StoreError("schema_invalid")
        entries = projection.get("collections")
        if not isinstance(entries, (list, tuple)) or len(entries) > 16:
            raise StoreError("schema_invalid")
        seen = set()
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {
                "collection",
                "record_ids",
                "fields",
            }:
                raise StoreError("schema_invalid")
            cid = entry["collection"]
            if not isinstance(cid, str) or not cid or cid in seen:
                raise StoreError("schema_invalid")
            seen.add(cid)
            for name, maximum in (("record_ids", 200), ("fields", 64)):
                values = entry[name]
                if name == "record_ids" and allow_live and values == "*":
                    continue
                minimum = 0 if name == "record_ids" else 1
                _projection_names(values, minimum=minimum, maximum=maximum)
        return entries

    async def collection_access_on(
        self, tx, scope, *, creator_id, collection, link_mode, record_ids="*"
    ):
        """Current collection authority after the host checks its creator proof.

        Live wildcard authority needs no record query. Named/pinned checks are
        bounded and share the same row/field/schema policy as data projections.
        """
        _require_transaction(tx)
        if (
            not isinstance(creator_id, str)
            or not creator_id
            or not isinstance(collection, str)
            or not collection
            or link_mode not in ("live", "pinned")
        ):
            raise StoreError("schema_invalid")
        if record_ids != "*":
            _projection_names(record_ids, minimum=0, maximum=200)
        document, access, actor = await self._load_actor(tx, scope, creator_id, shared=True)
        definition = next((c for c in document["collections"] if c["id"] == collection), None)
        if definition is None:
            return None
        fields = access.visible_fields(actor, definition)
        if not fields:
            return None
        selected = None
        if link_mode == "pinned" or record_ids != "*":
            args = self._record_access_args(
                scope,
                definition,
                access,
                actor,
                fields=fields,
                record_ids=None if record_ids == "*" else list(record_ids),
            )
            rows = await tx.fetch_all(
                AUTHORIZED_RECORDS + "SELECT record->>'id' AS id FROM authorized LIMIT 201", *args
            )
            if len(rows) > 200:
                raise StoreError("action_denied", 403)
            selected = sorted(row["id"] for row in rows)
        await self._fence(scope)
        return {
            "page_rev": document["rev"],
            "id": definition["id"],
            "mode": definition["mode"],
            "schema_version": definition["schema_version"],
            "schema": access.redact_schema(actor, definition),
            "fields": sorted(fields),
            "record_ids": selected,
        }

    @staticmethod
    def _snapshot_collections(source):
        if (
            not isinstance(source, Mapping)
            or set(source) != {"page_rev", "collections"}
            or type(source["page_rev"]) is not int
            or not 1 <= source["page_rev"] <= MAX_REV
            or not isinstance(source["collections"], (list, tuple))
            or len(source["collections"]) > 16
        ):
            raise StoreError("schema_invalid")
        result = {}
        for collection in source["collections"]:
            if (
                not isinstance(collection, Mapping)
                or set(collection) != {"id", "schema_version", "schema", "records"}
                or not isinstance(collection["id"], str)
                or not collection["id"]
                or collection["id"] in result
                or type(collection["schema_version"]) is not int
                or collection["schema_version"] < 1
                or not isinstance(collection["schema"], dict)
                or inline_schema_errors(collection["schema"])
                or not isinstance(collection["records"], (list, tuple))
                or len(collection["records"]) > 200
            ):
                raise StoreError("schema_invalid")
            seen = set()
            for record in collection["records"]:
                if (
                    not isinstance(record, Mapping)
                    or set(record) != {"id", "rev", "value"}
                    or not isinstance(record["id"], str)
                    or not record["id"]
                    or record["id"] in seen
                    or type(record["rev"]) is not int
                    or not 1 <= record["rev"] <= MAX_REV
                    or not isinstance(record["value"], dict)
                    or not inline_value_valid(collection["schema"], record["value"])
                ):
                    raise StoreError("schema_invalid")
                seen.add(record["id"])
            result[collection["id"]] = collection
        return result

    async def read_projection_on(
        self, tx, scope, *, creator_id, projection, expected_page_rev=None, source_snapshot=None
    ):
        """Project checked link data under the caller's transaction/link lock.

        creator_id is the verified creator's ACL identity, never the anonymous
        holder. The host binds scope and any immutable source to the checked
        link. Pinned hosts must require a stored source; None reads live data.
        """
        _require_transaction(tx)
        entries = self._projection_entries(projection)
        if not isinstance(creator_id, str) or not creator_id:
            raise StoreError("schema_invalid")
        document, access, actor = await self._load_actor(tx, scope, creator_id, shared=True)
        current = {c["id"]: c for c in document["collections"]}
        source = None if source_snapshot is None else self._snapshot_collections(source_snapshot)
        revision = document["rev"] if source is None else source_snapshot["page_rev"]
        if expected_page_rev is not None:
            self._precondition({"rev": revision}, expected_page_rev)
        selected = []
        for entry in entries:
            cid = entry["collection"]
            if cid not in current or (source is not None and cid not in source):
                raise StoreError("action_denied", 403)
            definition = current[cid] if source is None else source[cid]
            args = self._record_access_args(
                scope,
                current[cid],
                access,
                actor,
                fields=set(entry["fields"]),
                record_ids=list(entry["record_ids"]),
            )
            if source is None:
                records = [
                    decoded(row["record"])
                    for row in await tx.fetch_all(
                        AUTHORIZED_RECORDS + "SELECT record FROM authorized ORDER BY record->>'id'",
                        *args,
                    )
                ]
            else:
                records = definition["records"]
            fields, hidden, ids = set(args[3]), set(args[2]), set(args[5])
            selected.append(
                {
                    "id": cid,
                    "schema_version": definition["schema_version"],
                    "schema": access.redact_schema(actor, definition, fields=fields),
                    "records": [
                        {
                            "id": r["id"],
                            "rev": r["rev"],
                            "value": {
                                k: copy.deepcopy(v) for k, v in r["value"].items() if k in fields
                            },
                        }
                        for r in sorted(records, key=lambda r: r["id"])
                        if r["id"] in ids and r["id"] not in hidden
                    ],
                }
            )
        await self._fence(scope)
        return {"page_rev": revision, "collections": selected}

    async def capture_link_snapshot_on(
        self,
        tx,
        scope,
        *,
        creator_id,
        projection,
        allowed_action_ids,
        expected_page_rev,
    ):
        """Capture one complete bounded page while the caller holds its mint lock."""
        return await self._link_snapshot_on(
            tx,
            scope,
            creator_id=creator_id,
            projection=projection,
            allowed_action_ids=allowed_action_ids,
            expected_page_rev=expected_page_rev,
        )

    async def project_link_snapshot_on(
        self,
        tx,
        scope,
        *,
        creator_id,
        projection,
        allowed_action_ids,
        source_snapshot,
        expected_page_rev=None,
    ):
        """Narrow a pinned page under current authority, never filling it from live data."""
        _require_transaction(tx)
        if not isinstance(source_snapshot, dict):
            raise StoreError("schema_invalid")
        validated(source_snapshot)
        if source_snapshot["page_id"] != scope.page_id:
            raise StoreError("schema_invalid")
        return await self._link_snapshot_on(
            tx,
            scope,
            creator_id=creator_id,
            projection=projection,
            allowed_action_ids=allowed_action_ids,
            expected_page_rev=expected_page_rev,
            source_snapshot=source_snapshot,
        )

    async def _link_snapshot_on(
        self,
        tx,
        scope,
        *,
        creator_id,
        projection,
        allowed_action_ids,
        expected_page_rev=None,
        source_snapshot=None,
    ):
        _require_transaction(tx)
        self._projection_entries(projection)
        assets = projection.get("assets", [])
        for values, maximum in ((allowed_action_ids, 16), (assets, 64)):
            if (
                not isinstance(values, (list, tuple))
                or len(values) > maximum
                or any(not isinstance(v, str) or not v for v in values)
                or len(set(values)) != len(values)
            ):
                raise StoreError("schema_invalid")
        if not isinstance(creator_id, str) or not creator_id:
            raise StoreError("schema_invalid")
        current, access, actor = await self._load_actor(tx, scope, creator_id, shared=True)
        if source_snapshot is None:
            self._precondition(current, expected_page_rev)
        document = copy.deepcopy(current if source_snapshot is None else source_snapshot)
        # A pinned page's metadata, action definitions and values always come from
        # the source. The current document supplies authority/field bounds only.
        data_source = (
            None
            if source_snapshot is None
            else {
                "page_rev": document["rev"],
                "collections": [
                    {key: c[key] for key in ("id", "schema_version", "schema", "records")}
                    for c in document["collections"]
                ],
            }
        )
        projected = await self.read_projection_on(
            tx,
            scope,
            creator_id=creator_id,
            projection=projection,
            expected_page_rev=expected_page_rev,
            source_snapshot=data_source,
        )
        original = {c["id"]: c for c in document["collections"]}
        document["collections"] = [{**original[c["id"]], **c} for c in projected["collections"]]
        # Use the ordinary widget/field/schema redactor, retaining the bounded
        # records rather than only mandatory decision-card bootstrap records.
        result = self._redact_snapshot(
            document,
            access,
            actor,
            keep_records=True,
            allowed_action_ids=set(allowed_action_ids),
            allowed_asset_ids=set(assets),
            team_id=scope.team_id,
        )
        await self._fence(scope)
        return result

    async def read_widget(self, scope, principal, *, widget_id, expected_page_rev, bind):
        async with self.db.transaction() as tx:
            document, access, actor = await self._load(tx, scope, principal)
            return await self._query_widget_on(
                tx,
                scope,
                document,
                access,
                actor,
                widget_id=widget_id,
                expected_page_rev=expected_page_rev,
                bind=bind,
            )

    async def query_widget(self, scope, principal, *, widget_id, bind, expected_page_rev=None):
        """Query a stored widget at the current revision, or a requested revision."""
        async with self.db.transaction() as tx:
            return await self.query_member_widget_on(
                tx,
                scope,
                principal,
                widget_id=widget_id,
                bind=bind,
                expected_page_rev=expected_page_rev,
            )

    async def query_member_widget_on(
        self, tx, scope, principal, *, widget_id, bind, expected_page_rev=None
    ):
        """Query as an admitted member while retaining the caller's fence/locks."""
        _require_transaction(tx)
        document, access, actor = await self._load(tx, scope, principal)
        return await self._query_widget_on(
            tx,
            scope,
            document,
            access,
            actor,
            widget_id=widget_id,
            expected_page_rev=expected_page_rev,
            bind=bind,
            allow_current=True,
        )

    async def query_widget_on(
        self,
        tx,
        scope,
        *,
        creator_id,
        widget_id,
        bind,
        link_id,
        expected_page_rev=None,
        projection=None,
    ):
        """Read a checked live link while its caller holds the link/session lock.

        creator_id, link_id and projection come from checked current link context,
        never request JSON. The host rechecks membership/lifecycle on every page.
        """
        _require_transaction(tx)
        if (
            not isinstance(creator_id, str)
            or not creator_id
            or not isinstance(link_id, str)
            or not link_id
            or projection is None
        ):
            raise StoreError("schema_invalid")
        self._projection_entries(projection, allow_live=True)
        document, access, actor = await self._load_actor(tx, scope, creator_id, shared=True)
        return await self._query_widget_on(
            tx,
            scope,
            document,
            access,
            actor,
            widget_id=widget_id,
            expected_page_rev=expected_page_rev,
            bind=bind,
            allow_current=True,
            projection=projection,
            link_id=link_id,
        )

    async def _query_widget_on(
        self,
        tx,
        scope,
        document,
        access,
        actor,
        *,
        widget_id,
        expected_page_rev,
        bind,
        allow_current=False,
        projection=None,
        link_id=None,
    ):
        if allow_current and expected_page_rev is None:
            expected_page_rev = document["rev"]
        self._precondition(document, expected_page_rev)
        if not isinstance(bind, dict):
            raise StoreError("schema_invalid", details=[{"pointer": "/bind"}])
        widget = next((w for w in widgets(document["layout"]) if w["id"] == widget_id), None)
        if (
            widget is None
            or not widget.get("bind")
            or bind.get("collection") != widget["bind"]["collection"]
        ):
            raise StoreError("query_denied", 403)
        definition = next(c for c in document["collections"] if c["id"] == bind["collection"])
        fields = access.visible_fields(actor, definition)
        record_ids = None
        if projection is not None:
            entries = self._projection_entries(projection, allow_live=True)
            selected = next((e for e in entries if e["collection"] == definition["id"]), None)
            if selected is None:
                raise StoreError("action_denied", 403)
            fields &= set(selected["fields"])
            record_ids = None if selected["record_ids"] == "*" else list(selected["record_ids"])
        probe = copy.deepcopy(document)
        probe["layout"] = [
            {
                "id": widget_id,
                "type": "table",
                "props": {
                    "columns": [{"field": f, "label": f, "format": "text"} for f in sorted(fields)]
                },
                "bind": bind,
            }
        ]
        probe["widget_state"] = {}
        validated(probe)
        if {f.get("field") for f in bind.get("all", []) + bind.get("sort", [])} - fields:
            raise StoreError("query_denied", 403)
        for predicate in bind.get("all", []):
            field_schema = definition["schema"]["properties"][predicate["field"]]
            values = (
                predicate.get("value", [])
                if predicate.get("op") == "in"
                else [predicate.get("value")]
            )
            if not isinstance(values, list) or not all(
                Draft202012Validator(field_schema).is_valid(value) for value in values
            ):
                raise StoreError("schema_invalid", details=[{"pointer": "/bind/all"}])
        query = {
            "widget_id": widget_id,
            "bind": {k: v for k, v in bind.items() if k != "cursor"},
        }
        if link_id is not None:
            query.update(link_id=link_id, projection=projection)
        digest = hashlib.sha256(canonical(query).encode()).hexdigest()
        offset = 0
        if bind.get("cursor"):
            cursor = await tx.fetch_one(
                "SELECT row_offset FROM {{tables.page_cursors}} WHERE token=$1 AND scope=$2 AND principal=$3 AND page_rev=$4 AND query_hash=$5 AND expires_at>NOW()",
                bind["cursor"],
                scope.key,
                actor,
                document["rev"],
                digest,
            )
            if cursor is None:
                raise StoreError("cursor_invalid", 409)
            offset = cursor["row_offset"]
        args = self._record_access_args(
            scope,
            definition,
            access,
            actor,
            fields=fields if projection is not None else None,
            record_ids=record_ids,
        )

        def parameter(value):
            args.append(value)
            return f"${len(args)}"

        clauses, orders = [], []
        for predicate in bind.get("all", []):
            field = parameter(predicate["field"])
            expression = f"COALESCE(record->'value'->{field}::text, 'null'::jsonb)"
            if predicate["op"] == "in":
                values = parameter([canonical(value) for value in predicate["value"]])
                clauses.append(f"{expression} = ANY({values}::jsonb[])")
            else:
                operator = {
                    "eq": "=",
                    "ne": "<>",
                    "lt": "<",
                    "lte": "<=",
                    "gt": ">",
                    "gte": ">=",
                }[predicate["op"]]
                value = parameter(canonical(predicate["value"]))
                clauses.append(f"{expression} {operator} {value}::jsonb")
        filter_args = list(args)
        for order in bind.get("sort", []):
            field = parameter(order["field"])
            direction = "ASC" if order["direction"] == "asc" else "DESC"
            orders.append(f"record->'value'->{field}::text {direction} NULLS FIRST")
        orders.append("record->>'id' ASC")
        where = " AND ".join(clauses) or "TRUE"
        authorized = AUTHORIZED_RECORDS
        count = await tx.fetch_value(
            authorized + "SELECT count(*) FROM authorized WHERE " + where, *filter_args
        )
        limit = bind.get("limit", 200)
        # Only order expressions may add parameters absent from count().
        # PostgreSQL requires every supplied parameter to appear, so bind
        # order fields separately in the paginated statement below.
        query_sql = (
            authorized
            + "SELECT record FROM authorized WHERE "
            + where
            + " ORDER BY "
            + ",".join(orders)
        )
        limit_arg, offset_arg = parameter(limit), parameter(offset)
        selected = [
            decoded(r["record"])
            for r in await tx.fetch_all(
                query_sql + f" LIMIT {limit_arg} OFFSET {offset_arg}", *args
            )
        ]
        if projection is not None:
            selected = [{key: record[key] for key in ("id", "rev", "value")} for record in selected]
        next_cursor = None
        if offset + limit < count:
            next_cursor = secrets.token_urlsafe(32)
            await tx.execute(
                "INSERT INTO {{tables.page_cursors}} VALUES($1,$2,$3,$4,$5,$6,NOW()+INTERVAL '15 minutes')",
                next_cursor,
                scope.key,
                actor,
                document["rev"],
                digest,
                offset + limit,
            )
        await self._fence(scope)
        return {
            "page_rev": document["rev"],
            "records": selected,
            "next_cursor": next_cursor,
            "count": count,
        }

    async def _purge_content(self, scope, tombstone_rev):
        async with self.db.transaction() as tx:
            await self._purge_content_in(tx, scope, tombstone_rev)

    async def _purge_content_in(self, tx, scope, tombstone_rev):
        row = await tx.fetch_one(
            "SELECT document,deleted FROM {{tables.pages}} WHERE scope=$1 FOR UPDATE", scope.key
        )
        deletion = await self.ledger.fetch_one(
            "SELECT job_id,receipt FROM {{tables.page_deletions}} WHERE scope=$1", scope.key
        )
        deletion_receipt = decoded(deletion["receipt"])
        policy = deletion_receipt["policy"]
        if policy is not None:
            try:
                key_receipt = await claim(
                    tx,
                    key=deletion_receipt["request_key"],
                    request_hash=bytes.fromhex(deletion_receipt["request_hash"]),
                    receipt_ref=str(deletion["job_id"]),
                    retention=timedelta(days=policy["retry_horizon_days"]),
                )
            except IdempotencyExpired:
                key_receipt = None
            key_deadline = datetime.fromisoformat(deletion_receipt["requested_at"]) + timedelta(
                days=policy["retry_horizon_days"]
            )
            if key_receipt is not None:
                await tx.execute(
                    "UPDATE {{tables.idempotency_keys}} SET expires_at=LEAST(expires_at,$2) WHERE receipt_ref=$1",
                    key_receipt.receipt_ref,
                    key_deadline,
                )
            await tx.execute(
                "UPDATE {{tables.idempotency_keys}} SET expires_at=LEAST(expires_at,$2) WHERE receipt_ref IN (SELECT transaction_id::text FROM {{tables.page_receipts}} WHERE scope=$1)",
                scope.key,
                key_deadline,
            )
        if policy is not None:
            await self.ledger.execute(
                "UPDATE {{tables.idempotency_keys}} SET expires_at=LEAST(expires_at,$2) WHERE key IN (SELECT key FROM {{tables.page_request_claims}} WHERE scope=$1)",
                scope.key,
                key_deadline,
            )
        if row is None:
            return
        document = decoded(row["document"])
        old_rev = document["rev"]
        document = {
            "page_id": scope.page_id,
            "rev": max(old_rev if row["deleted"] else old_rev + 1, tombstone_rev),
        }
        await tx.execute(
            "UPDATE {{tables.pages}} SET document=$2::jsonb,access='{}'::jsonb,deleted=TRUE WHERE scope=$1",
            scope.key,
            canonical(document),
        )
        for table in (
            "page_records",
            "page_layouts",
            "page_schemas",
            "page_cursors",
            "page_receipts",
            "page_import_history",
            "page_layout_context",
        ):
            await tx.execute("DELETE FROM {{tables." + table + "}} WHERE scope=$1", scope.key)
        await tx.execute(
            "UPDATE {{tables.page_audit}} SET evidence='{}'::jsonb,changed='[]'::jsonb WHERE scope=$1",
            scope.key,
        )

        await enqueue(
            tx,
            OutboxEvent(
                event_id=deletion["job_id"],
                team_id=scope.team_id,
                kind="aweb.page.changed",
                occurred_at=datetime.fromisoformat(decoded(deletion["receipt"])["requested_at"]),
                payload=canonical(
                    {
                        "installation_id": scope.installation_id,
                        "app_id": scope.app_id,
                        "page_id": scope.page_id,
                        "rev": tombstone_rev,
                        "deleted": True,
                    }
                ).encode(),
            ),
        )

        await tx.execute(
            "INSERT INTO {{tables.page_audit}} (transaction_id,scope,old_rev,new_rev,evidence,changed) VALUES($1,$2,$3,$4,'{}'::jsonb,'[\"deleted\"]'::jsonb) ON CONFLICT(transaction_id) DO NOTHING",
            deletion["job_id"],
            scope.key,
            tombstone_rev - 1,
            tombstone_rev,
        )

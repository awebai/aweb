"""PostgreSQL page transactions. Content and deletion-ledger databases are separate."""

from __future__ import annotations

import copy
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from jsonschema import Draft202012Validator
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_naapp.idempotency import (
    IdempotencyConflict,
    IdempotencyExpired,
    apply_idempotency_migrations,
    claim,
)
from aweb_naapp.outbox import OutboxEvent, apply_outbox_migrations, enqueue
from aweb_naapp.page_store.lifecycle import LifecycleMixin
from aweb_naapp.page_store.models import Access, RetentionPolicy, Scope, StoreError
from aweb_naapp.page_store.support import canonical, decoded, identity, validated, widgets

if TYPE_CHECKING:
    from aweb_naapp.runtime.team_auth import Principal

ROOT = Path(__file__).parent
MAX_REV = 2**53 - 1


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
    ):
        self.db, self.ledger, self.retention = db, ledger, retention
        self.lifecycle = lifecycle
        self.lifecycle_authorizer = lifecycle_authorizer
        self._ready = False

    async def start(self) -> None:
        """Reapply erasure fences before serving a restored content database."""
        self._ready = False
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
        await self._fence(scope)
        row = await tx.fetch_one(
            "SELECT document, access, deleted FROM {{tables.pages}} WHERE scope=$1 FOR UPDATE",
            scope.key,
        )
        if row is None or row["deleted"]:
            raise StoreError("resource_not_found", 404)
        access = Access.from_dict(decoded(row["access"]))
        if not access.permits(actor, operation):
            raise StoreError("resource_not_found", 404)
        return decoded(row["document"]), access, actor

    async def _records(self, tx, scope, collection):
        rows = await tx.fetch_all(
            "SELECT record FROM {{tables.page_records}} WHERE scope=$1 AND collection=$2 AND record IS NOT NULL ORDER BY record_id",
            scope.key,
            collection,
        )
        return [decoded(row["record"]) for row in rows]

    async def _claim(self, tx, scope, principal, key, request, *, retention=None):
        if not isinstance(key, str) or not key or len(key) > 256:
            raise StoreError("precondition_required", 428)
        try:
            result = await claim(
                tx,
                key=[scope.installation_id, scope.team_id, identity(principal, scope), key],
                request_hash=hashlib.sha256(
                    canonical({"scope": scope.key, **request}).encode()
                ).digest(),
                receipt_ref=str(uuid4()),
                retention=timedelta(days=(retention or self._policy()).retry_horizon_days),
            )
        except (IdempotencyConflict, IdempotencyExpired) as error:
            raise StoreError(error.code, error.status) from error
        if result.created:
            # Live resource keys last for the resource lifetime. Deletion starts
            # the retry horizon; the shared primitive still owns key tombstones.
            await tx.execute(
                "UPDATE {{tables.idempotency_keys}} SET expires_at='infinity' WHERE receipt_ref=$1",
                result.receipt_ref,
            )
            return UUID(result.receipt_ref), None
        receipt = await tx.fetch_value(
            "SELECT receipt FROM {{tables.page_receipts}} WHERE transaction_id=$1 AND scope=$2",
            UUID(result.receipt_ref),
            scope.key,
        )
        if receipt is None:
            raise RuntimeError("idempotency receipt missing")
        return UUID(result.receipt_ref), decoded(receipt)

    async def _commit(
        self, tx, scope, principal, transaction, document, old_rev, changed, record_revs=None
    ):
        if old_rev >= MAX_REV:
            raise StoreError("revision_exhausted", 409)
        document["rev"] = old_rev + 1
        receipt = {
            "transaction_id": str(transaction),
            "page_rev": document["rev"],
            "record_revs": record_revs or {},
            "audit_id": str(transaction),
        }
        await tx.execute(
            "UPDATE {{tables.pages}} SET document=$2::jsonb,policy_version=$3,retention_policy=$4::jsonb WHERE scope=$1",
            scope.key,
            canonical(document),
            self._policy().version,
            canonical(self._policy().as_dict()),
        )
        evidence = {
            "principal_id": identity(principal, scope),
            "signer_did": principal.did_key,
            "certificate_id": principal.certificate_id,
            "origin_kind": "member",
        }
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

    async def _create(
        self, tx, scope, principal, document, *, access: Access, key: str, request_context=None
    ):
        self._policy()
        actor = identity(principal, scope)
        await self._fence(scope)
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
        if existing is not None and not Access.from_dict(decoded(existing)).permits(actor, "read"):
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

    async def _mutate(self, scope, principal, *, expected_rev, key, records, state, sync):
        self._policy()
        async with self.db.transaction() as tx:
            document, access, actor = await self._load(
                tx, scope, principal, "owner" if sync else "write"
            )
            transaction, replay = await self._claim(
                tx,
                scope,
                principal,
                key,
                {
                    "op": "sync" if sync else "mutate",
                    "expected_rev": expected_rev,
                    "records": records,
                    "state": state,
                },
            )
            if replay:
                return replay
            self._precondition(document, expected_rev)
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
                }:
                    raise StoreError("schema_invalid")
                cid, rid = change.get("collection"), change.get("id")
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
                if operation not in {"create", "update", "delete"}:
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
                proposed = change.get("value") if isinstance(change.get("value"), dict) else {}
                allowed = access.value_fields(actor, collection, set(previous) | set(proposed))
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
                    value = change.get("value")
                    if not isinstance(value, dict) or set(value) - allowed:
                        raise StoreError("action_denied", 403)
                    record = {"id": rid, "rev": rev, "value": value}
                    if sync:
                        record["source"] = change.get("source")
                    elif "source" in change:
                        raise StoreError("schema_invalid")
                    self._validate_record(document, collection, record)
                    await self._put_record(tx, scope, cid, record)
                revisions[f"{cid}/{rid}"] = rev
                changed.append(
                    {
                        "collection": cid,
                        "record_id": rid,
                        "fields": sorted(change.get("value") or {}),
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
                tx, scope, principal, transaction, document, expected_rev, changed, revisions
            )

    @staticmethod
    def _validate_record(document, collection, record):
        probe = {
            **document,
            "layout": [],
            "actions": [],
            "widget_state": {},
            "collections": [{**collection, "records": [record]}],
        }
        validated(probe)

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
                self._validate_record(document, definition, record)
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
        return self._redact_snapshot(document, access, actor)

    def _redact_snapshot(self, document, access, actor):
        definitions = {c["id"]: c for c in document["collections"]}
        records = {cid: {r["id"]: r for r in c["records"]} for cid, c in definitions.items()}
        required = {cid: {} for cid in definitions}
        for widget in widgets(document["layout"]):
            denied = False
            if widget["type"] == "decision_card":
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
                denied = denied or bool(
                    self._binding_fields(widget)
                    - access.visible_fields(actor, definitions[binding["collection"]])
                )
            if denied:
                wid = widget["id"]
                widget.clear()
                widget.update(id=wid, type="access_unavailable", fallback="Unavailable", props={})
        for collection in document["collections"]:
            allowed = access.visible_fields(actor, collection)
            collection["records"] = [
                {
                    **r,
                    "value": {
                        k: v
                        for k, v in r["value"].items()
                        if k in access.value_fields(actor, collection, r["value"])
                    },
                }
                for r in required[collection["id"]].values()
                if access.visible_row(actor, collection["id"], r["id"])
            ]
            schema = collection["schema"]
            schema["properties"] = {
                k: v for k, v in schema.get("properties", {}).items() if k in allowed
            }
            if "required" in schema:
                schema["required"] = [f for f in schema["required"] if f in allowed]
            if not access.all_value_fields(actor, collection):
                schema.pop("default", None)
                schema.pop("examples", None)
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

    async def read_widget(self, scope, principal, *, widget_id, expected_page_rev, bind):
        if not isinstance(bind, dict):
            raise StoreError("schema_invalid", details=[{"pointer": "/bind"}])
        async with self.db.transaction() as tx:
            document, access, actor = await self._load(tx, scope, principal)
            self._precondition(document, expected_page_rev)
            widget = next((w for w in widgets(document["layout"]) if w["id"] == widget_id), None)
            if (
                widget is None
                or not widget.get("bind")
                or bind.get("collection") != widget["bind"]["collection"]
            ):
                raise StoreError("query_denied", 403)
            definition = next(c for c in document["collections"] if c["id"] == bind["collection"])
            fields = access.visible_fields(actor, definition)
            probe = copy.deepcopy(document)
            probe["layout"] = [
                {
                    "id": widget_id,
                    "type": "table",
                    "props": {
                        "columns": [
                            {"field": f, "label": f, "format": "text"} for f in sorted(fields)
                        ]
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
            args = [
                scope.key,
                definition["id"],
                sorted(access.hidden_rows.get(actor, {}).get(definition["id"], set()))
                if actor != access.owner
                else [],
                sorted(fields),
                access.all_value_fields(actor, definition),
            ]

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
            authorized = """WITH authorized AS MATERIALIZED (
                SELECT (record-'value') || jsonb_build_object('value', COALESCE(
                    (SELECT jsonb_object_agg(key,value) FROM jsonb_each(record->'value')
                     WHERE $5::boolean OR key=ANY($4::text[])), '{}'::jsonb)) AS record
                FROM {{tables.page_records}}
                WHERE scope=$1 AND collection=$2 AND record IS NOT NULL
                  AND NOT(record_id=ANY($3::text[]))
            ) """
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

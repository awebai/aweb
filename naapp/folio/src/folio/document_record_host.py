"""Table data and checked row edits inside ordinary Folio document links."""

import copy
import json
from typing import Annotated
from uuid import UUID

from aweb_naapp.page_store import LinkRecordContext, Scope, StoreError, principal_id
from fastapi import Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from folio import edit_sessions
from folio.document_widgets import WidgetDocumentError, table_widgets
from folio.record_adapters import delete_result, query_result, write_result
from folio.record_collections import TABLE_WIDGET_ID
from folio.record_host import store_http
from folio.record_view_access import checked_view
from folio.record_widgets import resolve_widget_on


class RowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(min_length=1, max_length=128)


class RowAdd(RowRequest):
    values: dict[str, JsonValue]


class RowUpdate(RowRequest):
    record_id: str = Field(min_length=1, max_length=128)
    expected_rev: int = Field(ge=1)
    patch: dict[str, JsonValue]


class RowDelete(RowRequest):
    record_id: str = Field(min_length=1, max_length=128)
    expected_rev: int = Field(ge=1)


def definitions(body):
    try:
        return table_widgets(body)
    except WidgetDocumentError as error:
        raise StoreError(error.code, 422) from None


def grants(row):
    value = row["record_write_grants"]
    value = json.loads(value) if isinstance(value, str) else value
    return value if isinstance(value, dict) else {}


class DocumentRecordHost:
    def __init__(self, runtime, storage):
        self.runtime, self.storage = runtime, storage

    async def source(self, context):
        row, tx = context.row, context.tx
        selected = await tx.fetch_one(
            "SELECT body,version_number FROM {{tables.document_versions}} "
            "WHERE document_id=$1 AND ($2::integer IS NULL OR version_number=$2) "
            "ORDER BY version_number DESC LIMIT 1",
            row["document_id"],
            None if row["editable"] else row["version_number"],
        )
        if selected is None:
            raise edit_sessions.unavailable()
        return dict(selected)

    def require_identity(self, context):
        creator = context.row["records_creator_id"]
        if not isinstance(creator, str) or not creator:
            raise StoreError("records_identity_required", 409)
        return creator

    async def write_fields(self, tx, scope, creator_id, collection):
        try:
            metadata = await self.storage.require_store().collection_access_on(
                tx,
                scope,
                creator_id=creator_id,
                collection=collection,
                link_mode="live",
                write=True,
            )
        except StoreError as error:
            if error.status == 404:
                return set()
            raise
        return set(metadata["fields"]) if metadata else set()

    async def mint_authority_on(
        self, tx, *, installation, principal, document_id, version_number, editable
    ):
        # The document lock precedes collection/page locks, just like edit sessions.
        document = await tx.fetch_one(
            "SELECT v.body FROM {{tables.documents}} d JOIN {{tables.document_versions}} v "
            "ON v.document_id=d.document_id AND v.version_number=$3 "
            "WHERE d.document_id=$1 AND d.team_id=$2 FOR SHARE OF d",
            document_id,
            principal.team_id,
            version_number,
        )
        if document is None:
            raise edit_sessions.unavailable()
        identity_scope = Scope(
            installation.installation_id,
            installation.team_id,
            installation.app_id,
            str(document_id),
        )
        creator = principal_id(principal, identity_scope)
        frozen = {}
        if editable:
            for identifier, widget in sorted(definitions(document["body"]).items()):
                try:
                    scope, metadata, _ = await resolve_widget_on(
                        tx,
                        installation,
                        creator,
                        widget,
                        self.storage,
                    )
                    fields = await self.write_fields(tx, scope, creator, metadata["id"])
                except StoreError as error:
                    if error.status in (403, 404):
                        continue  # Prose may be shared even when a table is unavailable.
                    raise
                fields &= {column["field"] for column in widget["props"]["columns"]}
                if fields:
                    frozen[identifier] = {
                        "collection": metadata["id"],
                        "fields": sorted(fields),
                        "operations": ["add", "patch", "delete"],
                    }
        return creator, frozen

    async def resolve(self, context, identifier, *, write=False):
        creator = self.require_identity(context)
        current = await self.source(context)
        widget = definitions(current["body"]).get(identifier)
        if widget is None:
            raise StoreError("resource_not_found", 404)
        scope, metadata, page = await resolve_widget_on(
            context.tx,
            context.permit.admitted,
            creator,
            widget,
            self.storage,
            write=write,
        )
        page = copy.deepcopy(page)  # Renderer normalization must not rewrite the saved query.
        displayed = {column["field"] for column in widget["props"]["columns"]}
        metadata = {
            **metadata,
            "collection_fields": metadata["fields"],
            "fields": sorted(displayed & set(metadata["fields"])),
        }
        schema = copy.deepcopy(metadata["schema"])
        schema["properties"] = {
            key: value for key, value in schema["properties"].items() if key in displayed
        }
        if "required" in schema:
            schema["required"] = [key for key in schema["required"] if key in displayed]
        page["collections"][0]["schema"] = schema
        # Predicate fields/values belong to the checked server query, not the renderer.
        page["layout"][0]["bind"] = {
            "collection": metadata["id"],
            "limit": widget["bind"].get("limit", 20),
        }
        await context.revalidate(context.tx)
        return widget, scope, metadata, page

    async def query(self, context, identifier, cursor=None):
        widget, scope, metadata, _ = await self.resolve(context, identifier)
        bind = copy.deepcopy(widget["bind"])
        bind.pop("cursor", None)  # Persisted actor cursors never become another holder's cursor.
        if cursor is not None:
            bind["cursor"] = cursor
        result = await self.storage.require_store().query_widget_on(
            context.tx,
            scope,
            creator_id=self.require_identity(context),
            widget_id=TABLE_WIDGET_ID,
            bind=bind,
            link_id=context.row["token"] + ":" + identifier,
            predicate_fields=frozenset(
                item["field"] for item in bind.get("all", []) + bind.get("sort", [])
            ),
            projection={
                "collections": [
                    {"collection": metadata["id"], "fields": metadata["fields"], "record_ids": "*"}
                ],
                "assets": [],
            },
        )
        await context.revalidate(context.tx)
        return {
            key: value
            for key, value in query_result(metadata["id"], result).items()
            if key != "collection_id"
        }

    async def capabilities(self, context, identifier, scope, metadata):
        empty = {"add": False, "patch_fields": [], "delete": False, "reopen_to_edit": False}
        if not context.row["editable"]:
            return empty
        current = await self.write_fields(
            context.tx, scope, self.require_identity(context), metadata["id"]
        )
        current &= set(metadata["fields"])
        frozen = grants(context.row).get(identifier, {})
        if not isinstance(frozen, dict) or frozen.get("collection") != metadata["id"]:
            return empty | {"reopen_to_edit": bool(current)}
        fields = current & set(frozen.get("fields", []))
        operations = set(frozen.get("operations", []))
        return {
            "add": "add" in operations
            and bool(fields)
            and set(metadata["schema"].get("required", [])) <= fields,
            "patch_fields": sorted(fields) if "patch" in operations else [],
            "delete": "delete" in operations
            and bool(fields)
            and set(metadata["collection_fields"]) <= fields,
            "reopen_to_edit": bool(current - fields),
        }

    async def snapshot(self, context):
        current = await self.source(context)
        result = {}
        for identifier in definitions(current["body"]):
            if not context.row["records_creator_id"]:
                result[identifier] = {
                    "state": "records_identity_required",
                    "reopen": "edit" if context.row["editable"] else "new_link_from_sharer",
                }
                continue
            try:
                _, scope, metadata, page = await self.resolve(context, identifier)
                queried = await self.query(context, identifier)
                page["rev"] = queried["snapshot_rev"]
                page["collections"][0]["records"] = queried["records"]
                result[identifier] = {
                    "state": "ready",
                    "data_mode": "live",
                    "page": page,
                    "query": {
                        key: value for key, value in queried.items() if key != "collection_id"
                    },
                    "edit": await self.capabilities(context, identifier, scope, metadata),
                }
            except StoreError as error:
                if error.status not in (403, 404):
                    raise
                result[identifier] = {"state": "unavailable"}
        await context.revalidate(context.tx)
        return {"version_number": current["version_number"], "widgets": result}

    async def mutate(self, context, identifier, operation, payload):
        _, scope, metadata, _ = await self.resolve(context, identifier, write=True)
        frozen = grants(context.row).get(identifier, {})
        if not isinstance(frozen, dict) or frozen.get("collection") != metadata["id"]:
            raise StoreError("action_denied", 403)
        public_session = context.row["record_session_id"]
        if not isinstance(public_session, UUID):
            raise edit_sessions.unavailable()  # Never substitute a bearer value or hash.
        row = context.row
        actor = LinkRecordContext(
            scope=scope,
            creator_id=self.require_identity(context),
            creator_did_key=row["created_by_did_key"],
            creator_did_aw=row["created_by_did_aw"],
            creator_alias=row["created_by_alias"],
            certificate_id=row["certificate_id"],
            editor_name=None,
            link_id=row["token"],
            session_id=str(public_session),
            document_id=str(row["document_id"]),
            widget_id=identifier,
            collection=metadata["id"],
            operations=frozenset(frozen.get("operations", [])),
            fields=frozenset(frozen.get("fields", [])) & frozenset(metadata["fields"]),
            revalidate=context.revalidate,
        )
        request = payload.model_dump(exclude={"request_id"})
        receipt = await self.storage.require_store().write_link_record_on(
            context.tx,
            scope,
            actor,
            operation=operation,
            collection=metadata["id"],
            key=payload.request_id,
            **request,
        )
        return (delete_result if operation == "delete" else write_result)(metadata["id"], receipt)

    def mount(self, app, database_dependency):
        async def edit_query(
            link_id: str,
            widget_id: str,
            request: Request,
            database: Annotated[object, Depends(database_dependency)],
            cursor: Annotated[str | None, Query(max_length=2048)] = None,
        ):
            try:
                async with edit_sessions.checked_access(
                    database,
                    self.runtime,
                    link_id=link_id,
                    credential=request.headers.get(edit_sessions.SESSION_HEADER),
                ) as context:
                    return await self.query(context, widget_id, cursor)
            except StoreError as error:
                raise store_http(error) from None

        app.get("/present/edit/{link_id}/widgets/{widget_id}/records")(edit_query)

        async def perform(link_id, widget_id, request, database, operation, payload):
            try:
                async with edit_sessions.checked_access(
                    database,
                    self.runtime,
                    link_id=link_id,
                    credential=request.headers.get(edit_sessions.SESSION_HEADER),
                    write=True,
                ) as context:
                    return await self.mutate(context, widget_id, operation, payload)
            except StoreError as error:
                raise store_http(error) from None

        @app.post("/present/edit/{link_id}/widgets/{widget_id}/records/add")
        async def add(
            link_id: str,
            widget_id: str,
            request: Request,
            payload: RowAdd,
            database: Annotated[object, Depends(database_dependency)],
        ):
            return await perform(link_id, widget_id, request, database, "add", payload)

        @app.post("/present/edit/{link_id}/widgets/{widget_id}/records/update")
        async def update(
            link_id: str,
            widget_id: str,
            request: Request,
            payload: RowUpdate,
            database: Annotated[object, Depends(database_dependency)],
        ):
            return await perform(link_id, widget_id, request, database, "patch", payload)

        @app.post("/present/edit/{link_id}/widgets/{widget_id}/records/delete")
        async def delete(
            link_id: str,
            widget_id: str,
            request: Request,
            payload: RowDelete,
            database: Annotated[object, Depends(database_dependency)],
        ):
            return await perform(link_id, widget_id, request, database, "delete", payload)

        @app.get("/present/{token}/widgets")
        async def view_snapshot(
            token: str, database: Annotated[object, Depends(database_dependency)]
        ):
            try:
                async with checked_view(database, self.runtime, token) as context:
                    return await self.snapshot(context)
            except StoreError as error:
                raise store_http(error) from None

        @app.get("/present/{token}/widgets/{widget_id}/records")
        async def view_query(
            token: str,
            widget_id: str,
            database: Annotated[object, Depends(database_dependency)],
            cursor: Annotated[str | None, Query(max_length=2048)] = None,
        ):
            try:
                async with checked_view(database, self.runtime, token) as context:
                    return await self.query(context, widget_id, cursor)
            except StoreError as error:
                raise store_http(error) from None

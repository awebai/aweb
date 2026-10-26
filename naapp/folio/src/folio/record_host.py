"""Folio member tools and admitted document saves over shared stores."""

from typing import Annotated

from aweb_naapp.page_store import StoreError, principal_id
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.installation import InstallationFence, InstallationRefused
from fastapi import Depends, FastAPI, HTTPException

from folio.collection_scope import collection_scope
from folio.record_models import (
    CollectionDefineRequest,
    RecordAddRequest,
    RecordDeleteRequest,
    RecordQueryRequest,
    RecordUpdateRequest,
)
from folio.record_service import RecordService
from folio.record_storage import RecordStorage
from folio.record_widgets import validate_saved_widgets_on


def store_http(error: StoreError | InstallationRefused) -> HTTPException:
    return HTTPException(error.status, detail={"code": error.code})


class RecordHost:
    def __init__(
        self,
        runtime: NaappRuntime,
        storage: RecordStorage,
    ) -> None:
        self.runtime, self.storage = runtime, storage
        self.settings = runtime.settings
        self.grants = runtime.installation_grants()

        async def policy(request, principal, tool):
            # Record-level and field-level authority is decided inside PageStore.
            return tool.name in {
                "collection-define",
                "record-add",
                "record-update",
                "record-delete",
                "record-query",
            }

        self.guard = runtime.authorized(grants=self.grants, policy=policy)

    def fence(self) -> InstallationFence:
        return InstallationFence(
            self.runtime.db(), app_id=self.runtime.manifest.app_id, grants=self.grants
        )

    def service(self) -> RecordService:
        return RecordService(self.storage.require_store())

    async def save_document(self, database, installation, principal, *, body, operation, **kwargs):
        """Join author admission and collection read locks to the version write."""
        try:
            async with database.transaction() as tx:
                # Keep document -> collection lock order shared with edit sessions.
                await tx.fetch_one(
                    "SELECT document_id FROM {{tables.documents}} "
                    "WHERE team_id=$1 AND slug=$2 FOR UPDATE",
                    principal.team_id,
                    kwargs["slug"],
                )
                await validate_saved_widgets_on(tx, installation, principal, body, self.storage)
                return await operation(
                    tx,
                    principal=principal,
                    events=self.runtime.app_events,
                    body=body,
                    **kwargs,
                )
        except (StoreError, InstallationRefused) as error:
            raise store_http(error) from None

    async def member_operation(self, authorization, method, payload):
        try:
            async with self.runtime.db().transaction() as tx:
                admitted = await self.fence().admit(tx, authorization.grant)
                service = self.service()
                if method == "define_on":
                    scope = collection_scope(admitted, payload.collection_id)
                    return await service.define_on(
                        tx,
                        admitted,
                        authorization.principal,
                        payload,
                        owner_id=principal_id(authorization.principal, scope),
                    )
                return await getattr(service, method)(
                    tx, admitted, authorization.principal, payload
                )
        except (StoreError, InstallationRefused) as error:
            raise store_http(error) from None

    def mount(self, app: FastAPI) -> None:
        guard = self.guard

        @app.post("/v1/collections")
        async def define(
            payload: CollectionDefineRequest,
            authorization: Annotated[Authorization, Depends(guard)],
        ):
            return await self.member_operation(authorization, "define_on", payload)

        @app.post("/v1/records/add")
        async def add(
            payload: RecordAddRequest, authorization: Annotated[Authorization, Depends(guard)]
        ):
            return await self.member_operation(authorization, "add_on", payload)

        @app.post("/v1/records/update")
        async def update(
            payload: RecordUpdateRequest, authorization: Annotated[Authorization, Depends(guard)]
        ):
            return await self.member_operation(authorization, "update_on", payload)

        @app.post("/v1/records/delete")
        async def delete(
            payload: RecordDeleteRequest, authorization: Annotated[Authorization, Depends(guard)]
        ):
            return await self.member_operation(authorization, "delete_on", payload)

        @app.post("/v1/records/query")
        async def query(
            payload: RecordQueryRequest, authorization: Annotated[Authorization, Depends(guard)]
        ):
            return await self.member_operation(authorization, "query_on", payload)

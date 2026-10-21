"""Folio operations over PageStore, joined to the host's admitted transaction.

The runtime authenticates/grants the member, then InstallationFence admits and
locks the installation on this same transaction before these methods run.
"""

from aweb_naapp.page_store import Access, PageStore, StoreError
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from folio.collection_documents import (
    collection_scope,
    list_collection_documents,
    put_collection_document_on,
)
from folio.record_adapters import (
    definition_result,
    delete_result,
    query_bind,
    query_result,
    write_result,
)
from folio.record_collections import TABLE_WIDGET_ID, build_collection_page
from folio.record_models import (
    CollectionDefineRequest,
    RecordAddRequest,
    RecordDeleteRequest,
    RecordQueryRequest,
    RecordUpdateRequest,
)


class RecordService:
    def __init__(self, store: PageStore) -> None:
        self.store = store

    async def define_on(
        self, tx: TransactionManager, installation: AdmittedInstallation, principal: Principal,
        payload: CollectionDefineRequest, *, owner_id: str,
    ) -> dict:
        scope = collection_scope(installation, payload.collection_id)
        document = build_collection_page(page_id=scope.page_id, collection_id=payload.collection_id,
                                         title=payload.title, schema=payload.record_schema, owner=owner_id)
        receipt = await self.store.create_on(
            tx, scope, principal, document,
            access=Access(owner=owner_id, team_id=scope.team_id, team_read=True, team_write=True),
            key=payload.request_id,
        )
        entry = await put_collection_document_on(tx, scope, principal, collection_id=payload.collection_id,
                                                 title=payload.title)
        return definition_result(payload.collection_id, receipt, entry)

    async def add_on(
        self, tx: TransactionManager, installation: AdmittedInstallation, principal: Principal,
        payload: RecordAddRequest,
    ) -> dict:
        receipt = await self.store.add_record_on(
            tx, collection_scope(installation, payload.collection_id), principal,
            collection=payload.collection_id, values=payload.values,
            record_id=payload.record_id, key=payload.request_id,
        )
        return write_result(payload.collection_id, receipt)

    async def update_on(
        self, tx: TransactionManager, installation: AdmittedInstallation, principal: Principal,
        payload: RecordUpdateRequest,
    ) -> dict:
        receipt = await self.store.patch_record_on(
            tx, collection_scope(installation, payload.collection_id), principal,
            collection=payload.collection_id, record_id=payload.record_id,
            expected_rev=payload.expected_rev, patch=payload.patch, key=payload.request_id,
        )
        return write_result(payload.collection_id, receipt)

    async def delete_on(
        self, tx: TransactionManager, installation: AdmittedInstallation, principal: Principal,
        payload: RecordDeleteRequest,
    ) -> dict:
        receipt = await self.store.delete_record_on(
            tx, collection_scope(installation, payload.collection_id), principal,
            collection=payload.collection_id, record_id=payload.record_id,
            expected_rev=payload.expected_rev, key=payload.request_id,
        )
        return delete_result(payload.collection_id, receipt)

    async def query_on(
        self, tx: TransactionManager, installation: AdmittedInstallation, principal: Principal,
        payload: RecordQueryRequest,
    ) -> dict:
        result = await self.store.query_member_widget_on(
            tx, collection_scope(installation, payload.collection_id), principal,
            widget_id=TABLE_WIDGET_ID, bind=query_bind(payload),
        )
        return query_result(payload.collection_id, result)

    async def list_documents_on(
        self, tx: TransactionManager, installation: AdmittedInstallation, principal: Principal,
    ) -> list[dict]:
        entries = []
        for document in await list_collection_documents(tx, installation):
            try:
                # Only PageStore decides whether an entry is still readable.
                snapshot = await self.query_on(tx, installation, principal, RecordQueryRequest(
                    collection_id=document["collection_id"], limit=1))
            except StoreError as error:
                if error.status == 404:
                    continue
                raise
            entries.append({field: document[field] for field in (
                "document_id", "slug", "title", "created_at", "updated_at", "kind")}
                           | {"current_version": snapshot["snapshot_rev"]})
        return entries

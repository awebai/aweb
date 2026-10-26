"""Thin Folio operations join the real shared store and discovery transaction."""

from pathlib import Path

import pytest
from aweb_naapp.page_store import StoreError
from aweb_naapp.runtime.team_auth import record_observed_principal
from pgdbm import AsyncMigrationManager
from test_collection_scope import INSTALLATION
from test_record_collections import VALUE
from test_record_storage import ACTOR, POLICY

from folio.config import Settings
from folio.record_collections import DISCOVERY_SCHEMA, DISCOVERY_TITLE
from folio.record_models import (
    CollectionDefineRequest,
    RecordAddRequest,
    RecordDeleteRequest,
    RecordQueryRequest,
    RecordUpdateRequest,
)
from folio.record_service import RecordService
from folio.record_storage import RecordStorage


@pytest.fixture
async def service(test_db_factory):
    content = await test_db_factory.create_db(suffix="folio_service")
    ledger = await test_db_factory.create_db(suffix="folio_service_ledger")
    storage = RecordStorage(
        Settings(
            _env_file=None,
            db_schema=content.config.get_schema(),
            AWEB_PAGE_DELETION_DATABASE_URL=ledger.config.get_dsn(),
            AWEB_PAGE_RETENTION_POLICY=POLICY,
        )
    )
    try:
        await storage.connect(content)
        path = Path(__file__).resolve().parents[1] / "src/folio/migrations"
        await AsyncMigrationManager(
            content, migrations_path=str(path), module_name="folio"
        ).apply_pending_migrations()
        await record_observed_principal(content, ACTOR)
        yield RecordService(storage.require_store())
    finally:
        await storage.disconnect()


async def define(service, tx):
    payload = CollectionDefineRequest.model_validate(
        {
            "collection_id": "discovery",
            "title": DISCOVERY_TITLE,
            "schema": DISCOVERY_SCHEMA,
            "request_id": "define",
        }
    )
    return await service.define_on(tx, INSTALLATION, ACTOR, payload, owner_id=ACTOR.did_key)


async def test_define_replays_without_creating_a_document(service):
    async with service.store.db.transaction() as tx:
        first = await define(service, tx)
    async with service.store.db.transaction() as tx:
        assert await define(service, tx) == first
    assert "document_slug" not in first
    assert "table_url" not in first
    assert await service.store.db.fetch_value("SELECT count(*) FROM {{tables.documents}}") == 0
    assert (
        await service.store.db.fetch_value("SELECT count(*) FROM {{tables.document_versions}}") == 0
    )


async def test_add_patch_delete_replay_keeps_original_values_after_later_revisions(service):
    async with service.store.db.transaction() as tx:
        await define(service, tx)
        added = await service.add_on(
            tx,
            INSTALLATION,
            ACTOR,
            RecordAddRequest(collection_id="discovery", request_id="add", values=VALUE),
        )
    row_id = added["record"]["id"]
    patch = RecordUpdateRequest(
        collection_id="discovery",
        record_id=row_id,
        expected_rev=1,
        request_id="edit",
        patch={"status": "contacted", "next_follow_up": ""},
    )
    async with service.store.db.transaction() as tx:
        changed = await service.update_on(tx, INSTALLATION, ACTOR, patch)
    assert changed["record"]["value"] == {**VALUE, "status": "contacted", "next_follow_up": ""}
    async with service.store.db.transaction() as tx:
        deleted = await service.delete_on(
            tx,
            INSTALLATION,
            ACTOR,
            RecordDeleteRequest(
                collection_id="discovery", record_id=row_id, expected_rev=2, request_id="delete"
            ),
        )
    assert deleted["deleted"] is True
    async with service.store.db.transaction() as tx:
        assert (
            await service.add_on(
                tx,
                INSTALLATION,
                ACTOR,
                RecordAddRequest(collection_id="discovery", request_id="add", values=VALUE),
            )
            == added
        )
        assert await service.update_on(tx, INSTALLATION, ACTOR, patch) == changed
        assert (
            await service.delete_on(
                tx,
                INSTALLATION,
                ACTOR,
                RecordDeleteRequest(
                    collection_id="discovery", record_id=row_id, expected_rev=2, request_id="delete"
                ),
            )
            == deleted
        )
        empty = await service.query_on(
            tx, INSTALLATION, ACTOR, RecordQueryRequest(collection_id="discovery")
        )
    assert empty["records"] == [] and empty["count"] == 0


async def test_invalid_calendar_patch_has_no_partial_write_or_index_change(service):
    async with service.store.db.transaction() as tx:
        await define(service, tx)
        added = await service.add_on(
            tx,
            INSTALLATION,
            ACTOR,
            RecordAddRequest(collection_id="discovery", request_id="add", values=VALUE),
        )
    with pytest.raises(StoreError, match="schema_invalid"):
        async with service.store.db.transaction() as tx:
            await service.update_on(
                tx,
                INSTALLATION,
                ACTOR,
                RecordUpdateRequest(
                    collection_id="discovery",
                    record_id=added["record"]["id"],
                    expected_rev=1,
                    request_id="bad-date",
                    patch={"date": "2026-02-29", "status": "must not commit"},
                ),
            )
    async with service.store.db.transaction() as tx:
        result = await service.query_on(
            tx, INSTALLATION, ACTOR, RecordQueryRequest(collection_id="discovery")
        )
    assert result["records"] == [added["record"]]

"""Folio mounts the real shared store with an independent deletion database."""

import pytest
from aweb_naapp.page_store import Access, StoreError
from aweb_naapp.runtime.team_auth import Principal
from test_record_collections import SCOPE, VALUE

from folio.config import Settings
from folio.record_collections import DISCOVERY_SCHEMA, DISCOVERY_TITLE, build_collection_page
from folio.record_storage import RecordStorage

POLICY = {
    "version": "synthetic-folio-test", "content_purge_days": 7, "audit_content_days": 90,
    "backup_expiry_days": 30, "backup_interval_hours": 24, "restore_rpo_hours": 24,
    "retry_horizon_days": 30, "encrypted_backups": True, "legal_exceptions": [],
}
ACTOR = Principal(SCOPE.team_id, "did:key:creator", None, None, "creator", "certificate-1", "did:key:team")


def test_without_a_ledger_the_record_service_is_explicitly_unavailable():
    storage = RecordStorage(Settings(_env_file=None, AWEB_PAGE_DELETION_DATABASE_URL=None))
    with pytest.raises(StoreError) as error:
        storage.require_store()
    assert (error.value.code, error.value.status) == ("records_unavailable", 503)


async def test_store_starts_on_separate_database_and_enforces_real_folio_record_validation(test_db_factory):
    content = await test_db_factory.create_db(suffix="folio_records")
    ledger = await test_db_factory.create_db(suffix="folio_ledger")
    settings = Settings(
        _env_file=None, db_schema=content.config.get_schema(),
        AWEB_PAGE_DELETION_DATABASE_URL=ledger.config.get_dsn(),
        AWEB_PAGE_RETENTION_POLICY=POLICY,
    )
    storage = RecordStorage(settings)
    try:
        await storage.connect(content)
        store = storage.require_store()
        assert await store.db.fetch_value("SELECT current_database()") != await store.ledger.fetch_value("SELECT current_database()")
        document = build_collection_page(page_id=SCOPE.page_id, collection_id="discovery",
                                         title=DISCOVERY_TITLE, schema=DISCOVERY_SCHEMA, owner=ACTOR.did_key)
        document["collections"][0]["records"] = [{"id": "row-1", "rev": 1, "value": VALUE}]
        await store.create(SCOPE, ACTOR, document, access=Access(owner=ACTOR.did_key), key="define-1")
        assert (await store.read(SCOPE, ACTOR))["collections"][0]["records"][0]["value"] == VALUE
        with pytest.raises(StoreError, match="schema_invalid"):
            await store.patch_record(SCOPE, ACTOR, collection="discovery", record_id="row-1",
                                     expected_rev=1, patch={"date": "2026-02-29"}, key="invalid-date")
        result = await store.read(SCOPE, ACTOR)
        assert result["rev"] == 1
        assert result["collections"][0]["records"][0]["value"] == VALUE
    finally:
        await storage.disconnect()
    with pytest.raises(StoreError, match="records_unavailable"):
        storage.require_store()


async def test_same_database_is_refused_before_records_can_be_served(test_db_factory):
    content = await test_db_factory.create_db(suffix="folio_same_db")
    storage = RecordStorage(Settings(
        _env_file=None, db_schema=content.config.get_schema(),
        AWEB_PAGE_DELETION_DATABASE_URL=content.config.get_dsn(),
        AWEB_PAGE_RETENTION_POLICY=POLICY,
    ))
    try:
        with pytest.raises(ValueError, match="separate database"):
            await storage.connect(content)
        with pytest.raises(StoreError, match="records_unavailable"):
            storage.require_store()
    finally:
        await storage.disconnect()

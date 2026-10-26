"""Collections are metadata/data for embeds, never synthetic Folio documents."""

from test_record_service import define, service

__all__ = ["service"]


async def test_define_receipt_contains_collection_metadata_without_synthetic_document(service):
    async with service.store.db.transaction() as tx:
        receipt = await define(service, tx)
    assert receipt == {"collection_id": "discovery", "schema_version": 1, "snapshot_rev": 1}
    assert await service.store.db.fetch_value("SELECT count(*) FROM {{tables.documents}}") == 0
    async with service.store.db.transaction() as tx:
        assert await define(service, tx) == receipt

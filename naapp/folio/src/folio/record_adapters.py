"""Translate the public record contract to shared-store inputs and receipts."""

import copy

from folio.record_models import RecordQueryRequest


def query_bind(request: RecordQueryRequest) -> dict:
    bind = {
        "collection": request.collection_id,
        "all": [predicate.model_dump() for predicate in request.filter],
        "sort": [order.model_dump() for order in request.sort],
        "limit": request.limit,
    }
    if request.cursor is not None:
        bind["cursor"] = request.cursor
    return bind


def definition_result(collection_id: str, receipt: dict) -> dict:
    return {
        "collection_id": collection_id,
        "schema_version": 1,
        "snapshot_rev": receipt["page_rev"],
    }


def write_result(collection_id: str, receipt: dict) -> dict:
    # Preserve the original authorized outcome on replay. Never reload a newer
    # row here, and never expose the store's internal audit/transaction receipt.
    return {
        "collection_id": collection_id,
        "snapshot_rev": receipt["page_rev"],
        "record": copy.deepcopy(receipt["record"]),
    }


def delete_result(collection_id: str, receipt: dict) -> dict:
    return {
        "collection_id": collection_id,
        "snapshot_rev": receipt["page_rev"],
        "record_id": receipt["record_id"],
        "rev": receipt["rev"],
        "deleted": receipt["deleted"],
    }


def query_result(collection_id: str, result: dict) -> dict:
    return {
        "collection_id": collection_id,
        "snapshot_rev": result["page_rev"],
        "records": copy.deepcopy(result["records"]),
        "count": result["count"],
        "next_cursor": result["next_cursor"],
    }

"""Map public record arguments/results without querying or reconstructing state."""

import copy

from folio.record_adapters import (
    definition_result,
    delete_result,
    query_bind,
    query_result,
    write_result,
)
from folio.record_models import RecordQueryRequest


def test_query_mapping_preserves_supplied_filter_sort_and_cursor():
    request = RecordQueryRequest.model_validate(
        {
            "collection_id": "discovery",
            "filter": [{"field": "kind", "op": "in", "value": ["interaction"]}],
            "sort": [{"field": "date", "direction": "desc"}],
            "limit": 10,
            "cursor": "cursor-from-store",
        }
    )
    assert query_bind(request) == {
        "collection": "discovery",
        "all": [{"field": "kind", "op": "in", "value": ["interaction"]}],
        "sort": [{"field": "date", "direction": "desc"}],
        "limit": 10,
        "cursor": "cursor-from-store",
    }
    assert "cursor" not in query_bind(RecordQueryRequest(collection_id="discovery"))


def test_write_result_uses_the_original_committed_record_and_page_revision():
    receipt = {
        "page_rev": 4,
        "record_id": "generated-1",
        "rev": 2,
        "record": {"id": "generated-1", "rev": 2, "value": {"status": "contacted"}},
        "audit_id": "internal",
        "transaction_id": "internal",
    }
    assert write_result("discovery", receipt) == {
        "collection_id": "discovery",
        "snapshot_rev": 4,
        "record": receipt["record"],
    }
    result = write_result("discovery", receipt)
    result["record"]["value"]["status"] = "changed by caller"
    assert receipt["record"]["value"]["status"] == "contacted"


def test_delete_result_keeps_the_committed_tombstone_and_no_internal_receipt_fields():
    receipt = {
        "page_rev": 5,
        "record_id": "generated-1",
        "rev": 3,
        "deleted": True,
        "audit_id": "internal",
    }
    assert delete_result("discovery", receipt) == {
        "collection_id": "discovery",
        "snapshot_rev": 5,
        "record_id": "generated-1",
        "rev": 3,
        "deleted": True,
    }


def test_query_count_is_all_authorized_matches_not_number_of_rows_in_this_page():
    query = {
        "page_rev": 8,
        "records": [{"id": "r", "rev": 1, "value": {"status": "read"}}],
        "count": 125,
        "next_cursor": "next-page",
    }
    before = copy.deepcopy(query)
    assert query_result("discovery", query) == {
        "collection_id": "discovery",
        "snapshot_rev": 8,
        "records": query["records"],
        "count": 125,
        "next_cursor": "next-page",
    }
    assert query == before


def test_definition_returns_collection_metadata_without_a_synthetic_document():
    assert definition_result("discovery", {"page_rev": 1}) == {
        "collection_id": "discovery",
        "schema_version": 1,
        "snapshot_rev": 1,
    }

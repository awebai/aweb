"""Folio's first typed table and trusted, whole-record domain validation."""

import copy

import pytest
from aweb_naapp.page_store import Scope, StoreError
from aweb_naapp.pages import inline_value_valid, validate_page

from folio.record_collections import (
    DISCOVERY_SCHEMA,
    DISCOVERY_TITLE,
    build_collection_page,
    validate_record,
)

SCOPE = Scope("installation-1", "team:example.test", "folio", "discovery")
VALUE = {
    "source_url": "https://example.test/research?topic=pages",
    "date": "2024-02-29",
    "finding": "A useful discussion",
    "why_relevant": "People already exchange these records",
    "status": "read; no contact yet",
    "kind": "awareness",
}
DEFINITION = {"id": "discovery", "schema": DISCOVERY_SCHEMA}


def test_discovery_has_the_agreed_fields_without_workflow_states():
    assert set(DISCOVERY_SCHEMA["properties"]) == {
        "source_url", "date", "finding", "why_relevant", "possible_contribution",
        "status", "next_follow_up", "kind",
    }
    assert inline_value_valid(DISCOVERY_SCHEMA, VALUE)
    assert inline_value_valid(DISCOVERY_SCHEMA, {**VALUE, "status": "an unfamiliar recorded fact"})
    assert inline_value_valid(DISCOVERY_SCHEMA, {
        **VALUE, "possible_contribution": "", "next_follow_up": "", "kind": "interaction",
    })
    for field in DISCOVERY_SCHEMA["required"]:
        missing = {key: value for key, value in VALUE.items() if key != field}
        assert not inline_value_valid(DISCOVERY_SCHEMA, missing), field
    assert not inline_value_valid(DISCOVERY_SCHEMA, {**VALUE, "approval": True})
    assert not inline_value_valid(DISCOVERY_SCHEMA, {**VALUE, "kind": "queue"})


def test_discovery_builds_a_valid_shared_read_only_table_without_row_copies():
    schema_before = copy.deepcopy(DISCOVERY_SCHEMA)
    page = build_collection_page(
        page_id="discovery", collection_id="discovery", title=DISCOVERY_TITLE,
        schema=DISCOVERY_SCHEMA, owner="did:key:creator",
    )
    result = validate_page(page)
    assert result.valid, result.errors
    assert page["title"] == "Discoveries and conversations"
    assert page["actions"] == []
    assert page["collections"][0]["records"] == []
    table = next(widget for widget in page["layout"] if widget["type"] == "table")
    assert table["bind"]["collection"] == "discovery"
    assert {column["field"] for column in table["props"]["columns"]} == set(schema_before["properties"])
    assert not table["props"].get("row_actions")
    page["collections"][0]["schema"]["properties"]["status"]["title"] = "Modified"
    assert DISCOVERY_SCHEMA == schema_before


@pytest.mark.parametrize("value", [
    VALUE,
    {**VALUE, "date": "2026-10-21", "source_url": "http://example.test/source"},
    {**VALUE, "possible_contribution": "", "next_follow_up": ""},
])
def test_trusted_validator_accepts_real_dates_and_safe_web_sources_without_mutation(value):
    record = {"id": "row-1", "rev": 7, "value": copy.deepcopy(value)}
    before = copy.deepcopy(record)
    validate_record(SCOPE, DEFINITION, record)
    assert record == before


@pytest.mark.parametrize("date", ["2026-02-29", "2026-04-31", "2026-13-01", "20261021", "2026-1-01"])
def test_trusted_validator_rejects_impossible_or_noncanonical_calendar_dates(date):
    # C1 format is an annotation: Folio adds its domain validation without changing C1.
    with pytest.raises(StoreError) as error:
        validate_record(SCOPE, DEFINITION, {"id": "r", "rev": 1, "value": {**VALUE, "date": date}})
    assert error.value.code == "schema_invalid"
    assert any(detail["pointer"].endswith("/value/date") for detail in error.value.details)


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "data:text/html,hello", "//example.test/source",
    "https://user:password@example.test/source", "https://user@example.test/",
    "https://example.test\\@evil.test/", " https://example.test/", "https://example.test/\n",
    "https://example.test:invalid/", "https:///missing-host",
])
def test_trusted_validator_refuses_unsafe_sources_and_embedded_credentials(url):
    with pytest.raises(StoreError) as error:
        validate_record(SCOPE, DEFINITION, {"id": "r", "rev": 1, "value": {**VALUE, "source_url": url}})
    assert error.value.code == "schema_invalid"
    assert any(detail["pointer"].endswith("/value/source_url") for detail in error.value.details)


@pytest.mark.parametrize("schema", [
    {"type": "object", "properties": None},
    {"type": "string", "maxLength": 100},
    {"type": "object", "properties": {"status": {"$ref": "https://example.test/schema"}}},
])
def test_collection_definition_refuses_invalid_or_non_object_record_schemas(schema):
    with pytest.raises(StoreError) as error:
        build_collection_page(page_id="table-1", collection_id="notes", title="Notes",
                              schema=schema, owner="did:key:creator")
    assert error.value.code == "schema_invalid"

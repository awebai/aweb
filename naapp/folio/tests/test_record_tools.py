"""The CLI/MCP manifest contract carries partial writes and explicit CAS."""

import pytest
from aweb_naapp.manifest import canonical_bytes, load_manifest
from jsonschema import Draft202012Validator
from manifest_config import served_manifest

from folio.record_tools import RECORD_TOOLS


def _tool(name):
    return next(tool for tool in RECORD_TOOLS if tool["name"] == name)


def test_records_manifest_is_accepted_by_the_shared_reader_and_binds_every_body_argument():
    manifest = served_manifest("https://folio.aweb.ai")
    parsed = load_manifest(canonical_bytes(manifest))
    assert set(parsed.tools_by_name()) >= {
        "collection-define", "record-add", "record-update", "record-delete", "record-query",
    }
    for tool in RECORD_TOOLS:
        assert tool["method"] == "POST"
        assert {param["name"] for param in tool["params"]} == set(tool["input_schema"]["properties"])
        assert {param["in"] for param in tool["params"]} == {"body"}
        assert tool["mutation"] == (tool["name"] != "record-query")
        assert tool["scopes"] == ["folio:read" if tool["name"] == "record-query" else "folio:write"]


def test_add_schema_permits_the_server_to_allocate_an_id_and_accepts_structured_values():
    schema = _tool("record-add")["input_schema"]
    validator = Draft202012Validator(schema)
    assert validator.is_valid({"collection_id": "discovery", "request_id": "add-1",
                               "values": {"status": "read", "kind": "awareness"}})
    assert not validator.is_valid({"collection_id": "discovery", "request_id": "add-1",
                                   "values": {"status": "read"}, "team_id": "other"})


@pytest.mark.parametrize("name", ["record-update", "record-delete"])
def test_conditional_write_schema_requires_revision_and_request_id(name):
    validator = Draft202012Validator(_tool(name)["input_schema"])
    body = {"collection_id": "discovery", "record_id": "r", "expected_rev": 1, "request_id": "op-1"}
    if name == "record-update":
        body["patch"] = {"status": "contacted"}
    assert validator.is_valid(body)
    assert not validator.is_valid({key: value for key, value in body.items() if key != "expected_rev"})
    assert not validator.is_valid({**body, "expected_rev": 0})
    assert not validator.is_valid({**body, "request_id": ""})


def test_query_schema_limits_filters_sort_and_each_page_without_a_write_key():
    validator = Draft202012Validator(_tool("record-query")["input_schema"])
    query = {"collection_id": "discovery", "filter": [{"field": "kind", "op": "eq", "value": "interaction"}],
             "sort": [{"field": "date", "direction": "desc"}], "limit": 200}
    assert validator.is_valid(query)
    assert not validator.is_valid({**query, "limit": 201})
    assert not validator.is_valid({**query, "filter": query["filter"] * 21})

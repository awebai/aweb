"""The callable record contract: partial writes, explicit revisions and bounded queries."""

import pytest
from pydantic import ValidationError

from folio.record_models import (
    CollectionDefineRequest,
    RecordAddRequest,
    RecordDeleteRequest,
    RecordQueryRequest,
    RecordUpdateRequest,
)


def test_add_accepts_a_server_generated_id_or_a_callers_stable_id():
    payload = {"collection_id": "awareness", "request_id": "add-1", "values": {"status": "found"}}
    generated = RecordAddRequest.model_validate(payload)
    assert generated.record_id is None
    assert generated.values == {"status": "found"}
    supplied = RecordAddRequest.model_validate({**payload, "record_id": "source-hash"})
    assert supplied.record_id == "source-hash"


def test_update_preserves_a_field_patch_without_inventing_unsupplied_fields():
    request = RecordUpdateRequest.model_validate({
        "collection_id": "awareness", "record_id": "row-1", "expected_rev": 4,
        "request_id": "edit-1", "patch": {"status": "contacted"},
    })
    assert request.patch == {"status": "contacted"}
    assert request.expected_rev == 4
    # Status describes recorded facts; an unfamiliar status remains valid data.
    assert RecordUpdateRequest.model_validate({
        **request.model_dump(), "patch": {"status": "waiting for a reply"},
    }).patch == {"status": "waiting for a reply"}


@pytest.mark.parametrize("model", [RecordUpdateRequest, RecordDeleteRequest])
@pytest.mark.parametrize("revision", [None, 0, -1, True, "1"])
def test_conditional_writes_require_a_positive_integer_revision(model, revision):
    body = {"collection_id": "awareness", "record_id": "row-1", "request_id": "change-1"}
    if model is RecordUpdateRequest:
        body["patch"] = {"status": "noted"}
    if revision is not None:
        body["expected_rev"] = revision
    with pytest.raises(ValidationError):
        model.model_validate(body)


@pytest.mark.parametrize("changes", [
    {"patch": {}}, {"request_id": ""}, {"team_id": "other:example.test"},
    {"principal": {"did_key": "invented"}},
])
def test_update_refuses_an_empty_write_or_caller_supplied_authority(changes):
    with pytest.raises(ValidationError):
        RecordUpdateRequest.model_validate({
            "collection_id": "awareness", "record_id": "row-1", "expected_rev": 1,
            "request_id": "edit-1", "patch": {"status": "noted"}, **changes,
        })


def test_query_accepts_typed_filters_sorts_and_an_opaque_cursor():
    request = RecordQueryRequest.model_validate({
        "collection_id": "awareness",
        "filter": [{"field": "status", "op": "eq", "value": "contacted"},
                   {"field": "kind", "op": "in", "value": ["awareness", "interaction"]}],
        "sort": [{"field": "date", "direction": "desc"}], "cursor": "opaque-cursor",
    })
    assert request.limit == 50
    assert request.filter[1].value == ["awareness", "interaction"]
    assert request.sort[0].direction == "desc"
    assert request.cursor == "opaque-cursor"


@pytest.mark.parametrize("changes", [
    {"limit": 0}, {"limit": 201},
    {"filter": [{"field": "status", "op": "eq", "value": "found"}] * 21},
    {"sort": [{"field": "date", "direction": "asc"}] * 9},
    {"filter": [{"field": "status", "op": "sql", "value": "anything"}]},
    {"sort": [{"field": "date", "direction": "arbitrary"}]},
])
def test_query_rejects_out_of_bound_or_undeclared_query_operations(changes):
    with pytest.raises(ValidationError):
        RecordQueryRequest.model_validate({"collection_id": "awareness", **changes})


def test_define_retains_the_supplied_typed_schema():
    schema = {"type": "object", "properties": {"status": {"type": "string", "maxLength": 160}},
              "required": ["status"], "additionalProperties": False}
    request = CollectionDefineRequest.model_validate({
        "collection_id": "awareness", "title": "Awareness", "schema": schema,
        "request_id": "define-1",
    })
    assert request.record_schema == schema
    assert request.model_dump(by_alias=True)["schema"] == schema


@pytest.mark.parametrize("predicate", [
    {"field": "kind", "op": "in", "value": ["awareness"] * 51},
    {"field": "status", "op": "eq", "value": ["read"]},
    {"field": "kind", "op": "in", "value": "awareness"},
    {"field": "amount", "op": "eq", "value": float("nan")},
])
def test_filter_operands_stay_within_the_shared_query_contract(predicate):
    with pytest.raises(ValidationError):
        RecordQueryRequest.model_validate({"collection_id": "discovery", "filter": [predicate]})

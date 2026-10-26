"""Only displayed fields may cross the document-link boundary."""

import json

import pytest
from test_record_host import linked, listener
from test_widget_authorization import authors, signed, table_body
from test_widget_records_session import mint, with_table

__all__ = ["authors", "linked", "listener"]


@pytest.mark.parametrize("editable", [False, True])
@pytest.mark.parametrize("filtered", [False, True])
async def test_widget_fields_bound_query_schema_snapshot_and_receipt(authors, editable, filtered):
    world, row = await with_table(authors, body=table_body())
    body = table_body()
    if filtered:
        excluded = await signed(
            world,
            world.member,
            "POST",
            "/v1/records/add",
            payload={
                "collection_id": "discovery",
                "values": {**row["value"], "why_relevant": "excluded-row"},
                "request_id": "excluded-filter-control",
            },
        )
        assert excluded.status_code == 200
        # A saved, author-authorized predicate may use a non-displayed field.
        body = body.replace(
            '"limit": 20',
            '"limit": 20, "all": [{"field":"why_relevant","op":"eq","value":'
            + json.dumps(row["value"]["why_relevant"])
            + "}]",
        )
        saved = await signed(
            world, world.member, "POST", "/v1/documents/ordinary/versions", body=body
        )
        assert saved.status_code == 200, saved.text
    _, path, headers, opened = await mint(world, editable=editable)
    query = await world.client.get(path + "/widgets/research/records", headers=headers)
    assert query.status_code == 200, query.text
    expected = {key: row["value"][key] for key in ("finding", "status")}
    assert query.json()["count"] == 1
    assert query.json()["records"][0]["value"] == expected
    if not editable:
        response = await world.client.get(path + "/widgets")
        assert response.status_code == 200
        opened = response.json()
    table = opened["widgets"]["research"]
    assert table["query"]["records"][0]["value"] == expected
    collection = table["page"]["collections"][0]
    assert set(collection["schema"]["properties"]) == {"finding", "status"}
    assert set(collection["schema"].get("required", [])) <= {"finding", "status"}
    assert collection["records"][0]["value"] == expected
    assert "why_relevant" not in json.dumps(table["page"])
    if editable:
        updated = await world.client.post(
            path + "/widgets/research/records/update",
            headers=headers,
            json={
                "record_id": row["id"],
                "expected_rev": 1,
                "patch": {"status": "changed"},
                "request_id": "projected-receipt",
            },
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["record"]["value"] == {**expected, "status": "changed"}
        forbidden = await world.client.post(
            path + "/widgets/research/records/update",
            headers=headers,
            json={
                "record_id": row["id"],
                "expected_rev": 2,
                "patch": {"why_relevant": "hidden"},
                "request_id": "hidden-write",
            },
        )
        assert forbidden.status_code == 403

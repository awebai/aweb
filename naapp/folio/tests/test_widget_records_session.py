"""Session row routes share records with signed agents and keep link provenance."""

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from test_record_collections import VALUE
from test_record_host import linked, listener
from test_widget_authorization import authors, signed, table_body

from folio.record_collections import DISCOVERY_SCHEMA

__all__ = ["authors", "linked", "listener"]
HEADER = "X-Folio-Edit-Session"


async def mint(world, *, editable=True):
    response = await signed(
        world,
        world.member,
        "POST",
        "/v1/present",
        payload={
            "slug": "ordinary",
            "editable": editable,
        },
    )
    assert response.status_code == 200, response.text
    link = response.json()
    parts = urlsplit(link["url"])
    if not editable:
        return link, parts.path, {}, None
    opened = await world.client.post(
        parts.path + "/session",
        json={
            "opener": parse_qs(parts.fragment)["k"][0],
        },
    )
    assert opened.status_code == 200, opened.text
    return link, parts.path, {HEADER: opened.json()["session_secret"]}, opened.json()


def full_table_body():
    definition = json.loads(table_body().split(":::widget\n")[1].split("\n:::")[0])
    definition["props"]["columns"] = [
        {"field": field, "label": field, "format": "text"}
        for field in DISCOVERY_SCHEMA["properties"]
    ]
    return "Before\n\n:::widget\n" + json.dumps(definition) + "\n:::\n\nAfter"


async def with_table(authors, *, body=None):
    world, _, _, _ = authors
    saved = await signed(
        world,
        world.member,
        "POST",
        "/v1/documents/ordinary/versions",
        body=body or full_table_body(),
    )
    assert saved.status_code == 200, saved.text
    added = await signed(
        world,
        world.member,
        "POST",
        "/v1/records/add",
        payload={
            "collection_id": "discovery",
            "values": VALUE,
            "request_id": "agent-add",
        },
    )
    assert added.status_code == 200, added.text
    return world, added.json()["record"]


async def test_initial_session_snapshot_and_queries_show_the_same_agent_rows(authors):
    world, row = await with_table(authors)
    _, path, headers, opened = await mint(world)
    table = opened["widgets"]["research"]
    assert table["state"] == "ready" and table["data_mode"] == "live"
    assert table["query"]["records"] == [row]
    assert table["edit"]["add"] and table["edit"]["delete"]
    assert "status" in table["edit"]["patch_fields"]
    assert [segment["kind"] for segment in opened["segments"]] == ["prose", "widget", "prose"]
    response = await world.client.get(path + "/widgets/research/records", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["records"] == [row]
    assert response.json()["count"] == 1


async def test_signed_agent_and_checked_session_race_use_one_row_revision_and_link_audit(authors):
    world, row = await with_table(authors)
    link, path, headers, _ = await mint(world)
    outcomes = await asyncio.gather(
        signed(
            world,
            world.member,
            "POST",
            "/v1/records/update",
            payload={
                "collection_id": "discovery",
                "record_id": row["id"],
                "expected_rev": 1,
                "patch": {"status": "agent"},
                "request_id": "agent-race",
            },
        ),
        world.client.post(
            path + "/widgets/research/records/update",
            headers=headers,
            json={
                "record_id": row["id"],
                "expected_rev": 1,
                "patch": {"status": "session"},
                "request_id": "session-race",
            },
        ),
    )
    assert sorted(response.status_code for response in outcomes) == [200, 409]
    loser = next(response for response in outcomes if response.status_code == 409)
    assert loser.json()["detail"]["code"] == "revision_conflict"
    # Commit a definite link-origin edit after the race, whichever participant won.
    updated = await world.client.post(
        path + "/widgets/research/records/update",
        headers=headers,
        json={
            "record_id": row["id"],
            "expected_rev": 2,
            "patch": {"status": "confirmed"},
            "request_id": "session-confirm",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["record"]["rev"] == 3
    evidence = await world.host.runtime.db().fetch_value(
        "SELECT evidence FROM {{tables.page_audit}} WHERE evidence->>'link_id'=$1 "
        "ORDER BY new_rev DESC LIMIT 1",
        link["token"],
    )
    evidence = json.loads(evidence) if isinstance(evidence, str) else evidence
    assert evidence["origin_kind"] == "link"
    assert evidence["creator_did_key"] == world.member.did_key
    assert evidence["session_id"] != headers[HEADER]
    assert len(evidence["session_id"]) == 36  # Public session row UUID, never bearer/hash.
    assert headers[HEADER] not in json.dumps(evidence)
    assert "signer_did" not in evidence


async def test_session_add_delete_retry_and_unknown_field_refusal(authors):
    world, _ = await with_table(authors)
    _, path, headers, _ = await mint(world)
    prefix = path + "/widgets/research/records/"
    payload = {"values": {**VALUE, "finding": "Human row"}, "request_id": "human-add"}
    first = await world.client.post(prefix + "add", headers=headers, json=payload)
    replay = await world.client.post(prefix + "add", headers=headers, json=payload)
    assert first.status_code == replay.status_code == 200
    assert replay.json() == first.json()
    row = first.json()["record"]
    injected = await world.client.post(
        prefix + "update",
        headers=headers,
        json={
            "collection_id": "other",
            "record_id": row["id"],
            "expected_rev": 1,
            "patch": {"status": "bad"},
            "request_id": "scope-injection",
        },
    )
    assert injected.status_code == 422
    deleted = await world.client.post(
        prefix + "delete",
        headers=headers,
        json={
            "record_id": row["id"],
            "expected_rev": 1,
            "request_id": "human-delete",
        },
    )
    assert deleted.status_code == 200 and deleted.json()["deleted"] is True
    queried = await world.client.get(path + "/widgets/research/records", headers=headers)
    assert row["id"] not in [record["id"] for record in queried.json()["records"]]


async def test_later_saved_table_is_live_readonly_until_a_new_edit_session(authors):
    world, _, _, _ = authors
    _, path, headers, _ = await mint(world)  # At mint, this ordinary document has no table.
    _, row = await with_table(authors)
    state = await world.client.get(path + "/state", headers=headers)
    assert state.status_code == 200, state.text
    table = state.json()["widgets"]["research"]
    assert table["state"] == "ready" and table["query"]["records"] == [row]
    assert table["edit"] == {
        "add": False,
        "patch_fields": [],
        "delete": False,
        "reopen_to_edit": True,
    }
    refused = await world.client.post(
        path + "/widgets/research/records/update",
        headers=headers,
        json={
            "record_id": row["id"],
            "expected_rev": 1,
            "patch": {"status": "bad"},
            "request_id": "no-grant",
        },
    )
    assert refused.status_code == 403
    _, _, _, fresh = await mint(world)
    assert "status" in fresh["widgets"]["research"]["edit"]["patch_fields"]


@pytest.mark.parametrize("editable", [True, False])
async def test_legacy_identity_never_yields_rows_counts_or_receipts(authors, editable):
    world, _ = await with_table(authors)
    link, path, headers, _ = await mint(world, editable=editable)
    # The migrated pre-records row has no stored canonical identity. No DID fallback.
    await world.host.runtime.db().execute(
        "UPDATE {{tables.presentation_links}} SET records_creator_id=NULL,record_write_grants='{}' WHERE token=$1",
        link["token"],
    )
    response = await world.client.get(
        path + ("/state" if editable else "/widgets"), headers=headers
    )
    assert response.status_code == 200, response.text
    table = response.json()["widgets"]["research"]
    assert table == {
        "state": "records_identity_required",
        "reopen": "edit" if editable else "new_link_from_sharer",
    }
    refused = await world.client.get(path + "/widgets/research/records", headers=headers)
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "records_identity_required"
    assert "count" not in refused.json() and "records" not in refused.json()
    if editable:
        # Prose remains editable while row authority is absent.
        state = response.json()
        saved = await world.client.post(
            path + "/edit",
            headers=headers,
            json={
                "body": state["body"].replace("Before", "Legacy prose still works"),
                "base_version": state["version_number"],
            },
        )
        assert saved.status_code == 200, saved.text
    else:
        assert (await world.client.get(path)).status_code == 200

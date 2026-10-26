"""Current link/session evidence and saved bindings bound every record operation."""

import asyncio

import httpx
import pytest
from aweb_naapp.page_store import Access
from test_record_host import linked, listener
from test_widget_authorization import authors, signed, table_body
from test_widget_records_session import HEADER, mint, with_table

__all__ = ["authors", "linked", "listener"]


@pytest.mark.parametrize("editable", [False, True])
async def test_revoke_refuses_query_and_receipt_replay(authors, editable):
    world, row = await with_table(authors)
    link, path, headers, _ = await mint(world, editable=editable)
    payload = {
        "record_id": row["id"],
        "expected_rev": 1,
        "patch": {"status": "saved"},
        "request_id": "revoke-replay",
    }
    if editable:
        assert (
            await world.client.post(
                path + "/widgets/research/records/update", headers=headers, json=payload
            )
        ).status_code == 200
    assert (
        await signed(world, world.member, "POST", "/v1/present/" + link["token"] + "/revoke")
    ).status_code == 200
    query = await world.client.get(path + "/widgets/research/records", headers=headers)
    assert query.status_code == 404 and '"records"' not in query.text
    assert (
        query.headers["Cache-Control"] == "no-store"
        and query.headers["Referrer-Policy"] == "no-referrer"
    )
    if editable:
        replay = await world.client.post(
            path + "/widgets/research/records/update", headers=headers, json=payload
        )
        assert replay.status_code == 404 and '"record"' not in replay.text


@pytest.mark.parametrize("outage", [False, True])
@pytest.mark.parametrize("editable", [False, True])
async def test_current_creator_membership_is_checked_on_every_read(authors, outage, editable):
    world, _ = await with_table(authors)
    _, path, headers, _ = await mint(world, editable=editable)
    if outage:

        def unavailable(request, response):
            raise httpx.ConnectError("synthetic AWID outage", request=request)

        world.registry.transport.fault = unavailable
    else:
        await world.registry.revoke(world.member.certificate_id)
    await asyncio.sleep(1.05)  # Let the real bounded AWID proof cache expire.
    query = await world.client.get(path + "/widgets/research/records", headers=headers)
    assert query.status_code in ((503,) if outage else (403, 404)), query.text
    assert '"records"' not in query.text and '"count"' not in query.text
    assert query.headers["Cache-Control"] == "no-store"


async def test_cursor_is_link_bound_and_saved_filter_stays_server_authoritative(authors):
    world, row = await with_table(authors, body=table_body().replace('"limit": 20', '"limit": 1'))
    added = await signed(
        world,
        world.member,
        "POST",
        "/v1/records/add",
        payload={"collection_id": "discovery", "values": row["value"], "request_id": "second-row"},
    )
    assert added.status_code == 200
    _, path, headers, _ = await mint(world)
    _, other, other_headers, _ = await mint(world)
    first = await world.client.get(path + "/widgets/research/records", headers=headers)
    cursor = first.json()["next_cursor"]
    assert first.json()["count"] == 2 and cursor
    own = await world.client.get(
        path + "/widgets/research/records", headers=headers, params={"cursor": cursor}
    )
    assert own.status_code == 200 and own.json()["count"] == 2
    borrowed = await world.client.get(
        other + "/widgets/research/records", headers=other_headers, params={"cursor": cursor}
    )
    assert borrowed.status_code == 409 and borrowed.json()["detail"]["code"] == "cursor_invalid"
    cross_session = await world.client.get(other + "/widgets/research/records", headers=headers)
    assert cross_session.status_code == 404
    assert headers[HEADER] not in cross_session.text


async def test_current_acl_projects_receipt_replay_and_refuses_hidden_fields(authors):
    world, author, scope, _ = authors
    _, row = await with_table(authors, body=table_body("allowed"))
    owner = world.member
    world.member = author
    try:
        _, path, headers, _ = await mint(world)
    finally:
        world.member = owner
    payload = {
        "record_id": row["id"],
        "expected_rev": 1,
        "patch": {"finding": "kept"},
        "request_id": "projected-replay",
    }
    written = await world.client.post(
        path + "/widgets/research/records/update", headers=headers, json=payload
    )
    assert written.status_code == 200
    current = await signed(
        world, owner, "POST", "/v1/records/query", payload={"collection_id": "discovery"}
    )
    await world.host.storage.require_store().change_access(
        scope,
        world.authorization.principal,
        expected_rev=current.json()["snapshot_rev"],
        key="narrow-minter",
        access=Access(
            owner=owner.did_key,
            team_id=owner.team_id,
            team_read=True,
            team_write=True,
            fields={author.did_key: {"discovery": {"finding"}}},
        ),
    )
    replay = await world.client.post(
        path + "/widgets/research/records/update", headers=headers, json=payload
    )
    assert replay.status_code == 200 and replay.json()["record"]["value"] == {"finding": "kept"}
    hidden = await world.client.post(
        path + "/widgets/research/records/update",
        headers=headers,
        json={**payload, "expected_rev": 2, "request_id": "hidden", "patch": {"status": "secret"}},
    )
    assert hidden.status_code == 403 and "secret" not in hidden.text
    query = await world.client.get(path + "/widgets/research/records", headers=headers)
    assert query.status_code == 200 and query.json()["records"][0]["value"] == {"finding": "kept"}


async def test_saved_collection_change_is_live_readonly_until_fresh_mint(authors):
    from folio.record_collections import DISCOVERY_SCHEMA

    world, row = await with_table(authors)
    _, path, headers, _ = await mint(world)
    defined = await signed(
        world,
        world.member,
        "POST",
        "/v1/collections",
        payload={
            "collection_id": "other",
            "title": "Other",
            "schema": DISCOVERY_SCHEMA,
            "request_id": "other-define",
        },
    )
    assert defined.status_code == 200
    added = await signed(
        world,
        world.member,
        "POST",
        "/v1/records/add",
        payload={
            "collection_id": "other",
            "values": {**row["value"], "finding": "Other collection"},
            "request_id": "other-add",
        },
    )
    assert added.status_code == 200
    from test_widget_records_session import full_table_body

    saved = await signed(
        world,
        world.member,
        "POST",
        "/v1/documents/ordinary/versions",
        body=full_table_body().replace('"collection": "discovery"', '"collection": "other"'),
    )
    assert saved.status_code == 200
    state = await world.client.get(path + "/state", headers=headers)
    table = state.json()["widgets"]["research"]
    assert table["query"]["records"] == [added.json()["record"]]
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
            "record_id": added.json()["record"]["id"],
            "expected_rev": 1,
            "patch": {"status": "refused"},
            "request_id": "rebind",
        },
    )
    assert refused.status_code == 403
    _, _, _, fresh = await mint(world)
    assert fresh["widgets"]["research"]["edit"]["add"]


async def test_new_displayed_field_does_not_expand_old_sessions_write_grant(authors):
    world, row = await with_table(authors, body=table_body("allowed"))
    _, path, headers, _ = await mint(world)
    saved = await signed(
        world, world.member, "POST", "/v1/documents/ordinary/versions", body=table_body()
    )
    assert saved.status_code == 200
    state = await world.client.get(path + "/state", headers=headers)
    table = state.json()["widgets"]["research"]
    assert set(table["query"]["records"][0]["value"]) == {"finding", "status"}
    assert table["edit"]["patch_fields"] == ["finding"] and table["edit"]["reopen_to_edit"]
    refused = await world.client.post(
        path + "/widgets/research/records/update",
        headers=headers,
        json={
            "record_id": row["id"],
            "expected_rev": 1,
            "patch": {"status": "refused"},
            "request_id": "new-field",
        },
    )
    assert refused.status_code == 403


async def test_consumed_opener_deadline_is_not_a_session_lifetime(authors):
    world, _ = await with_table(authors)
    link, path, headers, _ = await mint(world)
    await world.host.runtime.db().execute(
        "UPDATE {{tables.presentation_links}} SET expires_at=NOW()-interval '1 hour' WHERE token=$1",
        link["token"],
    )
    query = await world.client.get(path + "/widgets/research/records", headers=headers)
    assert query.status_code == 200 and query.json()["count"] == 1

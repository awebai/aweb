"""Member/live-link queries share ACL-before-query SQL and bounded cursors."""

import pytest
from asyncpg.exceptions import LockNotAvailableError

from aweb_naapp.page_store import Access, StoreError
from tests.page_store.test_projection import selection as named_selection
from tests.page_store.test_store import OWNER, READER, SCOPE, create, page


def selection(*, ids=("row-000",), fields=("label", "checked")):
    result = named_selection(ids=() if ids == "*" else ids, fields=fields)
    if ids == "*":
        result["collections"][0]["record_ids"] = "*"
    return result


def table(rows=2):
    document = page()
    document["collections"][0]["records"] = [
        {"id": f"row-{i:03}", "rev": 1, "value": {"label": "match", "checked": False}}
        for i in range(rows)
    ]
    return document


async def linked(store, *, creator=OWNER, link_id="lnk-a", projection=None, bind=None, **kw):
    async with store.db.transaction() as tx:
        return await store.query_widget_on(
            tx,
            SCOPE,
            creator_id=creator.did_key,
            widget_id="items",
            bind=bind or {"collection": "items"},
            link_id=link_id,
            projection=projection if projection is not None else selection(ids="*"),
            **kw,
        )


async def test_member_query_uses_the_current_revision_and_preserves_renderer_precondition(store):
    await create(store)
    result = await store.query_widget(SCOPE, OWNER, widget_id="items", bind={"collection": "items"})
    assert result["page_rev"] == 1 and result["count"] == 1
    with pytest.raises(StoreError, match="precondition_required"):
        await store.read_widget(
            SCOPE, OWNER, widget_id="items", expected_page_rev=None, bind={"collection": "items"}
        )


async def test_projection_hides_matching_rows_before_count_and_cursor_decisions(store):
    await create(store, table())
    projection = selection(ids=("row-000",))
    result = await linked(
        store,
        projection=projection,
        bind={
            "collection": "items",
            "limit": 1,
            "all": [{"field": "label", "op": "eq", "value": "match"}],
        },
    )
    assert result["count"] == 1 and result["next_cursor"] is None
    assert [r["id"] for r in result["records"]] == ["row-000"]
    empty = await linked(store, projection=selection(ids=()))
    assert empty["count"] == 0 and empty["records"] == [] and empty["next_cursor"] is None


async def test_link_cursor_cannot_cross_links_or_projection_or_creator(store):
    await create(store, table(3))
    first = await linked(store, bind={"collection": "items", "limit": 1})
    bind = {"collection": "items", "limit": 1, "cursor": first["next_cursor"]}
    second = await linked(store, bind=bind)
    assert second["count"] == 3 and second["records"][0]["id"] == "row-001"
    for kwargs in (
        {"link_id": "lnk-b"},
        {"projection": selection(ids=("row-000", "row-001"))},
        {"creator": READER},
    ):
        with pytest.raises(StoreError, match="cursor_invalid"):
            await linked(store, bind=bind, **kwargs)


async def test_live_marker_includes_new_rows_beyond_200_and_restarts_stale_cursors(store):
    await create(store, table(200))
    await store.add_record(
        SCOPE,
        OWNER,
        collection="items",
        record_id="row-200",
        values={"label": "match", "checked": False},
        key="add-200",
    )
    first = await linked(store)
    assert first["count"] == 201 and len(first["records"]) == 200
    await store.add_record(
        SCOPE,
        OWNER,
        collection="items",
        record_id="row-201",
        values={"label": "match", "checked": False},
        key="add-201",
    )
    with pytest.raises(StoreError, match="cursor_invalid"):
        await linked(store, bind={"collection": "items", "cursor": first["next_cursor"]})
    fresh = await linked(store)
    last = await linked(store, bind={"collection": "items", "cursor": fresh["next_cursor"]})
    assert fresh["count"] == last["count"] == 202
    assert (
        len(fresh["records"]) == 200 and len(last["records"]) == 2 and last["next_cursor"] is None
    )
    assert last["records"][-1]["id"] == "row-201"


async def test_current_creator_acl_narrows_live_fields_rows_and_page_access(store):
    await create(store, table())
    await store.change_access(
        SCOPE,
        OWNER,
        expected_rev=1,
        key="narrow",
        access=Access(
            owner=OWNER.did_key,
            readers={READER.did_key},
            hidden_rows={READER.did_key: {"items": {"row-001"}}},
            fields={READER.did_key: {"items": {"label"}}},
        ),
    )
    result = await linked(store, creator=READER)
    assert result["count"] == 1 and result["records"][0]["value"] == {"label": "match"}
    with pytest.raises(StoreError, match="query_denied"):
        await linked(
            store,
            creator=READER,
            bind={"collection": "items", "sort": [{"field": "checked", "direction": "asc"}]},
        )
    await store.request_delete(SCOPE, OWNER, expected_rev=2, key="delete")
    with pytest.raises(StoreError, match="resource_not_found"):
        await linked(store, creator=READER)


async def test_checked_link_requires_projection_and_holds_the_caller_lock(store):
    await create(store, table())
    async with store.db.transaction() as tx:
        with pytest.raises(StoreError, match="schema_invalid"):
            await store.query_widget_on(
                tx,
                SCOPE,
                creator_id=OWNER.did_key,
                widget_id="items",
                bind={"collection": "items"},
                link_id="lnk-a",
            )
        await store.query_widget_on(
            tx,
            SCOPE,
            creator_id=OWNER.did_key,
            widget_id="items",
            bind={"collection": "items"},
            link_id="lnk-a",
            projection=selection(ids="*"),
        )
        with pytest.raises(LockNotAvailableError):
            async with store.db.transaction() as writer:
                await writer.execute("SET LOCAL lock_timeout='100ms'")
                await writer.execute(
                    "UPDATE {{tables.pages}} SET access=access WHERE scope=$1", SCOPE.key
                )


@pytest.mark.parametrize("tx_kind", ["database", "missing"])
async def test_checked_link_query_refuses_a_database_manager_or_missing_transaction(store, tx_kind):
    with pytest.raises(TypeError, match="TransactionManager"):
        await store.query_widget_on(
            store.db if tx_kind == "database" else None,
            SCOPE,
            creator_id=OWNER.did_key,
            widget_id="items",
            bind={"collection": "items"},
            link_id="lnk-a",
            projection=selection(ids="*"),
        )


async def test_dynamic_rows_never_reach_bounded_capture_and_empty_named_rows_stay_empty(store):
    await create(store)
    async with store.db.transaction() as tx:
        for api in (store.read_projection_on, store.capture_link_snapshot_on):
            with pytest.raises(StoreError, match="schema_invalid"):
                await api(
                    tx,
                    SCOPE,
                    creator_id=OWNER.did_key,
                    projection=selection(ids="*"),
                    **(
                        {"allowed_action_ids": [], "expected_page_rev": 1}
                        if api == store.capture_link_snapshot_on
                        else {}
                    ),
                )
        captured = await store.capture_link_snapshot_on(
            tx,
            SCOPE,
            creator_id=OWNER.did_key,
            projection=selection(ids=()),
            allowed_action_ids=[],
            expected_page_rev=1,
        )
        assert captured["collections"][0]["records"] == []

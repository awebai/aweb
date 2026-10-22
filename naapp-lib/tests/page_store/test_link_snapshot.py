"""Complete pinned pages use real PageStore writes and the shared redactor."""

from __future__ import annotations

import copy

import pytest
from asyncpg.exceptions import LockNotAvailableError

from aweb_naapp.page_store import Access, StoreError
from aweb_naapp.pages import validate_page
from tests.page_store.test_projection import selection
from tests.page_store.test_store import OWNER, READER, SCOPE, create, page, record_change


def linked_page():
    document = page()
    # Future widget props are arbitrary JSON and must stay inert, including
    # names that resemble known widget callbacks.
    document["layout"][1]["type"] = "unknown"
    document["layout"][1]["props"] = {"action": {"untrusted": "inert"}, "actions": 42}
    collection = document["collections"][0]
    collection["schema"]["properties"]["private"] = {"type": "string"}
    collection["schema"].update(
        default={"private": "private-sentinel"}, examples=[{"private": "private-sentinel"}]
    )
    collection["records"][0]["value"]["private"] = "private-sentinel"
    document["layout"] += [
        {"id": "future-empty", "type": "future_empty", "fallback": "Needs a newer renderer"},
        {"id": "heading", "type": "heading", "props": {"text": "Original heading", "level": 1}},
        {"id": "check-button", "type": "button", "props": {"label": "Check", "action": "check"}},
        {
            "id": "request-button",
            "type": "button",
            "props": {"label": "Request", "action": "request-restock"},
        },
        {
            "id": "photo",
            "type": "image",
            "props": {"asset_id": "asset-photo", "alt": "Original photo"},
        },
        {
            "id": "excluded-photo",
            "type": "image",
            "props": {"asset_id": "asset-private", "alt": "Private photo"},
        },
    ]
    document["widget_state"] = {
        "items": {"message": "Original state"},
        "request-button": {"message": "Excluded action state"},
        "excluded-photo": {"message": "Private media state"},
    }
    return document


async def capture(store, *, creator_id=OWNER.did_key, projection=None, actions=("check",), **kw):
    async with store.db.transaction() as tx:
        return await store.capture_link_snapshot_on(
            tx,
            SCOPE,
            creator_id=creator_id,
            projection=projection
            if projection is not None
            else {**selection(), "assets": ["asset-photo"]},
            allowed_action_ids=actions,
            expected_page_rev=1,
            **kw,
        )


async def narrow(store, source, *, creator_id=OWNER.did_key, projection=None, actions=("check",)):
    async with store.db.transaction() as tx:
        return await store.project_link_snapshot_on(
            tx,
            SCOPE,
            creator_id=creator_id,
            projection=projection
            if projection is not None
            else {**selection(), "assets": ["asset-photo"]},
            allowed_action_ids=actions,
            source_snapshot=source,
        )


async def test_capture_keeps_a_bounded_valid_complete_page_without_excluded_content(store):
    await create(store, linked_page())
    result = await capture(store)
    assert validate_page(result).valid
    assert result["rev"] == result["layout_version"] == 1
    assert result["collections"][0]["mode"] == "owned"
    assert result["collections"][0]["records"] == [
        {"id": "item-1", "rev": 1, "value": {"label": "Verify fixture inventory", "checked": False}}
    ]
    assert "private-sentinel" not in repr(result)
    assert [a["id"] for a in result["actions"]] == ["check"]
    by_id = {w["id"]: w for w in result["layout"]}
    assert by_id["items"]["props"]["row_actions"] == ["check"]
    assert by_id["photo"]["props"]["asset_id"] == "asset-photo"
    for wid in ("request-button", "excluded-photo", "future", "future-empty"):
        assert by_id[wid]["type"] == "access_unavailable"
        assert by_id[wid]["props"] == {}
        assert wid not in result["widget_state"]
    assert result["widget_state"]["items"] == {"message": "Original state"}


async def test_pinned_whole_page_survives_record_layout_and_state_edits(store):
    await create(store, linked_page())
    source = await capture(store)
    frozen = copy.deepcopy(source)
    await store.mutate(
        SCOPE,
        OWNER,
        expected_rev=1,
        key="current-record-state",
        records=[record_change()],
        state={"items": {"message": "New state"}},
    )
    layout = copy.deepcopy(linked_page()["layout"])
    next(w for w in layout if w["id"] == "heading")["props"]["text"] = "New heading"
    await store.append_layout(
        SCOPE,
        OWNER,
        expected_rev=2,
        key="current-layout",
        layout=layout,
        title="New page title",
        locale="es",
    )
    result = await narrow(store, source, actions=("check", "request-restock"))
    assert result == frozen  # wider current action authority cannot add the uncaptured action
    assert source == frozen
    assert (await store.read(SCOPE, OWNER))["rev"] == 3


async def test_current_acl_action_and_asset_loss_only_narrows_stored_page(store):
    await create(store, linked_page())
    source = await capture(store, creator_id=READER.did_key, actions=("request-restock",))
    await store.change_access(
        SCOPE,
        OWNER,
        expected_rev=1,
        key="restrict-reader",
        access=Access(
            owner=OWNER.did_key,
            readers={READER.did_key},
            fields={READER.did_key: {"items": {"label"}}},
        ),
    )
    result = await narrow(
        store, source, creator_id=READER.did_key, projection=selection(), actions=()
    )
    assert result["rev"] == 1 and result["actions"] == []
    assert result["collections"][0]["records"][0]["value"] == {"label": "Verify fixture inventory"}
    by_id = {w["id"]: w for w in result["layout"]}
    for wid in ("items", "photo", "request-button"):
        assert by_id[wid]["type"] == "access_unavailable"
        assert wid not in result["widget_state"]
    assert by_id["heading"]["props"]["text"] == "Original heading"
    assert validate_page(result).valid
    await store.change_access(
        SCOPE, OWNER, expected_rev=2, key="remove-reader", access=Access(owner=OWNER.did_key)
    )
    with pytest.raises(StoreError, match="resource_not_found"):
        await narrow(store, source, creator_id=READER.did_key)
    await store.request_delete(SCOPE, OWNER, expected_rev=3, key="delete")
    with pytest.raises(StoreError, match="resource_not_found"):
        await narrow(store, source)


async def test_empty_projection_replaces_bound_widgets_and_cannot_restore_excluded_fields(store):
    await create(store, linked_page())
    source = await capture(store, projection=selection(fields=("checked",)), actions=())
    result = await narrow(store, source)
    assert result["collections"][0]["records"][0]["value"] == {"checked": False}
    empty = await narrow(store, source, projection={"collections": [], "assets": []}, actions=())
    assert empty["collections"] == []
    assert empty["layout"][0]["type"] == "access_unavailable"
    assert validate_page(empty).valid


@pytest.mark.parametrize("api", ["capture_link_snapshot_on", "project_link_snapshot_on"])
@pytest.mark.parametrize("kind", ["database", "missing"])
async def test_link_snapshot_apis_require_caller_transaction_before_loading(store, api, kind):
    with pytest.raises(TypeError, match="TransactionManager"):
        await getattr(store, api)(
            store.db if kind == "database" else None,
            SCOPE,
            creator_id=OWNER.did_key,
            projection=selection(),
            allowed_action_ids=[],
            **({"expected_page_rev": 1} if api.startswith("capture") else {"source_snapshot": {}}),
        )


async def test_capture_holds_revision_and_reads_uncommitted_caller_values(store):
    await create(store)
    async with store.db.transaction() as tx:
        await store.mutate_on(
            tx, SCOPE, OWNER, expected_rev=1, key="joined-capture", records=[record_change()]
        )
        result = await store.capture_link_snapshot_on(
            tx,
            SCOPE,
            creator_id=OWNER.did_key,
            projection=selection(),
            allowed_action_ids=[],
            expected_page_rev=2,
        )
        assert result["collections"][0]["records"][0]["value"]["checked"] is True
    async with store.db.transaction() as tx:
        await store.capture_link_snapshot_on(
            tx,
            SCOPE,
            creator_id=OWNER.did_key,
            projection=selection(),
            allowed_action_ids=[],
            expected_page_rev=2,
        )
        with pytest.raises(LockNotAvailableError):
            async with store.db.transaction() as writer:
                await writer.execute("SET LOCAL lock_timeout='100ms'")
                await writer.execute(
                    "UPDATE {{tables.pages}} SET access=access WHERE scope=$1", SCOPE.key
                )
    with pytest.raises(StoreError, match="revision_conflict"):
        await capture(store)


@pytest.mark.parametrize("cause", ["missing", "wrong-page", "corrupt"])
async def test_missing_corrupt_or_unbound_page_source_never_falls_back_to_current(store, cause):
    await create(store, linked_page())
    source = await capture(store)
    if cause == "missing":
        source = None
    elif cause == "wrong-page":
        source["page_id"] = "another-page"
    else:
        source["collections"][0]["records"][0]["value"]["checked"] = "not a boolean"
    with pytest.raises(StoreError, match="schema_invalid"):
        await narrow(store, source)


@pytest.mark.parametrize("limit", ["actions", "assets"])
async def test_capture_enforces_c4_action_and_asset_bounds(store, limit):
    await create(store)
    async with store.db.transaction() as tx:
        with pytest.raises(StoreError, match="schema_invalid"):
            await store.capture_link_snapshot_on(
                tx,
                SCOPE,
                creator_id=OWNER.did_key,
                projection={**selection(), "assets": [f"asset-{i}" for i in range(65)]}
                if limit == "assets"
                else selection(),
                allowed_action_ids=[f"action-{i}" for i in range(17)] if limit == "actions" else [],
                expected_page_rev=1,
            )


async def test_stored_source_runs_full_c1_limits_before_redaction(store):
    await create(store)
    source = await capture(store)
    source["layout"] = [
        {"id": f"widget-{i}", "type": "text", "props": {"markdown": "Text"}} for i in range(2001)
    ]
    with pytest.raises(StoreError) as refused:
        await narrow(store, source)
    assert refused.value.details[0]["code"] == "too_many_widgets"


async def test_captured_page_and_caller_writes_roll_back_together(store):
    await create(store)
    with pytest.raises(RuntimeError, match="caller rollback"):
        async with store.db.transaction() as tx:
            await store.mutate_on(
                tx,
                SCOPE,
                OWNER,
                expected_rev=1,
                key="captured-then-rollback",
                records=[record_change()],
            )
            captured = await store.capture_link_snapshot_on(
                tx,
                SCOPE,
                creator_id=OWNER.did_key,
                projection=selection(),
                allowed_action_ids=[],
                expected_page_rev=2,
            )
            assert captured["rev"] == 2
            raise RuntimeError("caller rollback")
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    source = await capture(store)
    assert source["collections"][0]["records"][0]["value"]["checked"] is False


async def test_retained_read_permission_does_not_keep_a_lost_edit_capability(store):
    await create(store, linked_page(), writers={READER.did_key})
    source = await capture(store, creator_id=READER.did_key)
    assert [a["id"] for a in source["actions"]] == ["check"]
    await store.change_access(
        SCOPE,
        OWNER,
        expected_rev=1,
        key="remove-write",
        access=Access(owner=OWNER.did_key, readers={READER.did_key}),
    )
    result = await narrow(store, source, creator_id=READER.did_key)
    assert result["actions"] == []
    assert (
        next(w for w in result["layout"] if w["id"] == "check-button")["type"]
        == "access_unavailable"
    )
    assert result["collections"][0]["records"] == source["collections"][0]["records"]

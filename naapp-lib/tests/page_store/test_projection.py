"""Live projections and pinned source data use current ACLs on the caller tx."""

import asyncio
import copy
import json

import pytest
from asyncpg.exceptions import LockNotAvailableError

from aweb_naapp.page_store import Access, StoreError
from tests.page_store.test_store import OWNER, READER, SCOPE, create, page, record_change


def selection(*, ids=("item-1",), fields=("label", "checked")):
    return {
        "collections": [{"collection": "items", "record_ids": list(ids), "fields": list(fields)}],
        "assets": [],
    }


async def project(store, creator=OWNER.did_key, **kwargs):
    async with store.db.transaction() as tx:
        return await store.read_projection_on(tx, SCOPE, creator_id=creator, **kwargs)


async def test_owner_projection_is_bounded_and_redacts_schema_annotations(store):
    document = page()
    collection = document["collections"][0]
    collection["schema"]["properties"]["private"] = {"type": "string", "maxLength": 100}
    collection["schema"].update(
        default={"private": "PRIVATE-ANNOTATION"}, examples=[{"private": "PRIVATE-ANNOTATION"}]
    )
    collection["records"][0]["value"]["private"] = "PRIVATE-ROW"
    collection["records"].append(
        {"id": "other", "rev": 1, "value": {"label": "UNREQUESTED-ROW", "checked": False}}
    )
    await create(store, document)
    requested = selection(fields=("label",))
    original = copy.deepcopy(requested)
    result = await project(store, projection=requested, expected_page_rev=1)
    assert requested == original
    assert set(result) == {"page_rev", "collections"}
    assert result["page_rev"] == 1
    selected = result["collections"][0]
    assert set(selected) == {"id", "schema_version", "schema", "records"}
    assert selected["id"] == "items" and selected["schema_version"] == 1
    assert selected["records"] == [
        {"id": "item-1", "rev": 1, "value": {"label": "Verify fixture inventory"}}
    ]
    assert set(selected["schema"]["properties"]) == {"label"}
    assert set(selected["schema"].get("required", [])) <= {"label"}
    assert "default" not in selected["schema"] and "examples" not in selected["schema"]
    assert "PRIVATE" not in json.dumps(result) and "UNREQUESTED" not in json.dumps(result)
    assert "private" in (await store.read(SCOPE, OWNER))["collections"][0]["schema"]["properties"]


async def test_empty_collection_subset_returns_no_collection_data(store):
    await create(store)
    assert await project(store, projection={"collections": [], "assets": []}) == {
        "page_rev": 1,
        "collections": [],
    }


async def test_projection_intersects_creator_rows_fields_and_current_page_access(store):
    document = page()
    document["collections"][0]["records"].append(
        {"id": "hidden", "rev": 1, "value": {"label": "HIDDEN-ROW", "checked": False}}
    )
    await create(
        store,
        document,
        hidden_rows={READER.did_key: {"items": {"hidden"}}},
        fields={READER.did_key: {"items": {"label"}}},
    )
    requested = selection(ids=("item-1", "hidden"))
    result = await project(store, READER.did_key, projection=requested)
    assert result["collections"][0]["records"] == [
        {"id": "item-1", "rev": 1, "value": {"label": "Verify fixture inventory"}}
    ]
    await store.change_access(
        SCOPE, OWNER, expected_rev=1, key="remove-reader", access=Access(owner=OWNER.did_key)
    )
    with pytest.raises(StoreError, match="resource_not_found"):
        await project(store, READER.did_key, projection=requested)
    with pytest.raises(StoreError, match="resource_not_found"):
        await project(store, READER.did_key, projection=requested, source_snapshot=result)


async def test_projection_reads_uncommitted_caller_writes_and_does_not_commit(store):
    await create(store)
    with pytest.raises(RuntimeError, match="rollback caller"):
        async with store.db.transaction() as tx:
            await store.mutate_on(
                tx, SCOPE, OWNER, expected_rev=1, key="uncommitted", records=[record_change()]
            )
            async with asyncio.timeout(3):
                result = await store.read_projection_on(
                    tx, SCOPE, creator_id=OWNER.did_key, projection=selection(), expected_page_rev=2
                )
            assert result["collections"][0]["records"][0]["value"]["checked"] is True
            raise RuntimeError("rollback caller")
    result = await project(store, projection=selection(), expected_page_rev=1)
    assert result["collections"][0]["records"][0]["value"]["checked"] is False
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 1


@pytest.mark.parametrize("kind", ["database", "missing"])
async def test_projection_requires_a_real_transaction_before_loading(store, kind):
    await create(store)
    wrong_tx = store.db if kind == "database" else None
    with pytest.raises(TypeError, match="TransactionManager"):
        await store.read_projection_on(
            wrong_tx, SCOPE, creator_id=OWNER.did_key, projection=selection()
        )


async def test_projection_holds_page_revision_until_the_caller_transaction_ends(store):
    await create(store)
    async with store.db.transaction() as tx:
        await store.read_projection_on(tx, SCOPE, creator_id=OWNER.did_key, projection=selection())
        with pytest.raises(LockNotAvailableError):
            async with store.db.transaction() as writer:
                await writer.execute("SET LOCAL lock_timeout = '100ms'")
                await writer.execute(
                    "UPDATE {{tables.pages}} SET access=access WHERE scope=$1", SCOPE.key
                )
    async with store.db.transaction() as writer:
        await writer.execute("SET LOCAL lock_timeout = '1s'")
        await writer.execute("UPDATE {{tables.pages}} SET access=access WHERE scope=$1", SCOPE.key)


async def test_pinned_source_survives_edits_and_cannot_gain_unpinned_values(store):
    await create(store)
    source = await project(store, projection=selection(fields=("checked",)), expected_page_rev=1)
    original = copy.deepcopy(source)
    await store.mutate(SCOPE, OWNER, expected_rev=1, key="edit-live", records=[record_change()])
    live = await project(store, projection=selection())
    assert live["page_rev"] == 2
    assert live["collections"][0]["records"][0]["value"]["checked"] is True
    pinned = await project(
        store, projection=selection(), expected_page_rev=1, source_snapshot=source
    )
    assert pinned["page_rev"] == 1
    assert pinned["collections"][0]["records"] == [
        {"id": "item-1", "rev": 1, "value": {"checked": False}}
    ]
    assert source == original
    with pytest.raises(StoreError, match="revision_conflict"):
        await project(store, projection=selection(), expected_page_rev=1)


async def test_pinned_source_obeys_current_field_row_and_page_deletion_fences(store):
    await create(store)
    source = await project(store, READER.did_key, projection=selection())
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
    pinned = await project(store, READER.did_key, projection=selection(), source_snapshot=source)
    assert pinned["collections"][0]["records"][0]["value"] == {"label": "Verify fixture inventory"}
    await store.change_access(
        SCOPE,
        OWNER,
        expected_rev=2,
        key="hide-reader-row",
        access=Access(
            owner=OWNER.did_key,
            readers={READER.did_key},
            hidden_rows={READER.did_key: {"items": {"item-1"}}},
        ),
    )
    hidden = await project(store, READER.did_key, projection=selection(), source_snapshot=source)
    assert hidden["collections"][0]["records"] == []
    await store.request_delete(SCOPE, OWNER, expected_rev=3, key="delete")
    with pytest.raises(StoreError, match="resource_not_found"):
        await project(store, projection=selection(), source_snapshot=source)


@pytest.mark.parametrize("source", [{}, {"page_rev": True, "collections": []}])
async def test_corrupt_source_is_refused_instead_of_reading_live_values(store, source):
    await create(store)
    with pytest.raises(StoreError, match="schema_invalid"):
        await project(store, projection=selection(), source_snapshot=source)

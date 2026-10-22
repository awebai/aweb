"""Row-local writes retain original request identity on real PostgreSQL."""

import asyncio

import pytest

from aweb_naapp.page_store import StoreError
from tests.page_store.test_store import OWNER, READER, SCOPE, create, page


async def values(store, principal=OWNER):
    return await store.read_widget(
        scope=SCOPE,
        principal=principal,
        widget_id="items",
        expected_page_rev=(await store.read(SCOPE, principal))["rev"],
        bind={"collection": "items"},
    )


async def test_patch_preserves_omitted_fields_and_replays_after_an_unrelated_write(store):
    await create(store)
    request = dict(
        collection="items", record_id="item-1", expected_rev=1, patch={"checked": True}, key="patch"
    )
    first = await store.patch_record(SCOPE, OWNER, **request)
    assert first["record_id"] == "item-1" and first["rev"] == 2 and first["page_rev"] == 2
    assert first["record"] == {
        "id": "item-1",
        "rev": 2,
        "value": {"label": "Verify fixture inventory", "checked": True},
    }
    added = await store.add_record(
        SCOPE,
        OWNER,
        collection="items",
        record_id="item-2",
        values={"label": "Another row", "checked": False},
        key="another",
    )
    assert added["page_rev"] == 3
    assert await store.patch_record(SCOPE, OWNER, **request) == first
    rows = (await values(store))["records"]
    assert rows[0]["value"] == {"label": "Verify fixture inventory", "checked": True}
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 3
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 3
    with pytest.raises(StoreError, match="idempotency_conflict"):
        await store.patch_record(SCOPE, OWNER, **{**request, "patch": {"checked": False}})


async def test_patch_of_a_visible_field_preserves_a_hidden_field_internally(store):
    document = page()
    collection = document["collections"][0]
    collection["schema"]["properties"]["private"] = {"type": "string"}
    collection["records"][0]["value"]["private"] = "hidden-sentinel"
    await create(
        store,
        document,
        writers={READER.did_key},
        fields={READER.did_key: {"items": {"label", "checked"}}},
    )
    receipt = await store.patch_record(
        SCOPE,
        READER,
        collection="items",
        record_id="item-1",
        expected_rev=1,
        patch={"checked": True},
        key="allowed",
    )
    assert "hidden-sentinel" not in repr(receipt)
    assert "hidden-sentinel" not in repr(await values(store, READER))
    assert (await values(store))["records"][0]["value"]["private"] == "hidden-sentinel"
    with pytest.raises(StoreError, match="action_denied"):
        await store.patch_record(
            SCOPE,
            READER,
            collection="items",
            record_id="item-1",
            expected_rev=2,
            patch={"private": "changed"},
            key="denied",
        )
    assert (await store.read(SCOPE, OWNER))["rev"] == 2


async def test_concurrent_same_record_patches_have_one_cas_winner(store):
    await create(store)
    results = await asyncio.gather(
        *(
            store.patch_record(
                SCOPE,
                OWNER,
                collection="items",
                record_id="item-1",
                expected_rev=1,
                patch={"label": label},
                key=label,
            )
            for label in ("first", "second")
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(r, dict) for r in results) == 1
    errors = [r for r in results if isinstance(r, StoreError)]
    assert len(errors) == 1 and errors[0].code == "revision_conflict"
    assert (await store.read(SCOPE, OWNER))["rev"] == 2


async def test_generated_add_id_is_stable_on_concurrent_and_later_retries(store):
    await create(store)
    request = dict(collection="items", values={"label": "Generated", "checked": False}, key="add")
    first, replay = await asyncio.gather(
        *[store.add_record(SCOPE, OWNER, **request) for _ in range(2)]
    )
    assert replay == first and first["record_id"].startswith("rec_") and first["rev"] == 1
    await store.patch_record(
        SCOPE,
        OWNER,
        collection="items",
        record_id="item-1",
        expected_rev=1,
        patch={"checked": True},
        key="unrelated",
    )
    assert await store.add_record(SCOPE, OWNER, **request) == first
    assert len((await values(store))["records"]) == 2


async def test_delete_replays_and_tombstone_refuses_reusing_the_record_id(store):
    await create(store)
    request = dict(collection="items", record_id="item-1", expected_rev=1, key="delete")
    first = await store.delete_record(SCOPE, OWNER, **request)
    assert first["deleted"] is True and first["rev"] == 2 and first["record_id"] == "item-1"
    assert await store.delete_record(SCOPE, OWNER, **request) == first
    assert (await values(store))["records"] == []
    with pytest.raises(StoreError, match="revision_conflict"):
        await store.add_record(
            SCOPE,
            OWNER,
            collection="items",
            record_id="item-1",
            values={"label": "Reused", "checked": False},
            key="reuse",
        )
    assert (await store.read(SCOPE, OWNER))["rev"] == 2


async def test_bad_patch_and_non_writer_commit_nothing(store):
    await create(store)
    for actor, patch, error in (
        (READER, {"checked": True}, "resource_not_found"),
        (OWNER, {"checked": "not boolean"}, "schema_invalid"),
        (OWNER, {}, "schema_invalid"),
    ):
        with pytest.raises(StoreError, match=error):
            await store.patch_record(
                SCOPE,
                actor,
                collection="items",
                record_id="item-1",
                expected_rev=1,
                patch=patch,
                key=error + repr(patch),
            )
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1


async def test_unrelated_concurrent_adds_do_not_need_a_page_precondition(store):
    await create(store)
    results = await asyncio.gather(
        *(
            store.add_record(
                SCOPE,
                OWNER,
                collection="items",
                record_id=rid,
                values={"label": rid, "checked": False},
                key=rid,
            )
            for rid in ("row-a", "row-b")
        )
    )
    assert {r["page_rev"] for r in results} == {2, 3}
    assert {r["rev"] for r in results} == {1}


async def test_original_row_receipt_survives_later_row_edit_and_deletion(store):
    await create(store)
    request = dict(
        collection="items",
        record_id="item-1",
        expected_rev=1,
        patch={"label": "First result"},
        key="original",
    )
    first = await store.patch_record(SCOPE, OWNER, **request)
    await store.patch_record(
        SCOPE,
        OWNER,
        collection="items",
        record_id="item-1",
        expected_rev=2,
        patch={"label": "Later result"},
        key="later",
    )
    await store.delete_record(
        SCOPE, OWNER, collection="items", record_id="item-1", expected_rev=3, key="delete"
    )
    assert await store.patch_record(SCOPE, OWNER, **request) == first
    assert first["record"]["value"]["label"] == "First result"


async def test_trusted_calendar_validator_sees_the_whole_merged_record(store):
    from datetime import date

    document = page()
    collection = document["collections"][0]
    collection["schema"]["properties"]["date"] = {"type": "string", "format": "date"}
    collection["records"][0]["value"]["date"] = "2026-10-21"
    seen = []

    def validate(scope, definition, record):
        seen.append(dict(record["value"]))
        assert scope == SCOPE and definition["id"] == "items"
        try:
            value = record["value"]["date"]
            assert date.fromisoformat(value).isoformat() == value
        except (ValueError, AssertionError) as exc:
            raise StoreError("schema_invalid") from exc

    store.record_validator = validate
    await create(store, document)
    with pytest.raises(StoreError, match="schema_invalid"):
        await store.patch_record(
            SCOPE,
            OWNER,
            collection="items",
            record_id="item-1",
            expected_rev=1,
            patch={"date": "2026-02-30"},
            key="bad-date",
        )
    first = await store.patch_record(
        SCOPE,
        OWNER,
        collection="items",
        record_id="item-1",
        expected_rev=1,
        patch={"checked": True},
        key="valid-date",
    )
    assert seen[-1]["date"] == "2026-10-21" and seen[-1]["checked"] is True
    assert first["record"]["value"]["date"] == "2026-10-21"
    assert (await store.read(SCOPE, OWNER))["rev"] == 2


async def test_retry_refuses_a_stored_value_after_current_field_visibility_narrows(store):
    from aweb_naapp.page_store import Access

    await create(store, writers={READER.did_key})
    request = dict(
        collection="items",
        record_id="item-1",
        expected_rev=1,
        patch={"checked": True},
        key="patch-before-narrowing",
    )
    await store.patch_record(SCOPE, READER, **request)
    await store.change_access(
        SCOPE,
        OWNER,
        expected_rev=2,
        key="narrow",
        access=Access(
            owner=OWNER.did_key,
            writers={READER.did_key},
            fields={READER.did_key: {"items": {"checked"}}},
        ),
    )
    with pytest.raises(StoreError, match="action_denied"):
        await store.patch_record(SCOPE, READER, **request)
    assert (await store.read(SCOPE, OWNER))["rev"] == 3


@pytest.mark.parametrize("operation", ["add", "patch", "delete"])
async def test_record_replay_refuses_a_collection_removed_by_a_document_migration(store, operation):
    import json

    from aweb_naapp.pages import validate_page

    await create(store)
    request = dict(collection="items", key="before-collection-removal")
    if operation == "add":
        method = store.add_record
        request["values"] = {"label": "Added row", "checked": False}
    else:
        method = store.patch_record if operation == "patch" else store.delete_record
        request.update(record_id="item-1", expected_rev=1)
        if operation == "patch":
            request["patch"] = {"checked": True}
    receipt = await method(SCOPE, OWNER, **request)
    document = await store.read(SCOPE, OWNER)
    document.update(collections=[], layout=[], widget_state={}, actions=[])
    document["rev"] += 1
    assert validate_page(document).valid
    # Simulate a committed document migration. There is no public collection
    # removal API; the existing request receipt remains in the database.
    await store.db.execute(
        "UPDATE {{tables.pages}} SET document=$2::jsonb WHERE scope=$1",
        SCOPE.key,
        json.dumps(document),
    )
    with pytest.raises(StoreError) as refused:
        await method(SCOPE, OWNER, **request)
    assert (refused.value.code, refused.value.status) == ("action_denied", 403)
    assert (await store.read(SCOPE, OWNER))["rev"] == document["rev"]
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 2
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 2
    stored = await store.db.fetch_value(
        "SELECT receipt FROM {{tables.page_receipts}} WHERE transaction_id=$1::uuid",
        receipt["transaction_id"],
    )
    assert json.loads(stored) == receipt

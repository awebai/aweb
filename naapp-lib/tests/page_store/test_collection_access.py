"""Checked creator metadata shares ACLs without scanning live record IDs."""

from dataclasses import replace

import pytest
from asyncpg.exceptions import LockNotAvailableError

from aweb_naapp.page_store import Access, StoreError
from tests.page_store.test_query_api import table
from tests.page_store.test_store import OWNER, READER, SCOPE, STRANGER, create


async def metadata(store, *, creator=OWNER, link_mode="live", record_ids="*", collection="items"):
    async with store.db.transaction() as tx:
        return await store.collection_access_on(
            tx,
            SCOPE,
            creator_id=creator.did_key,
            collection=collection,
            link_mode=link_mode,
            record_ids=record_ids,
        )


def test_public_principal_id_uses_verified_canonical_identity_and_scope():
    from aweb_naapp.page_store import principal_id

    member = replace(OWNER, did_aw="did:aw:verified")
    assert principal_id(member, SCOPE) == OWNER.did_key
    assert principal_id(replace(member, did_aw_registry_verified=True), SCOPE) == "did:aw:verified"
    with pytest.raises(StoreError, match="resource_not_found"):
        principal_id(replace(member, team_id="other:example.com"), SCOPE)


async def test_live_metadata_does_not_query_or_lock_record_ids(store):
    await create(store)
    async with store.db.transaction() as records_lock:
        await records_lock.execute("LOCK TABLE {{tables.page_records}} IN ACCESS EXCLUSIVE MODE")
        async with store.db.transaction() as tx:
            await tx.execute("SET LOCAL lock_timeout='100ms'")
            result = await store.collection_access_on(
                tx, SCOPE, creator_id=OWNER.did_key, collection="items", link_mode="live"
            )
    assert result["record_ids"] is None
    assert result["page_rev"] == 1 and result["mode"] == "owned"
    assert result["fields"] == ["checked", "label"]
    assert "records" not in result and "Verify fixture inventory" not in repr(result)


async def test_named_metadata_redacts_schema_and_checks_only_requested_visible_ids(store):
    document = table(3)
    schema = document["collections"][0]["schema"]
    schema.update(
        default={"checked": True, "label": "PRIVATE-ANNOTATION"}, examples=[{"checked": True}]
    )
    await create(
        store,
        document,
        fields={READER.did_key: {"items": {"label"}}},
        hidden_rows={READER.did_key: {"items": {"row-001"}}},
    )
    result = await metadata(store, creator=READER, record_ids=["row-001", "row-002", "missing"])
    assert result["record_ids"] == ["row-002"]
    assert result["fields"] == ["label"]
    assert set(result["schema"]["properties"]) == {"label"}
    assert result["schema"]["required"] == ["label"]
    assert "default" not in result["schema"] and "examples" not in result["schema"]
    assert "PRIVATE-ANNOTATION" not in repr(result)
    assert (await metadata(store, creator=READER, record_ids=[]))["record_ids"] == []
    assert await metadata(store, collection="missing") is None
    await store.change_access(
        SCOPE,
        OWNER,
        expected_rev=1,
        key="no-fields",
        access=Access(
            owner=OWNER.did_key, readers={READER.did_key}, fields={READER.did_key: {"items": set()}}
        ),
    )
    assert await metadata(store, creator=READER) is None


async def test_pinned_wildcard_is_bounded_and_empty_is_literal(store):
    await create(store, table(200))
    pinned = await metadata(store, link_mode="pinned")
    assert len(pinned["record_ids"]) == 200
    await store.add_record(
        SCOPE,
        OWNER,
        collection="items",
        record_id="row-200",
        key="extra",
        values={"label": "New", "checked": False},
    )
    with pytest.raises(StoreError) as refused:
        await metadata(store, link_mode="pinned")
    assert (refused.value.code, refused.value.status) == ("action_denied", 403)
    assert (await metadata(store))["record_ids"] is None
    assert (await metadata(store, link_mode="pinned", record_ids=["row-200"]))["record_ids"] == [
        "row-200"
    ]
    assert (await metadata(store, link_mode="pinned", record_ids=[]))["record_ids"] == []


async def test_empty_pinned_collection_and_current_authority(store):
    await create(store, table(0))
    assert (await metadata(store, link_mode="pinned"))["record_ids"] == []
    with pytest.raises(StoreError, match="resource_not_found"):
        await metadata(store, creator=STRANGER)
    await store.request_delete(SCOPE, OWNER, expected_rev=1, key="delete")
    with pytest.raises(StoreError, match="resource_not_found"):
        await metadata(store)


@pytest.mark.parametrize("tx_kind", ["database", "missing"])
async def test_collection_access_requires_a_caller_transaction(store, tx_kind):
    with pytest.raises(TypeError, match="TransactionManager"):
        await store.collection_access_on(
            store.db if tx_kind == "database" else None,
            SCOPE,
            creator_id=OWNER.did_key,
            collection="items",
            link_mode="live",
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"link_mode": "wrong"},
        {"creator_id": ""},
        {"collection": ""},
        {"record_ids": None},
        {"record_ids": "wrong"},
        {"record_ids": ["*"]},
        {"record_ids": ["same", "same"]},
        {"record_ids": list(range(201))},
    ],
)
async def test_collection_access_refuses_invalid_selection(store, changes):
    async with store.db.transaction() as tx:
        with pytest.raises(StoreError, match="schema_invalid"):
            await store.collection_access_on(
                tx,
                SCOPE,
                **{
                    "creator_id": OWNER.did_key,
                    "collection": "items",
                    "link_mode": "live",
                    **changes,
                },
            )


async def test_metadata_keeps_current_acl_locked_until_caller_commit(store):
    await create(store)
    async with store.db.transaction() as tx:
        await store.collection_access_on(
            tx, SCOPE, creator_id=OWNER.did_key, collection="items", link_mode="live"
        )
        with pytest.raises(LockNotAvailableError):
            async with store.db.transaction() as changing:
                await changing.execute("SET LOCAL lock_timeout='100ms'")
                await changing.execute(
                    "UPDATE {{tables.pages}} SET access=access WHERE scope=$1", SCOPE.key
                )

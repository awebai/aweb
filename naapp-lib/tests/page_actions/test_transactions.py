"""Page action effects and the page store share a real caller transaction."""

from datetime import UTC, datetime
from uuid import UUID, uuid4, uuid5

import pytest

from aweb_naapp.outbox import OutboxEvent, enqueue
from aweb_naapp.page_store import StoreError
from tests.page_store.test_store import OWNER, SCOPE, create, page, record_change
from tests.page_store.test_store import store as store


async def task_mirror(tx, *, receipt=None):
    await enqueue(
        tx,
        OutboxEvent(
            event_id=uuid5(UUID(receipt["transaction_id"]), "task-mirror") if receipt else uuid4(),
            team_id=SCOPE.team_id,
            kind="aweb.page.action.task_mirror",
            occurred_at=datetime.now(UTC),
            payload=b'{"request_id":"fixture-action"}',
        ),
    )


async def assert_original_page(store, *, outbox_count=1):
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    projected = await store.read_widget(
        SCOPE, OWNER, widget_id="items", expected_page_rev=1, bind={"collection": "items"}
    )
    assert projected["records"][0]["rev"] == 1
    assert projected["records"][0]["value"]["checked"] is False
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 1
    assert (
        await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == outbox_count
    )


async def test_caller_rollback_discards_page_and_task_mirror_and_same_key_can_retry(store):
    await create(store)
    with pytest.raises(RuntimeError, match="abort action resolution"):
        async with store.db.transaction() as tx:
            first = await store.mutate_on(
                tx, SCOPE, OWNER, expected_rev=1, key="resolve", records=[record_change()]
            )
            await task_mirror(tx)
            raise RuntimeError("abort action resolution")
    await assert_original_page(store)

    # The independent key claim survives the caller's rollback; retry recovers
    # its transaction ID rather than either duplicating or losing the action.
    async with store.db.transaction() as tx:
        retried = await store.mutate_on(
            tx, SCOPE, OWNER, expected_rev=1, key="resolve", records=[record_change()]
        )
        await task_mirror(tx)
    assert retried == first
    assert (await store.read(SCOPE, OWNER))["rev"] == 2
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 2
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 3


async def test_later_stale_patch_discards_first_patch_and_callers_task_mirror(store):
    document = page()
    document["collections"][0]["records"].append(
        {"id": "item-2", "rev": 1, "value": {"label": "Second item", "checked": False}}
    )
    await create(store, document)
    with pytest.raises(StoreError, match="revision_conflict"):
        async with store.db.transaction() as tx:
            await task_mirror(tx)
            await store.mutate_on(
                tx,
                SCOPE,
                OWNER,
                expected_rev=1,
                key="resolve-stale",
                records=[record_change(), record_change(id="item-2", expected_rev=0)],
            )
    await assert_original_page(store)


async def test_caught_stale_patch_rolls_back_effects_before_caller_records_failure(store):
    await create(store)
    async with store.db.transaction() as tx:
        with pytest.raises(StoreError, match="revision_conflict"):
            await store.mutate_on(
                tx,
                SCOPE,
                OWNER,
                expected_rev=1,
                key="resolve-caught",
                records=[record_change(), record_change(id="missing", expected_rev=1)],
            )
        # A failed action can still record/mirror its failure in the caller's
        # transaction. The valid first patch must not leak into that commit.
        await task_mirror(tx)
    await assert_original_page(store, outbox_count=2)


async def test_committed_retry_reuses_receipt_and_does_not_duplicate_task_mirror(store):
    await create(store)
    async with store.db.transaction() as tx:
        first = await store.mutate_on(
            tx, SCOPE, OWNER, expected_rev=1, key="resolve-replay", records=[record_change()]
        )
        await task_mirror(tx, receipt=first)
    async with store.db.transaction() as tx:
        replay = await store.mutate_on(
            tx, SCOPE, OWNER, expected_rev=1, key="resolve-replay", records=[record_change()]
        )
        await task_mirror(tx, receipt=replay)
    assert replay == first
    assert (await store.read(SCOPE, OWNER))["rev"] == 2
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 2
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 3

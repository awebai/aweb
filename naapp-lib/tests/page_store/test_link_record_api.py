"""Checked edit sessions share row CAS without pretending to be member requests."""

import asyncio
from dataclasses import replace

import pytest

from aweb_naapp.page_store import Access, LinkRecordContext, StoreError
from tests.page_store.test_store import OWNER, READER, SCOPE, create


async def admitted(tx):
    """A host supplies its local installation/session/membership recheck here."""


def context(**changes):
    return LinkRecordContext(
        scope=SCOPE,
        creator_id=OWNER.did_key,
        creator_did_key=OWNER.did_key,
        creator_did_aw=None,
        creator_alias=OWNER.alias,
        certificate_id=OWNER.certificate_id,
        editor_name=None,
        link_id="link-one",
        session_id="session-one",
        document_id="document-one",
        widget_id="table-one",
        collection="items",
        operations=frozenset({"add", "patch", "delete"}),
        fields=frozenset({"label", "checked"}),
        revalidate=admitted,
        **changes,
    )


async def patch(store, actor, *, expected_rev=1, key="edit", value=True):
    async with store.db.transaction() as tx:
        return await store.write_link_record_on(
            tx, SCOPE, actor, operation="patch", collection="items", record_id="item-1",
            expected_rev=expected_rev, patch={"checked": value}, key=key,
        )


async def test_link_patch_preserves_values_and_records_the_actual_session_origin(store):
    await create(store)
    receipt = await patch(store, context())
    assert receipt["record"] == {
        "id": "item-1", "rev": 2,
        "value": {"label": "Verify fixture inventory", "checked": True},
    }
    evidence = await store.db.fetch_value(
        "SELECT evidence FROM {{tables.page_audit}} WHERE transaction_id=$1",
        receipt["transaction_id"],
    )
    import json
    evidence = json.loads(evidence) if isinstance(evidence, str) else evidence
    assert evidence == {
        "origin_kind": "link", "creator_id": OWNER.did_key,
        "creator_did_key": OWNER.did_key, "creator_did_aw": None,
        "creator_alias": OWNER.alias, "certificate_id": OWNER.certificate_id,
        "editor_name": None, "link_id": "link-one", "session_id": "session-one",
        "document_id": "document-one", "widget_id": "table-one",
    }
    assert "signer_did" not in evidence


async def test_member_and_different_sessions_never_share_retry_identity(store):
    await create(store)
    member = await store.patch_record(
        SCOPE, OWNER, collection="items", record_id="item-1", expected_rev=1,
        patch={"checked": True}, key="same-key",
    )
    first = await patch(store, context(), expected_rev=2, key="same-key", value=False)
    second = await patch(
        store, replace(context(), session_id="session-two"),
        expected_rev=3, key="same-key", value=True,
    )
    assert len({r["transaction_id"] for r in (member, first, second)}) == 3
    assert await patch(store, context(), expected_rev=2, key="same-key", value=False) == first
    assert (await store.read(SCOPE, OWNER))["rev"] == 4


async def test_member_and_link_origin_race_use_the_same_row_revision(store):
    await create(store)
    results = await asyncio.gather(
        patch(store, context()),
        store.patch_record(
            SCOPE, OWNER, collection="items", record_id="item-1", expected_rev=1,
            patch={"checked": False}, key="member-race",
        ),
        return_exceptions=True,
    )
    winners = [r for r in results if isinstance(r, dict)]
    losers = [r for r in results if isinstance(r, StoreError)]
    assert len(winners) == len(losers) == 1
    assert (losers[0].status, losers[0].code) == (409, "revision_conflict")
    assert (await store.read(SCOPE, OWNER))["rev"] == 2


@pytest.mark.parametrize("operation", ["add", "patch", "delete"])
async def test_session_row_operations_join_the_outer_transaction(store, operation):
    await create(store)
    request = {"collection": "items", "key": operation, "operation": operation}
    if operation == "add":
        request["values"] = {"label": "New", "checked": False}
    else:
        request.update(record_id="item-1", expected_rev=1)
        if operation == "patch":
            request["patch"] = {"checked": True}
    with pytest.raises(RuntimeError, match="outer rollback"):
        async with store.db.transaction() as tx:
            receipt = await store.write_link_record_on(tx, SCOPE, context(), **request)
            assert receipt["page_rev"] == 2
            raise RuntimeError("outer rollback")
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    async with store.db.transaction() as tx:
        retried = await store.write_link_record_on(tx, SCOPE, context(), **request)
    assert retried["transaction_id"] == receipt["transaction_id"]


@pytest.mark.parametrize("operation", ["add", "patch"])
async def test_session_cannot_write_fields_outside_its_frozen_grant(store, operation):
    await create(store)
    actor = replace(context(), fields=frozenset({"checked"}))
    request = {"operation": operation, "collection": "items", "key": "forbidden"}
    if operation == "add":
        request["values"] = {"label": "Forbidden", "checked": False}
    else:
        request.update(record_id="item-1", expected_rev=1, patch={"label": "Forbidden"})
    with pytest.raises(StoreError, match="action_denied"):
        async with store.db.transaction() as tx:
            await store.write_link_record_on(tx, SCOPE, actor, **request)
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 1


async def test_session_authorization_is_checked_after_waiting_for_the_page_lock(store):
    await create(store)
    waiting = asyncio.Event()
    authority = {"current": True}

    async def require_current(tx):
        if not authority["current"]:
            raise StoreError("link_unavailable", 404)

    async def attempt():
        waiting.set()
        return await patch(store, replace(context(), revalidate=require_current))

    async with store.db.transaction() as blocking:
        blocker = await blocking.fetch_value("SELECT pg_backend_pid()")
        await blocking.fetch_one(
            "SELECT scope FROM {{tables.pages}} WHERE scope=$1 FOR UPDATE", SCOPE.key,
        )
        pending = asyncio.create_task(attempt())
        await waiting.wait()
        async with asyncio.timeout(5):
            while not await blocking.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                "WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))",
                blocker,
            ):
                await asyncio.sleep(0.01)
        # A real pending row write is now blocked behind the page lock.
        authority["current"] = False
    with pytest.raises(StoreError, match="link_unavailable"):
        await pending
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 1


async def test_session_replay_rechecks_current_creator_acl(store):
    await create(store, writers={READER.did_key})
    actor = replace(context(), creator_id=READER.did_key, creator_did_key=READER.did_key,
                    creator_alias=READER.alias, certificate_id=READER.certificate_id)
    await patch(store, actor)
    await store.change_access(
        SCOPE, OWNER, expected_rev=2, key="withdraw",
        access=Access(owner=OWNER.did_key, readers={READER.did_key}),
    )
    with pytest.raises(StoreError):
        await patch(store, actor)

"""Member records and queries retain the caller's installation transaction."""

import time

import pytest
from asyncpg.exceptions import LockNotAvailableError

from aweb_naapp.page_store import StoreError
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.installation import InstallationFence, apply_installation_migrations
from tests.page_store.test_store import OWNER, SCOPE, create


class AuthorityBeforeTransaction:
    async def grant_for(self, team_id, certificate_id=None):
        raise AssertionError("fetch authority before opening the transaction")

    async def status_for(self, team_id):
        raise AssertionError("fetch authority before opening the transaction")


def request(operation):
    result = {"collection": "items", "key": "joined-" + operation}
    if operation == "add":
        result["values"] = {"label": "Added", "checked": False}
    else:
        result.update(record_id="item-1", expected_rev=1)
        if operation == "patch":
            result["patch"] = {"checked": True}
    return result


@pytest.mark.parametrize("operation", ["add", "patch", "delete"])
async def test_joined_record_and_query_roll_back_with_the_installation_fence(store, operation):
    await create(store)
    await apply_installation_migrations(store.db)
    fence = InstallationFence(store.db, app_id=SCOPE.app_id, grants=AuthorityBeforeTransaction())
    grant = Grant(
        team_id=SCOPE.team_id,
        installation_id=SCOPE.installation_id,
        generation=1,
        scopes=frozenset({"records:write"}),
        fresh_until=time.monotonic_ns() + seconds_to_ns(60),
    )
    method = getattr(store, operation + "_record_on")
    kwargs = request(operation)
    with pytest.raises(RuntimeError, match="outer rollback"):
        async with store.db.transaction() as tx:
            admitted = await fence.admit(tx, grant)
            first = await method(tx, SCOPE, OWNER, **kwargs)
            result = await store.query_member_widget_on(
                tx, SCOPE, OWNER, widget_id="items", bind={"collection": "items"}
            )
            assert result["page_rev"] == 2
            assert result["count"] == {"add": 2, "patch": 1, "delete": 0}[operation]
            if operation == "patch":
                assert result["records"][0]["value"]["checked"] is True
            # Uncommitted writes are visible through the joined query, but not
            # through another connection. Fence withdrawal must still wait.
            assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 1
            with pytest.raises(LockNotAvailableError):
                async with store.db.transaction() as withdrawing:
                    await withdrawing.execute("SET LOCAL lock_timeout='100ms'")
                    await withdrawing.execute(
                        "UPDATE {{tables.installation_fences}} SET state=state WHERE app_id=$1 AND team_id=$2",
                        SCOPE.app_id,
                        SCOPE.team_id,
                    )
                    # An uncommitted first fence slot is not visible yet: try
                    # the same slot through admission to lock/insert it.
                    await fence.admit(withdrawing, grant)
            await fence.check(tx, admitted)
            raise RuntimeError("outer rollback")
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.installation_fences}}") == 0
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1
    async with store.db.transaction() as tx:
        await fence.admit(tx, grant)
        committed = await method(tx, SCOPE, OWNER, **kwargs)
        replay = await method(tx, SCOPE, OWNER, **kwargs)
        assert replay == committed
        assert committed["transaction_id"] == first["transaction_id"]
    assert (await store.read(SCOPE, OWNER))["rev"] == 2
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 2
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 2


@pytest.mark.parametrize("operation", ["add", "patch", "delete", "query"])
@pytest.mark.parametrize("tx_kind", ["database", "missing"])
async def test_joined_member_methods_require_a_transaction(store, operation, tx_kind):
    tx = store.db if tx_kind == "database" else None
    method = getattr(
        store, operation + "_record_on" if operation != "query" else "query_member_widget_on"
    )
    kwargs = (
        request(operation)
        if operation != "query"
        else {"widget_id": "items", "bind": {"collection": "items"}}
    )
    with pytest.raises(TypeError, match="TransactionManager"):
        await method(tx, SCOPE, OWNER, **kwargs)


async def test_joined_member_query_checks_revision_and_authority(store):
    from tests.page_store.test_store import STRANGER

    await create(store)
    async with store.db.transaction() as tx:
        with pytest.raises(StoreError, match="revision_conflict"):
            await store.query_member_widget_on(
                tx,
                SCOPE,
                OWNER,
                widget_id="items",
                bind={"collection": "items"},
                expected_page_rev=9,
            )
        with pytest.raises(StoreError, match="resource_not_found"):
            await store.query_member_widget_on(
                tx, SCOPE, STRANGER, widget_id="items", bind={"collection": "items"}
            )

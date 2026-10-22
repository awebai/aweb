"""Discovery metadata and page creation share a caller transaction."""

import pytest

from aweb_naapp.page_store import Access, StoreError
from tests.page_store.test_store import OWNER, SCOPE, page


@pytest.mark.parametrize("tx_kind", ["database", "missing"])
async def test_create_on_requires_a_caller_transaction(store, tx_kind):
    with pytest.raises(TypeError, match="TransactionManager"):
        await store.create_on(
            store.db if tx_kind == "database" else None,
            SCOPE,
            OWNER,
            page(),
            access=Access(owner=OWNER.did_key),
            key="create",
        )


async def test_discovery_and_page_roll_back_and_replay_together(store):
    await store.db.execute(
        "CREATE TABLE {{tables.test_discovery}} (page_id text PRIMARY KEY, receipt text)"
    )
    with pytest.raises(RuntimeError, match="caller rollback"):
        async with store.db.transaction() as tx:
            first = await store.create_on(
                tx, SCOPE, OWNER, page(), access=Access(owner=OWNER.did_key), key="create"
            )
            await tx.execute(
                "INSERT INTO {{tables.test_discovery}} VALUES ($1,$2)",
                SCOPE.page_id,
                first["transaction_id"],
            )
            raise RuntimeError("caller rollback")
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.pages}}") == 0
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.test_discovery}}") == 0
    for _ in range(2):
        async with store.db.transaction() as tx:
            receipt = await store.create_on(
                tx, SCOPE, OWNER, page(), access=Access(owner=OWNER.did_key), key="create"
            )
            assert receipt == first
            await tx.execute(
                "INSERT INTO {{tables.test_discovery}} VALUES ($1,$2) ON CONFLICT DO NOTHING",
                SCOPE.page_id,
                receipt["transaction_id"],
            )
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.test_discovery}}") == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 1


async def test_caught_create_refusal_does_not_leave_an_inner_request_claim(store):
    # The savepoint rolls back content-side attempts even if the caller commits.
    await store.create(SCOPE, OWNER, page(), access=Access(owner=OWNER.did_key), key="create")
    async with store.db.transaction() as tx:
        with pytest.raises(StoreError, match="revision_conflict"):
            await store.create_on(
                tx, SCOPE, OWNER, page(), access=Access(owner=OWNER.did_key), key="refused"
            )
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.idempotency_keys}}") == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_receipts}}") == 1

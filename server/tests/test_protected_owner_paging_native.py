"""aweb-adbb D2f: the owner page reads bounded pages of its own scope.

Every list (waiting, approved-not-confirmed, history) is one page ordered by
expiry then operation id, with a cursor to the next, so a load never reads
every retained row; other scopes are filtered in SQL. Rows are only ever
made by the signer's own prepare; a test sets a stored outcome or expiry
directly only where the signer's own path to it is not this test's subject."""

import json

import pytest

from aweb.protected_signing.owner import owner_view
from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_admission_native import prepare, root_operation
from tests.test_protected_owner_native import scope_of

pytest_plugins = ("tests.test_independent_protected_signer",)


async def prepared(a, count):
    operations = [root_operation(a) for _ in range(count)]
    for operation in operations:
        assert (await prepare(a, operation)).status_code == 200
    return [o.operation_id for o in operations]


async def walk(a, scope, listing, page):
    """Every id a list shows, page by page, following its cursor."""
    seen, cursor = [], None
    while True:
        view = await owner_view(a.group, scope=scope, subject=a.actor.subject, page=page,
                                cursors={listing: cursor} if cursor else None)
        rows = view[listing]
        assert len(rows) <= page
        seen += [row["operation_id"] for row in rows]
        cursor = view["more"][listing]
        if cursor is None:
            return seen


@pytest.mark.asyncio
async def test_waiting_requests_come_one_bounded_page_at_a_time(admissions):
    a = admissions
    ids = await prepared(a, 5)
    scope = await scope_of(a.human)
    seen = await walk(a, scope, "pending", 2)
    assert sorted(seen) == sorted(ids) and len(seen) == len(set(seen))


@pytest.mark.asyncio
async def test_history_pages_have_no_gap_or_repeat_among_equal_expiries(admissions):
    a = admissions
    ids = await prepared(a, 7)
    # The same stored expiry for all, and a final refusal each: only the
    # operation id orders them.
    await a.w.db.execute(
        "UPDATE {{tables.protected_signer_operations}} SET refusal_code='operation_refused', "
        "expires_at=date_trunc('second', now()) WHERE operation_id = ANY($1::text[])", ids)
    scope = await scope_of(a.human)
    seen = await walk(a, scope, "history", 3)
    assert sorted(seen) == sorted(ids) and len(seen) == len(set(seen))


@pytest.mark.asyncio
async def test_another_scopes_rows_are_never_read(admissions):
    a = admissions
    mine, other = await prepared(a, 2), await prepared(a, 2)
    elsewhere = {**json.loads(await a.w.db.fetch_value(
        "SELECT scope::text FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", other[0])),
        "service_id": "another-service"}
    await a.w.db.execute("UPDATE {{tables.protected_signer_operations}} SET scope=$2::jsonb "
                         "WHERE operation_id = ANY($1::text[])", other, json.dumps(elsewhere))
    view = await owner_view(a.group, scope=await scope_of(a.human), subject=a.actor.subject)
    assert sorted(p["operation_id"] for p in view["pending"]) == sorted(mine)

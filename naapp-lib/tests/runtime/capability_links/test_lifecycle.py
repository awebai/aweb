"""C4 lifecycle and receipt semantics on real PostgreSQL.

The small action app below owns its ledger and uses the shared idempotency
store. N5 never stores another copy of its receipts.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from awid.signing import canonical_json_bytes

from aweb_naapp.idempotency import apply_idempotency_migrations, claim, lookup
from aweb_naapp.runtime.capability_links import (
    ActionReceipt,
    LinkCaller,
    LinkRefused,
    Readable,
    admit,
    read,
    revoke,
)

from .conftest import CAPABILITY, CREATOR, SCOPE, T0, mint_link, request_from
from .test_exchange import _exchange, body


class ActionApp:
    """An action ledger that commits with the caller and leaves no side effects
    after a refused operation. It is not an N3 implementation."""

    fail = False

    async def lookup(self, tx, *, key, request_hash):
        receipt = await lookup(tx, key=key, request_hash=request_hash)
        if receipt is None:
            return None
        row = await tx.fetch_one(
            "SELECT result FROM {{tables.test_link_actions}} WHERE id = $1", receipt.receipt_ref
        )
        return ActionReceipt(receipt.receipt_ref, json.loads(row["result"]))

    async def apply(self, tx, *, action):
        operation_id = "op_" + uuid4().hex
        claimed = await claim(
            tx,
            key=action.key,
            request_hash=action.request_hash,
            receipt_ref=operation_id,
            retention=timedelta(days=30),
        )
        assert claimed.created  # the link lock serialized this admission
        result = {
            "input": dict(action.request["input"]),
            "provenance": {
                "kind": "anonymous_link",
                "link_id": action.caller.link_id,
                "session_id": action.caller.session_id,
            },
            "creator": action.creator,
            "page": action.scope.page_id,
            "projection": action.projection,
            "sponsor": action.intent_sponsor_did,
        }
        await tx.execute(
            "INSERT INTO {{tables.test_link_actions}} (id, result) VALUES ($1, $2::jsonb)",
            operation_id,
            json.dumps(result),
        )
        if self.fail:
            raise RuntimeError("app failed after its write")
        return ActionReceipt(operation_id, result)


@pytest.fixture
async def action_app(db):
    await apply_idempotency_migrations(db)
    await db.execute(
        "CREATE TABLE {{tables.test_link_actions}} (id TEXT PRIMARY KEY, result JSONB)"
    )
    return ActionApp()


async def holder(db, authority, *, one_use=False, request=None):
    request = request or request_from(CAPABILITY["delegation"][0]["link"])
    request["one_use"] = one_use
    minted = await mint_link(db, authority, request)
    session = await _exchange(db, authority, minted.link_id, body(minted.secret))
    return LinkCaller(minted.link_id, session.session_id)


def action_body(key="k1", *, action_id="mark-cleaned", record_id="b-17", **changes):
    request = {
        "action_id": action_id,
        "input": {"record_id": record_id},
        "expected_page_rev": 1,
        "expected_record_revs": {"bookings/b-17": 1},
        "idempotency_key": key,
    }
    request.update(changes)
    return canonical_json_bytes(request)


async def submit(db, authority, action_app, caller, *, key="k1", now=T0, **changes):
    async with db.transaction() as tx:
        return await admit(
            tx,
            authority,
            action_app,
            caller=caller,
            page_id=SCOPE.page_id,
            body=action_body(key, **changes),
            client="203.0.113.7",
            now=now,
        )


async def get_projection(db, authority, caller, *, projection=None, now=T0):
    async with db.transaction() as tx:
        return await read(
            tx, authority, caller=caller, page_id=SCOPE.page_id, projection=projection, now=now
        )


async def revoke_link(db, caller, *, actor=CREATOR, owner=False, now=T0):
    async with db.transaction() as tx:
        await revoke(tx, scope=SCOPE, link_id=caller.link_id, actor=actor, is_owner=owner, now=now)


def selection(*fields, records=("b-17",)):
    return {
        "collections": [
            {"collection": "bookings", "record_ids": list(records), "fields": list(fields)}
        ],
        "assets": [],
    }


async def test_reads_are_bounded_and_do_not_use_up_a_one_use_link(db, authority, action_app):
    caller = await holder(db, authority, one_use=True)
    for _ in range(2):
        checked = await get_projection(db, authority, caller, projection=selection("arrival"))
        assert checked.scope == SCOPE
        assert checked.mode == "live" and checked.page_rev is None
        assert checked.projection == selection("arrival")
    assert await db.fetch_value("SELECT used_at FROM {{tables.capability_links}}") is None
    with pytest.raises(LinkRefused, match="action_denied"):
        await get_projection(db, authority, caller, projection=selection("guest_note"))
    receipt = await submit(db, authority, action_app, caller)
    row = await db.fetch_one("SELECT used_at, used_by_operation FROM {{tables.capability_links}}")
    assert row["used_at"] == T0 and row["used_by_operation"] == receipt.operation_id
    with pytest.raises(LinkRefused) as refused:
        await get_projection(db, authority, caller)
    assert (refused.value.code, refused.value.status) == ("link_unavailable", 410)


@pytest.mark.parametrize(
    "projection",
    [
        selection("arrival", records=("b-18",)),
        {
            "collections": [{"collection": "other", "record_ids": ["b-17"], "fields": ["arrival"]}],
            "assets": [],
        },
        {"collections": [], "assets": ["secret-asset"]},
    ],
)
async def test_no_read_can_leave_the_frozen_projection(db, authority, projection):
    caller = await holder(db, authority)
    with pytest.raises(LinkRefused, match="action_denied"):
        await get_projection(db, authority, caller, projection=projection)


async def test_creator_authority_can_narrow_without_hiding_an_unaffected_field(db, authority):
    caller = await holder(db, authority)
    authority.reads[CREATOR]["bookings"] = Readable(("b-17",), frozenset({"arrival"}))
    with pytest.raises(LinkRefused, match="action_denied"):
        await get_projection(db, authority, caller, projection=selection("status"))
    assert (await get_projection(db, authority, caller, projection=selection("arrival"))).projection
    authority.reads[CREATOR]["bookings"] = Readable((), frozenset({"arrival"}))
    with pytest.raises(LinkRefused, match="action_denied"):
        await get_projection(db, authority, caller, projection=selection("arrival"))


@pytest.mark.parametrize("cause", ["one-use", "revoke", "authority"])
async def test_receipt_lookup_precedes_lifecycle_and_authority(db, authority, action_app, cause):
    caller = await holder(db, authority, one_use=cause == "one-use")
    first = await submit(db, authority, action_app, caller)
    if cause == "revoke":
        await revoke_link(db, caller)
    if cause == "authority":
        authority.actions[CREATOR].clear()
    assert await submit(db, authority, action_app, caller) == first
    with pytest.raises(LinkRefused) as changed:
        await submit(db, authority, action_app, caller, expected_page_rev=2)
    assert (changed.value.code, changed.value.status) == ("idempotency_conflict", 409)
    with pytest.raises(LinkRefused) as new:
        await submit(db, authority, action_app, caller, key="new")
    assert new.value.status == (403 if cause == "authority" else 410)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.test_link_actions}}") == 1


async def test_session_expiry_ends_both_read_and_receipt_replay(db, authority, action_app):
    caller = await holder(db, authority)
    await submit(db, authority, action_app, caller)
    for operation in (
        get_projection(db, authority, caller, now=T0 + timedelta(minutes=15)),
        submit(db, authority, action_app, caller, now=T0 + timedelta(minutes=15)),
    ):
        with pytest.raises(LinkRefused) as refused:
            await operation
        assert (refused.value.code, refused.value.status) == ("link_unavailable", 410)


@pytest.mark.parametrize(
    "changes", [{"input": "invalid"}, {"action_id": None}, {"task_authorization": {}}]
)
async def test_changed_bodies_conflict_before_new_action_schema_checks(
    db, authority, action_app, changes
):
    caller = await holder(db, authority)
    first = await submit(db, authority, action_app, caller)
    with pytest.raises(LinkRefused) as conflict:
        await submit(db, authority, action_app, caller, **changes)
    assert (conflict.value.code, conflict.value.status) == ("idempotency_conflict", 409)
    with pytest.raises(LinkRefused) as invalid:
        await submit(db, authority, action_app, caller, key="new-key", **changes)
    assert (invalid.value.code, invalid.value.status) == ("schema_invalid", 422)
    assert await submit(db, authority, action_app, caller) == first


async def test_expiry_boundary_from_the_contract(db, authority):
    request = request_from(CAPABILITY["delegation"][0]["link"])
    request["expires_at"] = CAPABILITY["expiry_sequence"][0]["expires_at"]
    caller = await holder(db, authority, request=request)
    assert await get_projection(db, authority, caller, now=T0 + timedelta(minutes=10, seconds=-1))
    with pytest.raises(LinkRefused) as expired:
        await get_projection(db, authority, caller, now=T0 + timedelta(minutes=10))
    assert expired.value.status == 410


@pytest.mark.parametrize(
    "changes", [dict(record_id="b-18"), dict(action_id="refund"), dict(action_id="approve-price")]
)
async def test_a_refused_action_neither_claims_nor_consumes_the_link(
    db, authority, action_app, changes
):
    caller = await holder(db, authority, one_use=True)
    with pytest.raises(LinkRefused, match="action_denied"):
        await submit(db, authority, action_app, caller, **changes)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.idempotency_keys}}") == 0
    assert await db.fetch_value("SELECT used_at FROM {{tables.capability_links}}") is None
    await submit(db, authority, action_app, caller)


async def test_an_action_failure_rolls_back_receipt_effect_and_one_use(db, authority, action_app):
    caller = await holder(db, authority, one_use=True)
    action_app.fail = True
    with pytest.raises(RuntimeError, match="app failed"):
        await submit(db, authority, action_app, caller)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.test_link_actions}}") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.idempotency_keys}}") == 0
    assert await db.fetch_value("SELECT used_at FROM {{tables.capability_links}}") is None
    action_app.fail = False
    await submit(db, authority, action_app, caller)


async def test_action_context_keeps_creator_separate_from_anonymous_provenance(
    db, authority, action_app
):
    caller = await holder(db, authority)
    result = (await submit(db, authority, action_app, caller)).result
    assert result["creator"] == CREATOR
    assert result["provenance"] == {
        "kind": "anonymous_link",
        "link_id": caller.link_id,
        "session_id": caller.session_id,
    }
    key = await db.fetch_value("SELECT key FROM {{tables.idempotency_keys}}")
    assert key == [SCOPE.installation_id, SCOPE.team_id, "link:" + caller.link_id, "k1"]


async def test_another_session_of_the_same_link_gets_the_same_receipt(db, authority, action_app):
    caller = await holder(db, authority)
    receipt = await submit(db, authority, action_app, caller)
    await db.execute(
        "INSERT INTO {{tables.link_sessions}} SELECT 'lks_second', link_id, session_did_key, "
        "csrf_sha256, created_at, expires_at FROM {{tables.link_sessions}} WHERE session_id=$1",
        caller.session_id,
    )
    assert (
        await submit(db, authority, action_app, replace(caller, session_id="lks_second")) == receipt
    )
    another = await holder(db, authority)
    assert (await submit(db, authority, action_app, another)).operation_id != receipt.operation_id


async def test_page_and_session_bindings_are_enforced(db, authority, action_app):
    caller = await holder(db, authority)
    async with db.transaction() as tx:
        with pytest.raises(LinkRefused, match="action_denied"):
            await read(tx, authority, caller=caller, page_id="other-page", now=T0)
    with pytest.raises(LinkRefused):
        await get_projection(db, authority, replace(caller, link_id="lnk_other"))


async def test_only_the_creator_or_verified_owner_can_revoke(db, authority):
    caller = await holder(db, authority)
    with pytest.raises(LinkRefused, match="action_denied"):
        await revoke_link(db, caller, actor="did:aw:someone")
    assert await get_projection(db, authority, caller)
    await revoke_link(db, caller, actor="did:aw:owner", owner=True)
    with pytest.raises(LinkRefused) as refused:
        await get_projection(db, authority, caller)
    assert refused.value.status == 410


async def test_concurrent_one_use_submits_admit_exactly_one(db, authority, action_app):
    caller = await holder(db, authority, one_use=True)

    async def attempt(key):
        try:
            return await submit(db, authority, action_app, caller, key=key)
        except LinkRefused as refused:
            assert refused.status == 410
            return None

    results = await asyncio.gather(*(attempt(f"key-{n}") for n in range(6)))
    assert sum(result is not None for result in results) == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.test_link_actions}}") == 1


async def test_concurrent_same_key_submits_return_one_receipt(db, authority, action_app):
    caller = await holder(db, authority, one_use=True)
    results = await asyncio.gather(*(submit(db, authority, action_app, caller) for _ in range(6)))
    assert len({result.operation_id for result in results}) == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.test_link_actions}}") == 1


@pytest.mark.parametrize("first", ["action", "revoke", "read"])
async def test_revocation_serializes_with_actions_and_reads(db, authority, action_app, first):
    caller = await holder(db, authority)
    async with db.transaction() as tx:
        if first == "revoke":
            await revoke(
                tx, scope=SCOPE, link_id=caller.link_id, actor=CREATOR, is_owner=False, now=T0
            )
            pending = asyncio.create_task(submit(db, authority, action_app, caller))
        elif first == "action":
            receipt = await admit(
                tx,
                authority,
                action_app,
                caller=caller,
                page_id=SCOPE.page_id,
                body=action_body(),
                client="203.0.113.7",
                now=T0,
            )
            pending = asyncio.create_task(revoke_link(db, caller))
        else:
            await read(tx, authority, caller=caller, page_id=SCOPE.page_id, now=T0)
            pending = asyncio.create_task(revoke_link(db, caller))
        # Yield through a real query while the first transaction retains its lock.
        await db.fetch_value("SELECT 1")
        assert not pending.done()
    if first == "revoke":
        with pytest.raises(LinkRefused) as refused:
            await pending
        assert refused.value.status == 410
    else:
        await pending
        if first == "action":
            assert await submit(db, authority, action_app, caller) == receipt
    with pytest.raises(LinkRefused) as refused:
        await get_projection(db, authority, caller)
    assert refused.value.status == 410


async def test_read_bucket_refills(db, authority):
    caller = await holder(db, authority)
    for _ in range(120):
        await get_projection(db, authority, caller)
    with pytest.raises(LinkRefused) as refused:
        await get_projection(db, authority, caller)
    assert (refused.value.code, refused.value.status, refused.value.retry_after_s) == (
        "safety_rate_limited",
        429,
        1,
    )
    await get_projection(db, authority, caller, now=T0 + timedelta(seconds=1))


async def test_link_write_bucket_and_replays(db, authority, action_app):
    caller = await holder(db, authority)
    first = await submit(db, authority, action_app, caller)
    for n in range(1, 20):
        await submit(db, authority, action_app, caller, key=f"k{n + 1}")
    assert await submit(db, authority, action_app, caller) == first
    with pytest.raises(LinkRefused) as refused:
        await submit(db, authority, action_app, caller, key="overflow")
    assert (refused.value.code, refused.value.retry_after_s) == ("safety_rate_limited", 3)
    await submit(db, authority, action_app, caller, key="overflow", now=T0 + timedelta(seconds=3))


async def test_client_write_bucket_is_shared_by_links(db, authority, action_app):
    for _ in range(3):
        caller = await holder(db, authority)
        for n in range(20):
            await submit(db, authority, action_app, caller, key=f"k{n}")
    caller = await holder(db, authority)
    with pytest.raises(LinkRefused) as refused:
        await submit(db, authority, action_app, caller)
    assert (refused.value.code, refused.value.retry_after_s) == ("safety_rate_limited", 1)
    await submit(db, authority, action_app, caller, now=T0 + timedelta(seconds=1))


@pytest.mark.parametrize("loss", ["field", "record", "collection", "asset"])
async def test_apply_receives_only_current_read_access(db, authority, action_app, loss):
    request = request_from(CAPABILITY["delegation"][0]["link"])
    authority.assets[CREATOR] = {"photo"}
    request["projection"]["assets"] = ["photo"]
    caller = await holder(db, authority, request=request)
    if loss == "field":
        authority.reads[CREATOR]["bookings"] = Readable(
            ("b-17", "new-row"), frozenset({"arrival", "new-field"})
        )
    elif loss == "record":
        authority.reads[CREATOR]["bookings"] = Readable(("new-row",), frozenset({"arrival"}))
    elif loss == "collection":
        authority.reads[CREATOR].clear()
    else:
        authority.assets[CREATOR].clear()
    receipt = await submit(db, authority, action_app, caller)
    projected = receipt.result["projection"]
    assert projected["assets"] == ([] if loss == "asset" else ["photo"])
    if loss in {"record", "collection"}:
        assert projected["collections"] == []
    elif loss == "field":
        assert projected["collections"] == selection("arrival")["collections"]
    else:
        assert projected["collections"] == request["projection"]["collections"]
    # The stored mint projection is immutable, even as current authority narrows.
    stored = await db.fetch_value("SELECT record FROM {{tables.capability_links}}")
    stored = json.loads(stored) if isinstance(stored, str) else stored
    assert stored["projection"] == request["projection"]

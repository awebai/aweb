"""Terminal broker/run receipts through the production B1/B2/S3 composition."""

import json
from uuid import uuid4

import pytest

from tests.test_production_bootstrap import approval_request
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import admitted_run, member_replay
from tests.test_production_runner_dispatch import runner_headers
from tests.test_use_approvals import SECRET


async def contain(root, action, target):
    _, client, configured, member, *_ = root
    path = "/v1/containment"
    raw = json.dumps({"request_id": uuid4().hex, "action": action, "target": target}).encode()
    reply = await client.post(
        configured.public_origin + path,
        content=raw,
        headers=member.headers(aud=configured.public_origin, method="POST", path=path, body=raw)
        | {"Content-Type": "application/json"},
    )
    assert reply.status_code == 200, (reply.status_code, reply.json().get("detail"))


async def status(root, pending):
    _, client, configured, member, *_ = root
    path = "/v1/status/" + pending.reply["request_ref"]
    return await client.get(
        configured.public_origin + path,
        headers=member.headers(aud=configured.public_origin, method="GET", path=path),
    )


async def snapshot(db):
    rows = {
        table: [dict(row) for row in await db.fetch_all("SELECT * FROM " + table + " ORDER BY 1")]
        for table in (
            "intents",
            "dispatches",
            "idempotency_keys",
            "use_contexts",
            "run_contexts",
            "run_deliveries",
            "run_approval_admissions",
            "approvals",
            "scoped_nonces",
            "rate_buckets",
            "broker_use_events",
        )
    }
    # Delivery retries belong to the running shared drain. Receipt retrieval
    # must neither enqueue an event nor alter its signed content.
    rows["outbox_events"] = [
        dict(row)
        for row in await db.fetch_all(
            "SELECT event_id,payload,signature FROM outbox_events ORDER BY position"
        )
    ]
    return rows


async def assert_terminal_receipt(root, pending, expected):
    db = root[0].runtime.db()
    before = await snapshot(db)
    for _ in range(2):
        looked_up = await status(root, pending)
        assert looked_up.status_code == 200 and looked_up.json() == expected
        replayed = await member_replay(root, pending)
        assert replayed.status_code == 200, (replayed.status_code, replayed.json().get("code"))
        assert replayed.json() == expected
    if await snapshot(db) != before:
        raise AssertionError("terminal status/replay changed persisted domain or audit state")


@pytest.mark.parametrize("kind", ["use", "run"])
async def test_revoked_approval_closes_as_cancelled_for_status_and_exact_replay(root, kind):
    pending = await approval_request(root, kind)
    db = root[0].runtime.db()
    approval_id = await db.fetch_value("SELECT approval_id FROM approvals")
    await contain(root, "revoke-approvals", approval_id)
    # Live B2 revocation and its first refusing POST remain distinct from the
    # persisted S3 terminal cancellation that subsequent reads retrieve.
    live = await status(root, pending)
    assert live.status_code == 200 and live.json()["code"] == "approval_revoked"
    assert await db.fetch_value("SELECT state FROM dispatches") == "awaiting_approval"
    denied = await member_replay(root, pending)
    assert denied.status_code == 403 and denied.json()["code"] == "approval_revoked"
    assert await db.fetch_value("SELECT state FROM dispatches") == "cancelled"
    assert await db.fetch_value("SELECT attempts FROM dispatches") == 0
    await assert_terminal_receipt(
        root,
        pending,
        {
            "state": "cancelled",
            "request_id": pending.reply["request_id"],
            "request_ref": pending.reply["request_ref"],
        },
    )


async def test_stored_run_preparation_refusal_is_a_readable_receipt_not_a_new_503(root):
    pending = await admitted_run(root)
    _, client, configured, *_ = root
    db = root[0].runtime.db()
    await contain(root, "disable-secret", SECRET["secret_id"])
    path = "/runner/v1/claim"
    failed = await client.post(
        configured.public_origin + path,
        content=b"{}",
        headers=runner_headers(pending, configured.public_origin, path),
    )
    assert failed.status_code == 503
    assert failed.json()["detail"]["code"] == "runner_unavailable"
    assert await db.fetch_value("SELECT state FROM dispatches") == "refused"
    assert await db.fetch_value("SELECT attempts FROM dispatches") == 0
    assert await db.fetch_value("SELECT assignment FROM run_deliveries") is None
    await assert_terminal_receipt(
        root,
        pending,
        {
            "state": "refused",
            "request_id": pending.reply["request_id"],
            "request_ref": pending.reply["request_ref"],
            "code": "custody_unavailable",
        },
    )

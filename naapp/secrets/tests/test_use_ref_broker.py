"""Public broker receipts join signed events without disclosing caller IDs."""

import json
import re
import secrets
from dataclasses import replace

import asyncpg
import pytest
from aweb_naapp.runtime.approvals import Assurance, Decision

from aweb_secrets import records
from tests.harness import running_upstream
from tests.test_broker_approved_service import setup as approved_setup
from tests.test_broker_audit import INSTALLATION, envelopes
from tests.test_broker_service import db as db
from tests.test_broker_service import fence as fence
from tests.test_broker_service import setup, submission
from tests.test_use_approvals import SECRET
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


def use_events(events):
    return [event for event in events if event["hook"] == "post-secret-use-hook"]


def assert_scope(events, authorization):
    """The public join includes signed producer scope and canonical actor IDs."""
    principal, grant = authorization.principal, authorization.grant
    for event in events:
        assert event["team_id"] == principal.team_id
        assert event["producer"]["installation_id"] == grant.installation_id
        assert event["producer"]["generation"] == grant.generation
        assert event["actor"]["did_key"] == principal.did_key
        if principal.did_aw_registry_verified:
            assert event["actor"]["did_aw"] == principal.did_aw
        else:
            assert "did_aw" not in event["actor"]


async def snapshot(db):
    return {
        table: [
            dict(row)
            for row in await db.fetch_all("SELECT * FROM {{tables." + table + "}} ORDER BY 1")
        ]
        for table in (
            "intents",
            "dispatches",
            "idempotency_keys",
            "rate_buckets",
            "broker_use_events",
            "outbox_events",
            "outbox_sequences",
        )
    }


async def test_broker_public_ref_is_stable_through_send_and_stored_replay(db, fence, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        marker = secrets.token_urlsafe(32)
        original = submission(upstream, request_id=marker)
        reply = await service.submit(secret=SECRET["ref"], submission=original)
        assert reply.body["state"] == "completed"
        assert await service.submit(secret=SECRET["ref"], submission=original) == reply
        events = use_events(await envelopes(db))
        assert_scope(events, original.authorization)
        assert [e["payload"]["action"] for e in events] == ["admitted", "dispatching", "completed"]
        assert all(e["payload"]["use_ref"] == reply.body["request_ref"] for e in events)
        if marker in json.dumps(events):
            raise AssertionError("caller request ID reached a signed broker event")


@pytest.mark.parametrize("injected", [False, True])
async def test_each_committed_pre_admission_refusal_has_a_new_public_ref(
    db, fence, tmp_path, injected
):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        if not injected:
            async with db.transaction() as tx:
                await records.revoke_grant(tx, INSTALLATION, "grt_alice001")
        marker = secrets.token_urlsafe(32)
        request = submission(
            upstream, request_id=marker, **({"use_ref": "caller-injected"} if injected else {})
        )
        refs = []
        for _ in range(2):
            reply = await service.submit(secret=SECRET["ref"], submission=request)
            assert reply.body["state"] == "refused"
            assert reply.body["code"] == ("params_invalid" if injected else "grant_missing")
            ref = reply.body["use_ref"]
            assert re.fullmatch(r"use_[A-Za-z0-9_-]{22}", ref)
            refs.append(ref)
        assert refs[0] != refs[1]
        events = use_events(await envelopes(db))
        assert_scope(events, request.authorization)
        assert [e["payload"]["use_ref"] for e in events] == refs
        assert all("dispatch_id" not in e["payload"] for e in events)
        if marker in json.dumps(events) or "caller-injected" in json.dumps(events):
            raise AssertionError("caller correlation input reached a signed refusal")
        for table in ("intents", "dispatches", "idempotency_keys", "rate_buckets"):
            assert await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0
        assert upstream.paths == []


async def test_broker_refusal_of_an_existing_use_retains_the_original_ref(db, fence, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        original = submission(upstream)
        completed = await service.submit(secret=SECRET["ref"], submission=original)
        async with db.transaction() as tx:
            await records.revoke_grant(tx, INSTALLATION, "grt_alice001")
        refused = await service.submit(secret=SECRET["ref"], submission=original)
        assert refused.body["code"] == "grant_revoked"
        assert refused.body["use_ref"] == completed.body["request_ref"]
        assert (
            use_events(await envelopes(db))[-1]["payload"]["use_ref"]
            == completed.body["request_ref"]
        )


async def test_failed_refusal_recording_rolls_back_both_records_and_presents_no_ref(
    db, fence, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        async with db.transaction() as tx:
            await records.revoke_grant(tx, INSTALLATION, "grt_alice001")
        await db.execute(
            "ALTER TABLE {{tables.broker_use_events}} ADD CONSTRAINT fail_refusal CHECK(false) NOT VALID"
        )
        before, replies = await snapshot(db), []
        with pytest.raises(asyncpg.CheckViolationError):
            replies.append(
                await service.submit(secret=SECRET["ref"], submission=submission(upstream))
            )
        assert replies == []
        assert await snapshot(db) == before


async def test_unattributed_submission_presents_no_audit_ref(db, fence, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        original = submission(upstream)
        invalid = replace(
            original,
            authorization=replace(
                original.authorization, tool=replace(original.authorization.tool, name="other")
            ),
        )
        before = await snapshot(db)
        refused = await service.submit(secret=SECRET["ref"], submission=invalid)
        assert refused.body["state"] == "refused" and "use_ref" not in refused.body
        assert await snapshot(db) == before


async def test_broker_approval_wait_decision_resubmission_and_replay_keep_one_ref(uses, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        service, audit, view, request = await approved_setup(uses, tmp_path, upstream)
        pending = await service.submit(secret=SECRET["ref"], submission=request)
        assert pending.body["state"] == "awaiting_approval"
        assert (await service.submit(secret=SECRET["ref"], submission=request)).body[
            "request_ref"
        ] == pending.body["request_ref"]
        link = await uses.world.db.fetch_one("SELECT * FROM {{tables.use_approvals}}")
        [token] = [
            t for a, t in uses.world.inbox.links["finance@acme.com"] if a == link["approval_id"]
        ]
        options = await uses.approvals.challenge(
            link["approval_id"], Decision.APPROVE, Assurance.PASSKEY, link_token=token
        )
        with audit.prepared_view(view):
            await uses.approvals.decide(
                link["approval_id"],
                Decision.APPROVE,
                Assurance.PASSKEY,
                uses.world.devices["finance@acme.com"].get(dict(options)),
                link_token=token,
            )
        result = await service.submit(secret=SECRET["ref"], submission=request)
        assert (
            result.body["state"] == "completed"
            and result.body["request_ref"] == pending.body["request_ref"]
        )
        assert await service.submit(secret=SECRET["ref"], submission=request) == result
        events = use_events(await envelopes(uses.world.db))
        assert_scope(events, request.authorization)
        assert [e["payload"]["action"] for e in events] == [
            "approval_requested",
            "approval_decided",
            "admitted",
            "dispatching",
            "completed",
        ]
        assert all(e["payload"]["use_ref"] == pending.body["request_ref"] for e in events)

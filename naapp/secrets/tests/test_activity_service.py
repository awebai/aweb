"""Actual broker records projected through a read-only, scoped keyset page."""

from dataclasses import asdict, replace
from datetime import timedelta

import pytest
from aweb_naapp.hooks.commitment import CommitmentContext

from aweb_secrets import records
from aweb_secrets.activity_service import ActivityCursor, ActivityReads
from aweb_secrets.broker_audit import record_broker_refusal
from aweb_secrets.secret import SecretRecord
from aweb_secrets.use_context import UseCommitments
from tests.test_admission import ALICE, NOW, SECRET, TEAM
from tests.test_broker_audit import INSTALLATION, authority, prepared, source
from tests.test_broker_audit import db as db
from tests.test_broker_audit import fence as fence


async def test_projection_keeps_original_correlation_after_metadata_changes(db, fence):
    request, admitted, dispatch_id, machine = await prepared(db, fence)
    async with db.transaction() as tx:
        await machine.admit(tx, dispatch_id, fence=authority(fence, admitted, request, dispatch_id))
    async with db.transaction() as tx:
        await records.update_secret(
            tx,
            INSTALLATION,
            TEAM,
            SecretRecord.from_after(
                {
                    **SECRET,
                    "ref": "renamed-after-the-event",
                }
            ),
        )
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION READ ONLY")
        page = await ActivityReads().page(tx, installation_id=INSTALLATION, team_id=TEAM)
    assert len(page.entries) == 1 and page.next_cursor is None
    entry = page.entries[0]
    assert entry.secret_ref == SECRET["ref"]
    assert entry.secret_id == SECRET["secret_id"]
    assert (entry.request_id, entry.request_ref, entry.dispatch_id) == (
        request.request_id,
        admitted.intent_id,
        dispatch_id,
    )
    assert entry.principal_did == ALICE.did_aw
    assert entry.action == entry.outcome == "admitted"
    assert (
        not {"payload", "actor", "params", "result", "url", "request_sha256"} & asdict(entry).keys()
    )
    assert entry.job_id is entry.runner_id is entry.approval_ref is None
    assert isinstance(entry.occurred_at, type(NOW)) and entry.occurred_at.utcoffset() is not None


async def test_same_timestamp_pages_have_no_gaps_or_repeats_and_scope_never_crosses(db, fence):
    _, admitted, _, _ = await prepared(db, fence)
    context = CommitmentContext(
        "secrets", TEAM, INSTALLATION, admitted.installation.generation, "request"
    )
    ids = []
    async with db.transaction() as tx:
        for index in range(5):
            ids.append(
                await record_broker_refusal(
                    tx,
                    producer=source(INSTALLATION, context.generation),
                    principal=ALICE,
                    commitments=UseCommitments(context, "a" * 64, None),
                    code="params_invalid",
                    occurred_at=NOW,
                    request_id=f"request-{index}",
                    secret_ref=SECRET["ref"],
                )
            )
        foreign = replace(context, team_id="backend:foreign.example")
        await record_broker_refusal(
            tx,
            producer=source(INSTALLATION, context.generation),
            principal=replace(ALICE, team_id=foreign.team_id),
            commitments=UseCommitments(foreign, "b" * 64, None),
            code="params_invalid",
            occurred_at=NOW + timedelta(seconds=1),
            request_id="foreign",
            secret_ref="foreign",
        )
    collected, cursor = [], None
    while True:
        async with db.transaction() as tx:
            await tx.execute("SET TRANSACTION READ ONLY")
            page = await ActivityReads().page(
                tx,
                installation_id=INSTALLATION,
                team_id=TEAM,
                before=cursor,
                limit=2,
            )
        collected.extend(entry.event_id for entry in page.entries)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
        assert isinstance(cursor, ActivityCursor)
    assert collected == sorted(ids, reverse=True)
    async with db.transaction() as tx:
        empty = await ActivityReads().page(tx, installation_id="foreign", team_id=TEAM)
    assert empty.entries == () and empty.next_cursor is None


@pytest.mark.parametrize("limit", [True, False, 0, -1, 101, "50", None])
async def test_limits_refuse_instead_of_unbounded_reads(db, limit):
    async with db.transaction() as tx:
        with pytest.raises(ValueError):
            await ActivityReads().page(tx, installation_id=INSTALLATION, team_id=TEAM, limit=limit)

"""Broker submissions through real admission, S3, signed outbox, custody and TLS."""

import asyncio
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.commitment import CommitmentKey, Purpose, RequestBytes
from aweb_naapp.hooks.producer import HookProducer
from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.runtime.authorization import Authorization, DeclaredTool
from aweb_naapp_testing.network import make_certificates
from fastapi import Request, Response

from aweb_secrets import records
from aweb_secrets.broker_service import BrokerRequests
from aweb_secrets.custody import (
    Custody,
    LocalKeyFileProvider,
    apply_custody_migrations,
    encode_value,
)
from aweb_secrets.custody.opening import UseSecretOpener
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.member_types import MemberSubmission
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.tokens import ProcessTokenCache
from aweb_secrets.use_approvals import apply_use_approval_migrations
from aweb_secrets.use_context import UseCommitter, apply_use_context_migrations
from tests.harness import running_upstream
from tests.test_admission import ALICE, BOB, NOW, SECRET, TEAM, _grant_source_grant, _install
from tests.test_broker_audit import INSTALLATION, envelopes, source, view
from tests.test_broker_audit import db as db
from tests.test_broker_audit import fence as fence

REQUEST = DeclaredTool(
    "request",
    "POST",
    "/v1/secrets/{secret}/requests",
    frozenset({"secrets:use"}),
    frozenset({"agent"}),
)


def submission(upstream, **changes):
    body = {
        "request_id": "first-use",
        "method": "POST",
        "url": upstream.url("/bearer/echo"),
        "data": {"message": "hello"},
        **changes,
    }
    return MemberSubmission(
        Authorization(ALICE, REQUEST, _grant_source_grant(installation_id=INSTALLATION)),
        RequestBytes(
            "POST",
            b"/v1/secrets/staging-api/requests",
            (b"application/json",),
            json.dumps(body).encode(),
        ),
    )


async def setup(
    db,
    fence,
    tmp_path,
    upstream,
    *,
    max_dispatch=timedelta(seconds=30),
    registration_view=None,
    clock=None,
    sweep_margin=timedelta(seconds=5),
):
    await _install(db, installation_id=INSTALLATION, active_version=None)
    for migration in (
        apply_dispatch_migrations,
        apply_outbox_migrations,
        apply_custody_migrations,
        apply_use_context_migrations,
        apply_use_approval_migrations,
    ):
        await migration(db)
    key_file = tmp_path / "custody-key"
    key_file.write_text(os.urandom(32).hex() + "\n")
    key_file.chmod(0o600)
    custody = Custody(LocalKeyFileProvider(key_file), db)
    destination = DestinationRecord.from_after(
        {
            "v": 1,
            "destination_id": "dst_broker01",
            "secret_id": SECRET["secret_id"],
            "scheme": "https",
            "host": "upstream.secrets.test",
            "port": upstream.port,
            "path": "/bearer/**",
            "methods": ["GET", "POST"],
            "query_rules": {},
            "header_allow": [],
            "network": "internal",
            "cidr": f"{upstream.host}/32",
        },
        internal_destinations=InternalDestinations.ALLOWED,
    )
    async with db.transaction() as tx:
        version = await custody.sealer.ingest(
            tx,
            installation_id=INSTALLATION,
            team_id=TEAM,
            secret_id=SECRET["secret_id"],
            value=encode_value("bearer", {"value": upstream.creds.bearer}),
        )
        await records.set_active_version(tx, INSTALLATION, TEAM, SECRET["secret_id"], version)
        await records.create_destination(tx, INSTALLATION, TEAM, destination)

    def producer(*, installation_id, generation):
        original = source(installation_id, generation)
        return original if clock is None else HookProducer(original.producer, clock=clock)

    async def registration(team_id):
        if clock is None:
            return await _view(team_id)
        from tests.test_use_audit import targets

        assert team_id == TEAM
        return targets(clock())

    return BrokerRequests(
        db,
        fence=fence,
        opener=UseSecretOpener(
            db, native=custody.opener, credential_opener=custody.backend_credential_opener
        ),
        egress=upstream.egress,
        tokens=ProcessTokenCache(),
        committer=UseCommitter(
            CommitmentKey(Purpose.SECRET_REQUEST, os.urandom(32)),
            CommitmentKey(Purpose.SECRET_PARAMS, os.urandom(32)),
        ),
        response_key=ResponseKey(os.urandom(32)),
        producer=producer,
        registration_view=registration_view or registration,
        max_backlog_age=timedelta(minutes=5),
        max_dispatch=max_dispatch,
        sweep_margin=sweep_margin,
        derived_max_ttl_s=3600,
        internal_destinations=InternalDestinations.ALLOWED,
        clock=clock or (lambda: NOW),
    )


async def _view(team_id):
    assert team_id == TEAM
    return view()


async def test_fresh_authenticated_submission_sends_once_and_replays_stored_result(
    db, fence, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        original = submission(upstream)
        first = await service.submit(secret=SECRET["ref"], submission=original)
        assert first.status == 200 and first.body["state"] == "completed", (
            first.status,
            first.body.get("state"),
            first.body.get("code"),
        )
        renewed = replace(
            original,
            authorization=replace(
                original.authorization,
                principal=replace(ALICE, certificate_id="renewed"),
            ),
        )
        second = await service.submit(secret=SECRET["ref"], submission=renewed)
        assert second == first
        assert upstream.paths == ["/bearer/echo"]
        assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 1
        assert await db.fetch_value("SELECT count(*) FROM {{tables.dispatches}}") == 1
        assert [e["payload"]["action"] for e in await envelopes(db)] == [
            "admitted",
            "dispatching",
            "completed",
        ]
        original_actor = (await envelopes(db))[0]["actor"]
        assert original_actor["certificate_id"] == ALICE.certificate_id
        if upstream.creds.bearer in repr(first) + repr(await envelopes(db)):
            raise AssertionError("credential appeared in reply or audit")


async def test_changed_effect_with_same_request_id_refuses_without_a_second_send(
    db, fence, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        await service.submit(secret=SECRET["ref"], submission=submission(upstream))
        result = await service.submit(
            secret=SECRET["ref"],
            submission=submission(upstream, data={"message": "changed"}),
        )
        assert result.status == 409 and result.body["code"] == "idempotency_conflict"
        assert upstream.paths == ["/bearer/echo"]
        assert await db.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 1


async def test_revoked_use_grant_prevents_replay_and_other_principal_cannot_read_receipt(
    db, fence, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        await service.submit(secret=SECRET["ref"], submission=submission(upstream))
        async with db.transaction() as tx:
            await records.revoke_grant(tx, INSTALLATION, "grt_alice001")
        result = await service.submit(secret=SECRET["ref"], submission=submission(upstream))
        assert result.body["state"] == "refused" and result.body["code"] == "grant_revoked"
        assert upstream.paths == ["/bearer/echo"]


async def test_failed_initial_destination_rolls_back_idempotency_intent_and_rate_charge(
    db, fence, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream)
        reply = await service.submit(
            secret=SECRET["ref"],
            submission=submission(upstream, url=upstream.url("/basic/echo")),
        )
        assert reply.body["state"] == "refused" and reply.body["code"] == "destination_not_in_scope"
        for table in ("intents", "dispatches", "idempotency_keys", "rate_buckets"):
            assert await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0
        assert upstream.paths == []
        assert [e["payload"]["action"] for e in await envelopes(db)] == ["refused"]


async def test_missing_audit_target_is_unavailable_without_retaining_an_admission(
    db, fence, tmp_path
):
    async def no_targets(team_id):
        return replace(await _view(team_id), registrations=())

    async with running_upstream(tmp_path) as upstream:
        service = await setup(db, fence, tmp_path, upstream, registration_view=no_targets)
        reply = await service.submit(secret=SECRET["ref"], submission=submission(upstream))
        assert reply.status == 503 and reply.body["code"] == "audit_target_unavailable"
        for table in ("intents", "dispatches", "idempotency_keys", "rate_buckets"):
            assert await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0
        assert upstream.paths == []
        assert [e["payload"]["action"] for e in await envelopes(db)] == ["refused"]


@pytest.mark.parametrize("next_call", ["same-pair", "different-url", "different-principal"])
async def test_real_transport_deadline_records_unknown_and_never_resends(
    db, fence, tmp_path, next_call
):
    async with running_upstream(tmp_path) as upstream:
        entered, release = asyncio.Event(), asyncio.Event()

        @upstream.app.post("/bearer/slow")
        async def slow(request: Request):
            if request.headers.get("authorization") != "Bearer " + upstream.creds.bearer:
                return Response(status_code=403)
            if not entered.is_set():
                entered.set()
                await release.wait()
            return Response(status_code=204)

        service = await setup(db, fence, tmp_path, upstream, max_dispatch=timedelta(seconds=3))
        original = submission(upstream, url=upstream.url("/bearer/slow"))
        try:
            first = await service.submit(secret=SECRET["ref"], submission=original)
            assert entered.is_set()
            assert first.status == 200 and first.body["state"] == "outcome_unknown"
            second = await service.submit(secret=SECRET["ref"], submission=original)
            assert second == first
            assert upstream.paths == ["/bearer/slow"]
            assert (
                await db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "outcome_unknown"
            )
            assert [e["payload"]["action"] for e in await envelopes(db)] == [
                "admitted",
                "dispatching",
                "outcome_unknown",
            ]
            followup = submission(
                upstream,
                request_id="after-unknown",
                url=upstream.url(
                    "/bearer/echo" if next_call == "different-url" else "/bearer/slow"
                ),
            )
            if next_call == "different-principal":
                await _install(
                    db,
                    installation_id=INSTALLATION,
                    grant_id="grt_other001",
                    subject={"principal": BOB.did_aw},
                )
                followup = replace(
                    followup, authorization=replace(followup.authorization, principal=BOB)
                )
            after = await service.submit(secret=SECRET["ref"], submission=followup)
            if next_call == "same-pair":
                assert after.status == 409 and after.body["code"] == "reconciliation_pending"
                assert upstream.paths == ["/bearer/slow"]
            else:
                assert after.status == 200 and after.body["state"] == "completed", (
                    after.status,
                    after.body.get("state"),
                    after.body.get("code"),
                )
                assert len(upstream.paths) == 2
        finally:
            release.set()


async def test_tls_not_sent_retry_keeps_its_original_total_time_bound(db, fence, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        wrong_directory = tmp_path / "wrong-trust"
        wrong_directory.mkdir()
        wrong = make_certificates(wrong_directory, ["upstream.secrets.test"], [])
        trust = tmp_path / "retry-ca.pem"
        trust.write_bytes(wrong.ca_file.read_bytes())
        at = [datetime.now(UTC)]
        service = await setup(
            db,
            fence,
            tmp_path,
            replace(upstream, egress=replace(upstream.egress, ca_file=trust)),
            clock=lambda: at[0],
        )
        original = submission(upstream)
        first = await service.submit(secret=SECRET["ref"], submission=original)
        assert first.status == 503 and first.body["state"] == "not_sent"
        assert upstream.paths == []
        started = await db.fetch_value("SELECT dispatch_started_at FROM {{tables.use_contexts}}")
        trust.write_bytes(upstream.egress.ca_file.read_bytes())
        at[0] = started + timedelta(seconds=31)
        second = await service.submit(secret=SECRET["ref"], submission=original)
        assert second.status == 403 and second.body["code"] == "operation_not_allowed"
        assert upstream.paths == []
        assert await db.fetch_value("SELECT attempts FROM {{tables.dispatches}}") == 1
        assert (
            await db.fetch_value("SELECT dispatch_started_at FROM {{tables.use_contexts}}")
            == started
        )


async def test_cancelled_sender_is_recovered_only_after_its_dispatch_bound(db, fence, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        entered, release = asyncio.Event(), asyncio.Event()

        @upstream.app.post("/bearer/crash")
        async def receiver(request: Request):
            if request.headers.get("authorization") != "Bearer " + upstream.creds.bearer:
                return Response(status_code=403)
            entered.set()
            await release.wait()
            return Response(status_code=204)

        service = await setup(
            db,
            fence,
            tmp_path,
            upstream,
            max_dispatch=timedelta(seconds=1),
            sweep_margin=timedelta(milliseconds=100),
        )
        original = submission(upstream, url=upstream.url("/bearer/crash"))
        sender = asyncio.create_task(service.submit(secret=SECRET["ref"], submission=original))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            sender.cancel()
            with pytest.raises(asyncio.CancelledError):
                await sender
            assert await db.fetch_value("SELECT state FROM {{tables.dispatches}}") == "dispatching"
            assert await service.sweep() == 0
            await asyncio.sleep(1.2)
            assert await service.sweep() == 1
            assert await service.sweep() == 0
            receipt = await service.submit(secret=SECRET["ref"], submission=original)
            assert receipt.status == 200 and receipt.body["state"] == "outcome_unknown"
            assert upstream.paths == ["/bearer/crash"]
            assert [e["payload"]["action"] for e in await envelopes(db)] == [
                "admitted",
                "dispatching",
                "outcome_unknown",
            ]
        finally:
            release.set()
            if not sender.done():
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)

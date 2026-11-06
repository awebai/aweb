"""A real passkey decision never sends; a fresh broker submission consumes it."""

import asyncio
import json
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.commitment import CommitmentKey, Purpose, RequestBytes
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
from aweb_naapp.runtime.approvals import (
    Approvals,
    Assurance,
    Decision,
    DispatchOutcome,
    PgApprovalStore,
)
from aweb_naapp.runtime.authorization import Authorization
from fastapi import Request, Response

from aweb_secrets import records
from aweb_secrets.broker_service import BrokerRequests
from aweb_secrets.custody import apply_custody_migrations, encode_value
from aweb_secrets.custody.opening import UseSecretOpener
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.member_types import MemberSubmission
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.tokens import ProcessTokenCache
from aweb_secrets.use_approvals import UseApprovers, UsePolicies
from aweb_secrets.use_audit import UseApprovalAudit
from aweb_secrets.use_context import UseCommitter, apply_use_context_migrations
from aweb_secrets.use_dispatch_authority import UseDispatchAuthority
from tests.harness import running_upstream
from tests.test_broker_audit import envelopes
from tests.test_broker_service import REQUEST
from tests.test_change_sets import ALICE
from tests.test_use_approvals import REQUESTER, SECRET, TEAM, designate, install
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world
from tests.test_use_audit import targets


async def setup(
    uses,
    tmp_path,
    upstream,
    *,
    owner=False,
    path="/bearer/echo",
    max_dispatch=timedelta(seconds=30),
    sweep_margin=timedelta(seconds=5),
    availability=None,
):
    if owner:
        await install(uses, approvers=[f"owner:{ALICE.principal_did}"])
    else:
        await designate(uses, "finance", "finance@acme.com")
        await install(uses)
    db = uses.world.db
    for migration in (
        apply_dispatch_migrations,
        apply_custody_migrations,
        apply_use_context_migrations,
    ):
        await migration(db)
    seed = secrets.token_bytes(32)

    def producer(*, installation_id, generation):
        return HookProducer(
            ServerProducer.app(
                origin="https://secrets.example.com",
                app_id="secrets",
                installation_id=installation_id,
                generation=generation,
                kid="approved-broker",
                seed=seed,
            ),
            clock=uses.clock,
        )

    store = PgApprovalStore(db)

    async def approval(tx, approval_id):
        return await store.get_in(approval_id, tx)

    audit = UseApprovalAudit(
        producer=producer,
        passkeys=lambda: uses.world.passkeys,
        approval=approval,
        max_backlog_age=timedelta(minutes=5),
        clock=uses.clock,
    )
    uses.approvals = Approvals(
        store=store,
        policies=UsePolicies(db),
        approvers=UseApprovers(db, uses.world.passkeys, uses.world.directory),
        delivery=uses.world.inbox,
        authenticators=[uses.world.passkeys.authenticator()],
        audit=audit,
        clock=uses.clock,
    )
    custody = uses.world.custody
    scope = uses.world.admitted
    async with db.transaction() as tx:
        version = await custody.sealer.ingest(
            tx,
            installation_id=scope.installation_id,
            team_id=TEAM,
            secret_id=SECRET["secret_id"],
            value=encode_value("bearer", {"value": upstream.creds.bearer}),
        )
        await records.set_active_version(
            tx, scope.installation_id, TEAM, SECRET["secret_id"], version
        )
        await records.create_destination(
            tx,
            scope.installation_id,
            TEAM,
            DestinationRecord.from_after(
                {
                    "v": 1,
                    "destination_id": "dst_approved",
                    "secret_id": SECRET["secret_id"],
                    "scheme": "https",
                    "host": "upstream.secrets.test",
                    "port": upstream.port,
                    "path": "/bearer/**",
                    "methods": ["POST"],
                    "query_rules": {},
                    "header_allow": [],
                    "network": "internal",
                    "cidr": f"{upstream.host}/32",
                },
                internal_destinations=InternalDestinations.ALLOWED,
            ),
        )
    view = targets(uses.clock())

    async def registration_view(team_id):
        assert team_id == TEAM
        return view if availability is None or availability[0] else None

    service = BrokerRequests(
        db,
        fence=uses.world.fence,
        opener=UseSecretOpener(
            db, native=custody.opener, credential_opener=custody.backend_credential_opener
        ),
        egress=upstream.egress,
        tokens=ProcessTokenCache(),
        committer=UseCommitter(
            CommitmentKey(Purpose.SECRET_REQUEST, secrets.token_bytes(32)),
            CommitmentKey(Purpose.SECRET_PARAMS, secrets.token_bytes(32)),
        ),
        response_key=ResponseKey(secrets.token_bytes(32)),
        producer=producer,
        registration_view=registration_view,
        max_backlog_age=timedelta(minutes=5),
        max_dispatch=max_dispatch,
        sweep_margin=sweep_margin,
        derived_max_ttl_s=3600,
        internal_destinations=InternalDestinations.ALLOWED,
        approvals=uses.approvals,
        approval_authority=lambda principal, admission: UseDispatchAuthority(
            principal=principal, admission=admission, passkeys=uses.world.passkeys
        ),
        use_audit=audit,
        clock=uses.clock,
    )
    body = json.dumps(
        {
            "request_id": "approved-use",
            "method": "POST",
            "url": upstream.url(path),
            "data": "hello",
        }
    ).encode()
    submission = MemberSubmission(
        Authorization(REQUESTER, REQUEST, uses.grant),
        RequestBytes("POST", b"/v1/secrets/staging-api/requests", (b"application/json",), body),
    )
    return service, audit, view, submission


@pytest.mark.parametrize(
    "decision,owner",
    [(Decision.APPROVE, False), (Decision.REJECT, False), (Decision.APPROVE, True)],
)
async def test_actual_broker_pending_decision_resubmission_and_stored_replay(
    uses, tmp_path, decision, owner
):
    async with running_upstream(tmp_path) as upstream:
        availability = [True]
        service, audit, view, submission = await setup(
            uses, tmp_path, upstream, owner=owner, availability=availability
        )
        pending = await service.submit(secret=SECRET["ref"], submission=submission)
        assert pending.status == 202 and pending.body["state"] == "awaiting_approval"
        assert upstream.paths == []
        link = await uses.world.db.fetch_one("SELECT * FROM {{tables.use_approvals}}")
        approval_id = link["approval_id"]
        contact = "alice@acme.com" if owner else "finance@acme.com"
        [token] = [t for a, t in uses.world.inbox.links[contact] if a == approval_id]
        options = await uses.approvals.challenge(
            approval_id, decision, Assurance.PASSKEY, link_token=token
        )
        with audit.prepared_view(view):
            await uses.approvals.decide(
                approval_id,
                decision,
                Assurance.PASSKEY,
                uses.world.devices[contact].get(dict(options)),
                link_token=token,
            )
        assert upstream.paths == []
        if decision is Decision.REJECT:
            availability[0] = False
        result = await service.submit(secret=SECRET["ref"], submission=submission)
        if decision is Decision.APPROVE:
            assert result.status == 200 and result.body["state"] == "completed", (
                result.status,
                result.body.get("state"),
                result.body.get("code"),
            )
            assert await service.submit(secret=SECRET["ref"], submission=submission) == result
            assert upstream.paths == ["/bearer/echo"]
            actions = [
                e["payload"]["action"]
                for e in await envelopes(uses.world.db)
                if e["hook"] == "post-secret-use-hook"
            ]
            assert actions == [
                "approval_requested",
                "approval_decided",
                "admitted",
                "dispatching",
                "completed",
            ]
        else:
            assert result.body["state"] == "refused" and result.body["code"] == "approval_denied"
            assert upstream.paths == []
            assert (
                await uses.world.db.fetch_value("SELECT state FROM {{tables.dispatches}}")
                == "approval_denied"
            )


async def test_cancelled_approved_sender_recovers_original_b2_and_s3_together(uses, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        entered, release = asyncio.Event(), asyncio.Event()

        @upstream.app.post("/bearer/crash")
        async def receiver(request: Request):
            if request.headers.get("authorization") != "Bearer " + upstream.creds.bearer:
                return Response(status_code=403)
            entered.set()
            await release.wait()
            return Response(status_code=204)

        service, audit, view, submission = await setup(
            uses,
            tmp_path,
            upstream,
            path="/bearer/crash",
            max_dispatch=timedelta(seconds=1),
            sweep_margin=timedelta(milliseconds=100),
        )
        pending = await service.submit(secret=SECRET["ref"], submission=submission)
        assert pending.body["state"] == "awaiting_approval"
        link = await uses.world.db.fetch_one("SELECT * FROM {{tables.use_approvals}}")
        approval_id = link["approval_id"]
        [token] = [t for a, t in uses.world.inbox.links["finance@acme.com"] if a == approval_id]
        options = await uses.approvals.challenge(
            approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
        )
        with audit.prepared_view(view):
            await uses.approvals.decide(
                approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                uses.world.devices["finance@acme.com"].get(dict(options)),
                link_token=token,
            )
        sender = asyncio.create_task(service.submit(secret=SECRET["ref"], submission=submission))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            sender.cancel()
            with pytest.raises(asyncio.CancelledError):
                await sender
            assert await service.sweep() == 0
            await asyncio.sleep(1.2)
            uses.clock.now = datetime.now(UTC)
            assert await service.sweep() == 1
            assert await service.sweep() == 0
            approval = await uses.approvals.get(approval_id)
            assert approval.dispatch_outcome is DispatchOutcome.OUTCOME_UNKNOWN
            receipt = await service.submit(secret=SECRET["ref"], submission=submission)
            assert receipt.status == 200 and receipt.body["state"] == "outcome_unknown"
            assert upstream.paths == ["/bearer/crash"]
            assert [
                e["payload"]["action"]
                for e in await envelopes(uses.world.db)
                if e["hook"] == "post-secret-use-hook"
            ] == [
                "approval_requested",
                "approval_decided",
                "admitted",
                "dispatching",
                "outcome_unknown",
            ]
        finally:
            release.set()
            if not sender.done():
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)

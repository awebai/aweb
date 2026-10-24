"""Real use-audit composition for HTTP/browser console tests."""

import os
from datetime import timedelta
from uuid import uuid4

from aweb_naapp.dispatch import Dispatches, apply_dispatch_migrations
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.commitment import CommitmentContext, CommitmentKey, Purpose, RequestBytes
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
from aweb_naapp.runtime.approvals import Approvals, PgApprovalStore
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import records
from aweb_secrets.admission import admit_use
from aweb_secrets.broker_audit import BrokerAudit, freeze_broker_audit
from aweb_secrets.broker_fence import BrokerFence
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.use_approvals import UseApprovers, UsePolicies, request_use_approval
from aweb_secrets.use_audit import UseApprovalAudit
from aweb_secrets.use_context import UseCommitter, apply_use_context_migrations, store_use_context
from tests.test_use_approvals import BODY, REQUESTER, SECRET, TEAM, open_action, use_request
from tests.test_use_audit import targets


def audit_for(uses):
    """A real sink using the same live store/passkeys, not an audit substitute."""
    if isinstance(uses.approvals._audit, UseApprovalAudit):
        audit = uses.approvals._audit
        return audit, audit._producer
    seed = os.urandom(32)

    def producer(*, installation_id, generation):
        return HookProducer(
            ServerProducer.app(
                origin="https://secrets.example.com",
                app_id="secrets",
                installation_id=installation_id,
                generation=generation,
                kid="console-test",
                seed=seed,
            ),
            clock=uses.clock,
        )

    store = PgApprovalStore(uses.world.db)

    async def approval(tx, approval_id):
        return await store.get_in(approval_id, tx)

    audit = UseApprovalAudit(
        producer=producer,
        passkeys=lambda: uses.world.passkeys,
        approval=approval,
        max_backlog_age=timedelta(minutes=5),
        clock=uses.clock,
    )
    w = uses.world
    uses.approvals = Approvals(
        store=store,
        policies=UsePolicies(w.db),
        approvers=UseApprovers(w.db, w.passkeys, w.directory),
        delivery=w.inbox,
        authenticators=[w.passkeys.authenticator()],
        audit=audit,
        clock=uses.clock,
    )
    return audit, producer


async def mint(uses, *, reason="refund"):
    """Mint an inert broker use through actual admission/S12/S3 and its outbox."""
    w, db = uses.world, uses.world.db
    await apply_dispatch_migrations(db)
    await apply_use_context_migrations(db)
    audit, producer = audit_for(uses)
    async with db.transaction() as tx:
        await records.create_destination(
            tx,
            INSTALLATION_ID,
            TEAM,
            DestinationRecord.from_after(
                {
                    "v": 1,
                    "destination_id": "dst_console",
                    "secret_id": SECRET["secret_id"],
                    "scheme": "https",
                    "host": "api.payments.example",
                    "port": 443,
                    "path": "/v1/**",
                    "methods": ["POST"],
                    "query_rules": {},
                    "header_allow": ["content-type"],
                    "network": "public",
                    "cidr": None,
                },
                internal_destinations=InternalDestinations.DISABLED,
            ),
        )
    dispatch_id, request = uuid4(), use_request()
    view = targets(uses.clock())
    machine = Dispatches(
        on_transition=BrokerAudit(producer=producer, view=view),
        max_dispatch=timedelta(seconds=30),
        sweep_margin=timedelta(seconds=5),
    )
    with audit.prepared_view(view), audit.minting(dispatch_id):
        async with db.transaction() as tx:
            admission = await admit_use(
                tx,
                fence=w.fence,
                grant=uses.grant,
                principal=REQUESTER,
                request=request,
                attestation=None,
                now=uses.clock(),
            )
            fence = BrokerFence(
                w.fence,
                admission=admission,
                principal=REQUESTER,
                request=request,
                dispatch_id=dispatch_id,
                headers=[],
                attestation=None,
                clock=uses.clock,
                derived_max_ttl_s=3600,
                internal_destinations=InternalDestinations.DISABLED,
                open_call=open_action(),
            )
            await fence.prepare(tx)
            context = CommitmentContext(
                "secrets", TEAM, INSTALLATION_ID, admission.installation.generation, "request"
            )
            committer = UseCommitter(
                CommitmentKey(Purpose.SECRET_REQUEST, os.urandom(32)),
                CommitmentKey(Purpose.SECRET_PARAMS, os.urandom(32)),
            )
            await store_use_context(
                tx,
                admission=admission,
                dispatch_id=dispatch_id,
                commitments=committer.commit(
                    context,
                    RequestBytes(
                        "POST", b"/v1/secrets/staging-api/requests", (b"application/json",), BODY
                    ),
                    parameters=None,
                ),
            )
            await freeze_broker_audit(
                tx,
                admission=admission,
                principal=REQUESTER,
                dispatch_id=dispatch_id,
                call=fence.call,
            )
            pending = await request_use_approval(
                tx,
                uses.approvals,
                admission=admission,
                dispatch_id=dispatch_id,
                principal=REQUESTER,
                action=open_action(),
                reason=reason,
            )
            await machine.create(
                tx, dispatch_id=dispatch_id, subject="console-use", action="broker"
            )
            await machine.await_approval(tx, dispatch_id)
            await fence.check_authority(tx, await machine.get(tx, dispatch_id))
    await uses.approvals.deliver(pending.pending)
    return pending

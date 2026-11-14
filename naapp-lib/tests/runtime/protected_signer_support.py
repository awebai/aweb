"""Shared protected-signer fixtures and helpers, registered by runtime conftest."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import timedelta

import pytest_asyncio
from aweb_naapp_testing import did_key
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.did import stable_id_from_did_key
from nacl.signing import SigningKey

from aweb_naapp.hooks.owner_act import owner_act_signing_bytes
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    ApprovalRevocation,
    Assurance,
    PgApprovalStore,
)
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty
from aweb_naapp.runtime.protected_signer import (
    AdmittedHuman,
    ProtectedKeyContext,
    ProtectedSigner,
    ReceiptReader,
    RestrictedRequester,
    RevokeHumanRole,
    SignerRefused,
)
from tests.runtime.approvals.support import AuditOutbox, Clock, Policies
from tests.runtime.approvals.test_passkeys import Contacts

ORIGIN = "https://signer.example.com"
SCOPE = "controller-authorizer"
CONTACT = "owner@example.com"


class SQLAuthority:
    """An embedding's actual current-authorizer table, not client assertions."""

    def __init__(self, db, context, subject, key, clock):
        self.db, self.context, self.subject, self.key, self.clock = (
            db,
            context,
            subject,
            key,
            clock,
        )

    async def observe(self, context, *, purpose):
        authority = self

        class Fence:
            team_key_did = authority.key

            async def prepare(self, tx, actor):
                await tx.fetch_one("SELECT * FROM {{tables.signer_authority}} FOR SHARE")
                await self.check(tx, actor)

            async def check(self, tx, actor):
                row = await tx.fetch_one("SELECT * FROM {{tables.signer_authority}}")
                if not row["active"] or (
                    purpose != "receipt" and row["generation"] != context.generation
                ):
                    raise SignerRefused("authority_changed")
                if isinstance(actor, AdmittedHuman) and (
                    actor.principal != context.human_id or actor.subject != row["subject"]
                ):
                    raise SignerRefused("scope_refused")
                if not isinstance(actor, AdmittedHuman) and actor.principal != "agent-requester":
                    raise SignerRefused("scope_refused")

            def require_fresh(self):
                pass  # This fixture authority is local SQL, held through commit.

        return Fence()


class ControllerCustody:
    """The protected server's existing controller key; only a named operation."""

    def __init__(self, key):
        self.key = key

    def sign_owner_act(self, operation, fields):
        assert isinstance(operation, RevokeHumanRole)
        return self.key.sign(owner_act_signing_bytes(fields)).signature


@dataclass
class World:
    signer: ProtectedSigner
    passkeys: Passkeys
    device: SoftAuthenticator
    operation: RevokeHumanRole
    requester: RestrictedRequester
    human: AdmittedHuman
    reader: ReceiptReader
    clock: Clock
    key: SigningKey
    audit: AuditOutbox


@pytest_asyncio.fixture
async def world(test_db_factory):
    db = await test_db_factory.create_db(suffix="protected_signer", schema="app")
    clock, contacts = Clock(), Contacts()
    audit = AuditOutbox(db)
    await audit.create()
    store = PgApprovalStore(db)
    await store.migrate()
    key, human_key = SigningKey.generate(), SigningKey.generate()
    human_id = stable_id_from_did_key(did_key(human_key))
    context = ProtectedKeyContext(
        "test-signer",
        "team_controller",
        "team-h:oatspec.io",
        "oatspec.io",
        human_id,
        "oatspec.io",
        1,
    )

    async def proof_context(scope, *, tx):
        # A second explicitly configured protected scope supports the genuine
        # same-subject, different-scope LOGIN refusal regression.
        if scope == "other-console-scope":
            return replace(context, service_id="other-test-signer")
        assert scope == SCOPE
        return context

    passkeys = Passkeys(
        db,
        rp=RelyingParty(ORIGIN, "Protected signer"),
        delivery=contacts,
        audit=audit,
        retirement=ApprovalRevocation(store, audit, clock),
        clock=clock,
        proof_context=proof_context,
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=10),
    )
    await passkeys.migrate()
    subject = str(uuid.uuid4())
    # Explicit protected-host provisioning fixture, before any app installation.
    await db.execute(
        "INSERT INTO {{tables.passkey_approvers}} "
        "(subject,scope,contact,designated_by,designated_at,effective_at) "
        "VALUES($1,$2,$3,'operator_bootstrap',$4,$4)",
        subject,
        SCOPE,
        CONTACT,
        clock(),
    )
    async with db.transaction() as tx:
        designation = await passkeys.reissue_enrolment(tx, scope=SCOPE)
    await passkeys.deliver(designation)
    device = SoftAuthenticator(ORIGIN)
    token = contacts.last(CONTACT)
    await passkeys.complete_enrolment(token, device.create(await passkeys.enrolment_options(token)))
    await db.execute(
        "CREATE TABLE {{tables.signer_authority}} "
        "(subject TEXT NOT NULL,generation INT NOT NULL,active BOOLEAN NOT NULL)"
    )
    await db.execute("INSERT INTO {{tables.signer_authority}} VALUES($1,1,true)", subject)
    policies = Policies(
        ActionPolicy(
            "aweb.human-assurance/1",
            1,
            Assurance.PASSKEY,
            timedelta(minutes=10),
            (SCOPE,),
        )
    )
    signer = ProtectedSigner(
        db,
        passkeys=passkeys,
        policies=policies,
        delivery=contacts,
        audit=audit,
        authority=SQLAuthority(db, context, subject, did_key(key), clock),
        custody=ControllerCustody(key),
        clock=clock,
    )
    await signer.migrate()
    operation = RevokeHumanRole(
        str(uuid.uuid4()),
        context,
        "https://console.example.com",
        "example",
        str(uuid.uuid4()),
        "example.owner",
        human_id,
    )
    yield World(
        signer,
        passkeys,
        device,
        operation,
        RestrictedRequester("agent-requester", context),
        AdmittedHuman(human_id, subject, SCOPE, context),
        ReceiptReader("agent-requester", context),
        clock,
        key,
        audit,
    )


async def approve(world):
    prepared = await world.signer.prepare(world.operation, requester=world.requester)
    options = await world.signer.approval_options(prepared.operation_id, human=world.human)
    return prepared, world.device.get(dict(options))



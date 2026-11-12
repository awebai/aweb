"""Protected owner-act signing through real B2/B3, PostgreSQL and WebAuthn."""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path

import pytest
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
    OwnerActOperation,
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

    def sign_operation(self, operation, fields):
        from aweb_naapp.runtime.protected_signer.codecs import signing_bytes

        return self.key.sign(signing_bytes(operation, fields)).signature

    def sign_owner_act(self, operation, fields):
        from aweb_naapp.runtime.protected_signer.types import owner_act_operation

        typed = owner_act_operation(operation)
        assert fields["act"] == typed.operation
        assert fields["subject"] == typed.intent()["subject"]
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


async def test_signs_one_real_owner_act_with_actual_uv_and_recovers_exact_receipt(world):
    prepared, proof = await approve(world)
    result = await world.signer.execute(prepared.operation_id, proof, human=world.human)
    assert result.state == "committed"
    signed = result.result
    raw, signature = base64.b64decode(signed["signing"]), base64.b64decode(signed["signature"])
    world.key.verify_key.verify(raw, signature)
    fields = json.loads(raw.split(b"\n", 1)[1])
    assert fields["act"] == "human-role.revoke"
    assert fields["subject"]["principal"] == world.operation.principal
    assert await world.signer.receipt(prepared.operation_id, reader=world.reader) == result
    assert await world.signer.execute(prepared.operation_id, proof, human=world.human) == result
    assert (await world.audit.kinds()).count("protected_operation_signed") == 1
    evidence = await world.passkeys.db.fetch_value(
        "SELECT evidence_ref FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
        prepared.operation_id,
    )
    retained = await world.passkeys.retained_proof(evidence)
    assert retained.context["kind"] == "protected_key"
    assert "installation_id" not in retained.context


async def test_changed_payload_under_same_client_operation_id_is_refused(world):
    await world.signer.prepare(world.operation, requester=world.requester)
    with pytest.raises(SignerRefused, match="operation_conflict"):
        await world.signer.prepare(
            replace(world.operation, role="other.owner"), requester=world.requester
        )


async def test_wrong_human_and_receipt_reader_have_no_authority(world):
    prepared = await world.signer.prepare(world.operation, requester=world.requester)
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.signer.approval_options(
            prepared.operation_id, human=replace(world.human, subject="another-holder")
        )
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.signer.receipt(
            prepared.operation_id, reader=replace(world.reader, principal="someone-else")
        )


async def test_current_authority_withdrawal_refuses_before_signing(world):
    prepared, proof = await approve(world)
    await world.passkeys.db.execute("UPDATE {{tables.signer_authority}} SET active=false")
    with pytest.raises(SignerRefused, match="authority_changed"):
        await world.signer.execute(prepared.operation_id, proof, human=world.human)
    assert "protected_operation_signed" not in await world.audit.kinds()


async def test_uv_five_minute_deadline_is_not_the_ten_minute_act_deadline(world):
    prepared, proof = await approve(world)
    world.clock.advance(timedelta(seconds=301))
    with pytest.raises(SignerRefused, match="gesture_expired"):
        await world.signer.execute(prepared.operation_id, proof, human=world.human)
    assert "protected_operation_signed" not in await world.audit.kinds()


async def test_concurrent_execute_and_receipt_have_one_committed_effect(world):
    prepared, proof = await approve(world)
    results = await asyncio.gather(
        world.signer.execute(prepared.operation_id, proof, human=world.human),
        world.signer.execute(prepared.operation_id, proof, human=world.human),
        world.signer.receipt(prepared.operation_id, reader=world.reader),
        return_exceptions=True,
    )
    assert all(not isinstance(r, Exception) for r in results), results
    assert all(r.state in ("pending", "committed") for r in results)
    committed = [r for r in results if r.state == "committed"]
    assert committed
    final = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert all(r.result == final.result for r in committed)
    assert (await world.audit.kinds()).count("protected_operation_signed") == 1


async def test_failed_audit_rolls_back_consume_result_and_allows_same_operation_retry(world):
    prepared, proof = await approve(world)
    db = world.passkeys.db
    await db.execute(
        "CREATE FUNCTION {{tables.refuse_signer_audit}}() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF NEW.kind='protected_operation_signed' THEN RAISE EXCEPTION 'audit unavailable'; "
        "END IF; RETURN NEW; END; $$"
    )
    await db.execute(
        "CREATE TRIGGER signer_audit_failure BEFORE INSERT ON {{tables.audit_outbox}} "
        "FOR EACH ROW EXECUTE FUNCTION {{tables.refuse_signer_audit}}()"
    )
    with pytest.raises(Exception, match="audit unavailable"):
        await world.signer.execute(prepared.operation_id, proof, human=world.human)
    pending = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert pending.state == "pending"
    await db.execute("DROP TRIGGER signer_audit_failure ON {{tables.audit_outbox}}")
    retried = await world.signer.execute(prepared.operation_id, proof, human=world.human)
    assert retried.state == "committed"
    assert (await world.audit.kinds()).count("protected_operation_signed") == 1


async def test_another_operation_cannot_use_the_original_uv_assertion(world):
    first, proof = await approve(world)
    second = await world.signer.prepare(
        replace(world.operation, operation_id=str(uuid.uuid4()), role="other.owner"),
        requester=world.requester,
    )
    with pytest.raises(SignerRefused, match="proof_invalid"):
        await world.signer.execute(second.operation_id, proof, human=world.human)
    assert (await world.signer.receipt(first.operation_id, reader=world.reader)).state == "pending"
    assert "protected_operation_signed" not in await world.audit.kinds()


async def test_last_audit_wait_crossing_original_uv_deadline_rolls_back_everything(world):
    prepared, proof = await approve(world)
    db = world.passkeys.db
    gate = 28766194
    await db.execute(
        "CREATE FUNCTION {{tables.wait_signer_audit}}() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF NEW.kind='protected_operation_signed' THEN PERFORM pg_advisory_xact_lock(28766194); "
        "END IF; RETURN NEW; END; $$"
    )
    await db.execute(
        "CREATE TRIGGER signer_audit_wait BEFORE INSERT ON {{tables.audit_outbox}} "
        "FOR EACH ROW EXECUTE FUNCTION {{tables.wait_signer_audit}}()"
    )
    task = None
    try:
        async with db.transaction() as blocker:
            await blocker.execute("SELECT pg_advisory_xact_lock($1::bigint)", gate)
            pid = await blocker.fetch_value("SELECT pg_backend_pid()")
            task = asyncio.create_task(
                world.signer.execute(prepared.operation_id, proof, human=world.human)
            )
            async with asyncio.timeout(10):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                    pid,
                ):
                    await asyncio.sleep(0.01)
            world.clock.advance(timedelta(seconds=301))
        with pytest.raises(SignerRefused, match="gesture_expired"):
            await task
        assert "protected_operation_signed" not in await world.audit.kinds()
        assert (
            await db.fetch_value(
                "SELECT result FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
                prepared.operation_id,
            )
            is None
        )
        approval = await world.signer.store.get(
            await db.fetch_value(
                "SELECT approval_id FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
                prepared.operation_id,
            )
        )
        assert approval.consumed_operation_id is None
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_execute_during_spent_assertion_uncommitted_decision_is_pending(world):
    prepared, proof = await approve(world)
    db = world.passkeys.db
    await db.execute(
        "CREATE FUNCTION {{tables.wait_signer_decision}}() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF NEW.kind='approval_decided' THEN PERFORM pg_advisory_xact_lock(28766195); "
        "END IF; RETURN NEW; END; $$"
    )
    await db.execute(
        "CREATE TRIGGER signer_decision_wait BEFORE INSERT ON {{tables.audit_outbox}} "
        "FOR EACH ROW EXECUTE FUNCTION {{tables.wait_signer_decision}}()"
    )
    first = None
    try:
        async with db.transaction() as blocker:
            await blocker.execute("SELECT pg_advisory_xact_lock(28766195::bigint)")
            pid = await blocker.fetch_value("SELECT pg_backend_pid()")
            first = asyncio.create_task(
                world.signer.execute(prepared.operation_id, proof, human=world.human)
            )
            async with asyncio.timeout(10):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                    pid,
                ):
                    await asyncio.sleep(0.01)
            async with asyncio.timeout(5):
                concurrent = await world.signer.execute(
                    prepared.operation_id, proof, human=world.human
                )
                observed = await world.signer.receipt(prepared.operation_id, reader=world.reader)
            assert concurrent.state == observed.state == "pending"
            assert concurrent.code == observed.code == "effect_in_progress"
        completed = await first
        assert completed.state == "committed"
        assert await world.signer.receipt(prepared.operation_id, reader=world.reader) == completed
        assert (await world.audit.kinds()).count("protected_operation_signed") == 1
    finally:
        if first is not None and not first.done():
            first.cancel()
            await asyncio.gather(first, return_exceptions=True)


async def test_policy_change_after_options_is_distinct_from_invalid_proof(world):
    prepared, proof = await approve(world)
    old = await world.signer.policies.current("aweb.human-assurance/1")
    world.signer.policies.set(replace(old, version=2))
    with pytest.raises(SignerRefused, match="policy_changed"):
        await world.signer.execute(prepared.operation_id, proof, human=world.human)
    receipt = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert receipt.state == "refused" and receipt.code == "policy_changed"
    assert "protected_operation_signed" not in await world.audit.kinds()


# Existing verifier vectors supply real protocol subjects, not a new grammar.
_OWNER_CASES = {
    case["act"]["act"]: case["act"]["subject"]
    for case in json.loads(
        (Path(__file__).resolve().parents[3] / "docs/vectors/owner-act-v1.json").read_bytes()
    )["positive_cases"]
}
_OWNER_CASES["human-credential.cap-set"] = {
    "app_id": "logs",
    "installation_id": "00000000-0000-4000-8000-000000000001",
    "role": "logs.owner",
    "cap": 3,
}


@pytest.mark.parametrize("act,subject", _OWNER_CASES.items(), ids=_OWNER_CASES.keys())
async def test_all_owner_act_codecs_share_actual_uv_consume_and_one_signature(world, act, subject):
    operation = OwnerActOperation(
        world.operation.operation_id,
        world.operation.context,
        world.operation.audience,
        act,
        "app"
        if act == "human-credential.cap-set"
        else ("controller_recovery" if act == "human-credential.replace" else "default"),
        subject,
    )
    prepared = await world.signer.prepare(operation, requester=world.requester)
    assert prepared.payload["operation"] == act
    assert prepared.payload["artifact"]["subject"] == subject
    options = await world.signer.approval_options(operation.operation_id, human=world.human)
    proof = world.device.get(dict(options))
    receipt = await world.signer.execute(operation.operation_id, proof, human=world.human)
    assert receipt.state == "committed"
    raw = base64.b64decode(receipt.result["signing"])
    signature = base64.b64decode(receipt.result["signature"])
    world.key.verify_key.verify(raw, signature)
    artifact = json.loads(raw.split(b"\n", 1)[1])
    assert artifact["act"] == act and artifact["subject"] == subject
    assert await world.signer.receipt(operation.operation_id, reader=world.reader) == receipt
    assert await world.signer.execute(operation.operation_id, proof, human=world.human) == receipt
    assert (await world.audit.kinds()).count("protected_operation_signed") == 1
    with pytest.raises(SignerRefused, match="operation_conflict"):
        await world.signer.prepare(
            replace(operation, subject={**subject, "app_id": "another-app"}),
            requester=world.requester,
        )


async def test_server_record_uses_same_real_uv_receipt_and_cannot_switch_destination(world):
    from awid.team_server_record import verify_team_server_record

    from aweb_naapp.runtime.protected_signer import CatalogOperation

    operation = CatalogOperation(
        world.operation.operation_id,
        world.operation.context,
        "https://registry.example.org",
        "team.server-record.publish",
        "default",
        {"server_url": "https://coord.example.org"},
    )
    prepared = await world.signer.prepare(operation, requester=world.requester)
    options = await world.signer.approval_options(operation.operation_id, human=world.human)
    receipt = await world.signer.execute(
        operation.operation_id,
        world.device.get(dict(options)),
        human=world.human,
    )
    raw = base64.b64decode(receipt.result["signing"])
    artifact = json.loads(raw.split(b"\n", 1)[1])
    verified = verify_team_server_record(
        artifact,
        receipt.result["signature"].rstrip("="),
        team_id=operation.context.authority_id,
        current_team_did_key=did_key(world.key),
        now=world.clock(),
    )
    assert verified.server_url == operation.intent()["subject"]["server_url"]
    assert prepared.payload["artifact"] == artifact
    assert await world.signer.receipt(operation.operation_id, reader=world.reader) == receipt
    with pytest.raises(SignerRefused, match="operation_conflict"):
        await world.signer.prepare(
            replace(operation, subject={"server_url": "https://other.example.org"}),
            requester=world.requester,
        )
    assert (await world.audit.kinds()).count("protected_operation_signed") == 1

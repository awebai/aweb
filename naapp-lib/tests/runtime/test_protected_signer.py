"""Protected owner-act signing through real B2/B3, PostgreSQL and WebAuthn."""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest

from aweb_naapp.runtime.protected_signer import (
    SignerRefused,
)
from tests.runtime.protected_signer_support import approve


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

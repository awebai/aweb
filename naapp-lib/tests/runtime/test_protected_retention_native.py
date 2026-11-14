"""PG/B2/B3 retention and commit-order controls; VM execution only.

The remote transport is a port double. It does NOT issue or verify a service
attestation. Genuine protected-consumer acceptance belongs to the .15 joined
composition; these controls prove the local engine's transaction/retry fences.
"""

import base64
import json
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import timedelta

import asyncpg
import pytest
from awid.signing import canonical_json_bytes

from aweb_naapp.runtime.protected_signer import (
    EffectConfirmation,
    FrozenDelivery,
    RetainedEffect,
    SignerRefused,
)
from tests.runtime.protected_signer_support import approve


class EffectPort:
    def __init__(self, world):
        self.w, self.original = world, world.signer.custody
        self.retains = self.posts = 0
        self.applied = False
        self.drop_answer = self.expire_before_claim = self.change_policy = False

    def sign_owner_act(self, operation, artifact):
        return self.original.sign_owner_act(operation, artifact)

    def retain_authorized_effect(self, **kw):
        self.retains += 1
        self.w.key.verify_key.verify(kw["signing"], kw["signature"])
        assert kw["operation"].spec.effect.provider is None
        assert kw["request"]["artifact"] == kw["artifact"]
        body = canonical_json_bytes({"signing": base64.b64encode(kw["signing"]).decode(),
            "signature": base64.b64encode(kw["signature"]).rstrip(b"=").decode()})
        return RetainedEffect(kw["operation"].operation_id, kw["signing"], kw["signature"], "a" * 64,
            kw["expires_at"], FrozenDelivery(kw["operation"].audience, "POST", "/.well-known/aweb-owner-act",
                {"Authorization": "private-transport-test-value"}, body), "opaque-transport-marker-not-a-service-proof")

    async def deliver_retained(self, operation, retained):
        # A separate physical connection must see both the local signature
        # bundle AND the release claim. This fails if delivery is inside either
        # uncommitted engine transaction. The world explicitly uses schema app.
        connection = await asyncpg.connect(self.w.passkeys.db.config.get_dsn())
        try:
            row = await connection.fetchrow("SELECT signed_result,retained_effect,delivery_claim,result "
                "FROM app.protected_signer_operations WHERE operation_id=$1", operation.operation_id)
            assert row is not None and row["signed_result"] is not None and row["delivery_claim"] is not None
            assert row["result"] is None
            stored = json.loads(row["retained_effect"])
            assert RetainedEffect.from_fields(stored) == retained
        finally:
            await connection.close()
        assert self.w.clock() < retained.expires_at
        self.posts += 1
        assert self.posts == 1
        self.applied = True
        if self.drop_answer:
            raise ConnectionError("transport lost the application answer")

    async def confirm_retained(self, operation, retained):
        if self.expire_before_claim:
            self.expire_before_claim = False
            self.w.clock.advance(timedelta(seconds=301))
        if self.change_policy:
            self.change_policy = False
            policy = await self.w.signer.policies.current("aweb.human-assurance/1")
            self.w.signer.policies.set(replace(policy, version=policy.version + 1))
        if not self.applied:
            return None
        return EffectConfirmation(operation.operation_id, retained.artifact_sha256, self.w.clock() + timedelta(seconds=60))


async def row_for(world, operation_id):
    return await world.passkeys.db.fetch_one("SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", operation_id)


async def counts(world):
    kinds = await world.audit.kinds()
    return kinds.count("protected_operation_signed"), kinds.count("protected_operation_applied")


async def test_private_bundle_and_claim_commit_before_delivery_and_only_safe_result_is_public(world):
    port = EffectPort(world)
    world.signer.custody = port
    prepared, proof = await approve(world)
    result = await world.signer.execute(prepared.operation_id, proof, human=world.human)
    assert result.state == "committed" and result.result["v"] == 2
    assert result.result["delivery"]["state"] == "applied"
    assert "private-transport-test-value" not in str(result.result)
    assert "opaque-transport-marker" not in str(result.result)
    assert await world.signer.execute(prepared.operation_id, proof, human=world.human) == result
    assert await world.signer.receipt(prepared.operation_id, reader=world.reader) == result
    assert port.retains == port.posts == 1 and await counts(world) == (1, 1)


async def test_lost_answer_recovers_identical_effect_after_expiry_without_another_release(world):
    port = EffectPort(world)
    port.drop_answer = True
    world.signer.custody = port
    prepared, proof = await approve(world)
    with pytest.raises(ConnectionError, match="lost the application answer"):
        await world.signer.execute(prepared.operation_id, proof, human=world.human)
    before = await row_for(world, prepared.operation_id)
    assert before["result"] is None and before["signed_result"] is not None and before["delivery_claim"] is not None
    world.clock.advance(timedelta(hours=2))
    recovered = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert recovered.state == "committed" and recovered.result["artifact"] == json.loads(before["signed_result"])
    after = await row_for(world, prepared.operation_id)
    for field in ("intent", "request", "signed_result", "retained_effect", "delivery_claim", "expires_at"):
        assert after[field] == before[field]
    assert port.retains == port.posts == 1 and await counts(world) == (1, 1)


async def test_applied_audit_failure_rolls_back_receipt_then_recovers_the_same_signature(world):
    port = EffectPort(world)
    world.signer.custody = port
    prepared, proof = await approve(world)
    db = world.passkeys.db
    await db.execute("CREATE FUNCTION {{tables.refuse_applied_audit}}() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF NEW.kind='protected_operation_applied' THEN RAISE EXCEPTION 'applied audit unavailable'; "
        "END IF; RETURN NEW; END; $$")
    await db.execute("CREATE TRIGGER applied_audit_failure BEFORE INSERT ON {{tables.audit_outbox}} "
        "FOR EACH ROW EXECUTE FUNCTION {{tables.refuse_applied_audit}}()")
    # Direct engine call: unlike the mounted HTTP route it does not translate
    # this real PostgreSQL trigger failure into a sanitized 503 response.
    with pytest.raises(Exception, match="applied audit unavailable"):
        await world.signer.execute(prepared.operation_id, proof, human=world.human)
    before = await row_for(world, prepared.operation_id)
    assert port.applied and before["result"] is None and await counts(world) == (1, 0)
    await db.execute("DROP TRIGGER applied_audit_failure ON {{tables.audit_outbox}}")
    recovered = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert recovered.state == "committed" and recovered.result["artifact"] == json.loads(before["signed_result"])
    assert port.retains == port.posts == 1 and await counts(world) == (1, 1)


async def test_retained_signature_never_releases_after_original_uv_window(world):
    port = EffectPort(world)
    port.expire_before_claim = True
    world.signer.custody = port
    prepared, proof = await approve(world)
    result = await world.signer.execute(prepared.operation_id, proof, human=world.human)
    assert result.state == "unknown" and result.code == "external_effect_unresolved"
    row = await row_for(world, prepared.operation_id)
    assert row["result"] is None and row["signed_result"] is not None and row["delivery_claim"] is None
    assert port.retains == 1 and port.posts == 0 and await counts(world) == (1, 0)


async def test_a_commit_wait_crossing_original_uv_deadline_sends_nothing(world, monkeypatch):
    port = EffectPort(world)
    world.signer.custody = port
    original_confirm = port.confirm_retained
    transaction = world.passkeys.db.transaction
    armed = crossed = False

    async def confirm(operation, retained):
        nonlocal armed
        result = await original_confirm(operation, retained)
        armed = True
        return result

    @asynccontextmanager
    async def delayed_claim_commit(*args, **kw):
        nonlocal crossed
        async with transaction(*args, **kw) as tx:
            yield tx
        if armed and not crossed:
            crossed = True
            world.clock.advance(timedelta(seconds=301))

    port.confirm_retained = confirm
    monkeypatch.setattr(world.passkeys.db, "transaction", delayed_claim_commit)
    prepared, proof = await approve(world)
    result = await world.signer.execute(prepared.operation_id, proof, human=world.human)
    assert crossed and result.state == "unknown" and result.code == "external_effect_unresolved"
    row = await row_for(world, prepared.operation_id)
    assert row["delivery_claim"] is not None and row["result"] is None
    assert port.retains == 1 and port.posts == 0 and await counts(world) == (1, 0)


async def test_changed_policy_cannot_release_a_retained_signature(world):
    port = EffectPort(world)
    port.change_policy = True
    world.signer.custody = port
    prepared, proof = await approve(world)
    with pytest.raises(SignerRefused, match="policy_changed"):
        await world.signer.execute(prepared.operation_id, proof, human=world.human)
    row = await row_for(world, prepared.operation_id)
    assert row["result"] is None and row["signed_result"] is not None and row["delivery_claim"] is None
    assert port.retains == 1 and port.posts == 0 and await counts(world) == (1, 0)


async def test_expired_confirmation_observation_rolls_back_applied_result(world):
    port = EffectPort(world)
    world.signer.custody = port
    original = world.signer.authority.observe
    crossed = False

    async def observe(context, *, purpose):
        nonlocal crossed
        fence = await original(context, purpose=purpose)
        if purpose == "receipt" and port.applied and not crossed:
            crossed = True
            check = fence.check

            async def final_check(tx, actor):
                await check(tx, actor)
                world.clock.advance(timedelta(seconds=61))

            fence.check = final_check
        return fence

    world.signer.authority.observe = observe
    prepared, proof = await approve(world)
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await world.signer.execute(prepared.operation_id, proof, human=world.human)
    assert (await row_for(world, prepared.operation_id))["result"] is None
    assert port.applied and await counts(world) == (1, 0)
    recovered = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert recovered.state == "committed" and port.posts == port.retains == 1 and await counts(world) == (1, 1)

"""Real persisted scope/F6 resolution and B3 frozen evidence, without a fallback."""

import pytest
from aweb_naapp.runtime.passkeys import PasskeyProofUnavailable, ProofContextUnavailable
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.owners import approver_scope
from aweb_secrets.passkey_context import PasskeyContexts
from tests.test_change_sets import ALICE, TEAM, enrol_owner
from tests.test_change_sets import world as world
from tests.test_use_approvals import designate
from tests.test_use_approvals import uses as uses


async def test_owner_scope_resolves_the_actual_fresh_installation_without_authority_locks(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    resolve = PasskeyContexts(app_id=world.fence.app_id)
    async with world.db.transaction() as tx:
        context = await resolve(scope, tx=tx)
        assert context.app_id == world.fence.app_id
        assert (context.team_id, context.installation_id, context.generation) == (
            TEAM,
            INSTALLATION_ID,
            world.admitted.generation,
        )
        assert not await tx.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND granted "
            "AND locktype IN ('relation','advisory') AND mode<>'AccessShareLock')"
        )


@pytest.mark.parametrize(
    "change", ["unknown", "stale", "inactive", "retired", "wrong_app", "wrong_installation"]
)
async def test_missing_or_unusable_installation_context_never_gets_fabricated(world, change):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    resolve = PasskeyContexts(app_id="another-app" if change == "wrong_app" else world.fence.app_id)
    async with world.db.transaction() as tx:
        if change == "unknown":
            scope = "secrets.owner.unknown"
        elif change == "stale":
            await tx.execute(
                "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()-interval '1 second'"
            )
        elif change == "inactive":
            await tx.execute("UPDATE {{tables.installation_fences}} SET state='inactive'")
        elif change == "retired":
            await tx.execute(
                "INSERT INTO {{tables.retired_installation_fences}} (app_id,team_id,installation_id) VALUES($1,$2,$3)",
                world.fence.app_id,
                TEAM,
                INSTALLATION_ID,
            )
        elif change == "wrong_installation":
            await tx.execute(
                "UPDATE {{tables.owner_principals}} SET installation_id='different-installation'"
            )
    with pytest.raises(ProofContextUnavailable) as refused:
        async with world.db.transaction() as tx:
            await resolve(scope, tx=tx)
    assert str(refused.value) == "proof_context_unavailable"


async def test_real_login_proof_keeps_challenge_context_after_current_generation_changes(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    resolve = PasskeyContexts(app_id=world.fence.app_id)
    async with world.db.transaction() as tx:
        original = await resolve(scope, tx=tx)
    options = await world.passkeys.login_options(scope)
    async with world.db.transaction() as tx:
        await tx.execute("UPDATE {{tables.installation_fences}} SET generation=generation+1")
    login = await world.passkeys.verify_login(scope, world.devices["alice@acme.com"].get(options))
    commitment = await world.passkeys.evidence_commitment(
        login.evidence_ref, context=original, scope=scope, subject=login.subject, purpose="login"
    )
    assert len(commitment) == 64
    async with world.db.transaction() as tx:
        current = await resolve(scope, tx=tx)
        assert current.generation == original.generation + 1
        with pytest.raises(PasskeyProofUnavailable):
            await world.passkeys.evidence_commitment(
                login.evidence_ref,
                context=current,
                scope=scope,
                subject=login.subject,
                purpose="login",
                tx=tx,
            )


@pytest.mark.parametrize("ambiguous", [False, True])
async def test_confirmed_approver_binding_resolves_but_a_second_binding_never_wins(uses, ambiguous):
    await designate(uses, "finance", "finance@acme.com")
    w = uses.world
    scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
    resolve = PasskeyContexts(app_id=w.fence.app_id)
    async with w.db.transaction() as tx:
        if ambiguous:
            # Simulate inconsistent persisted directory rows: the stale extra
            # binding must not be ignored in favor of the one fresh match.
            await tx.execute(
                "INSERT INTO {{tables.owner_principals}} (scope,installation_id,team_id,principal_did)"
                " VALUES($1,$2,$3,$4)",
                scope,
                "different-installation",
                TEAM,
                ALICE.principal_did,
            )
            with pytest.raises(ProofContextUnavailable):
                await resolve(scope, tx=tx)
        else:
            context = await resolve(scope, tx=tx)
            assert (context.team_id, context.installation_id, context.generation) == (
                TEAM,
                INSTALLATION_ID,
                w.admitted.generation,
            )

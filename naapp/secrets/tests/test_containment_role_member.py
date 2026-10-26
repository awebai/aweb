"""Individual user-role withdrawal through real authority, SQL, HTTP and TLS."""

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from aweb_naapp.roles import PrincipalKey, assign, has_role, hold_role, principal_key
from aweb_naapp.runtime.installation import InstallationRefused
from aweb_naapp_testing import Member

from aweb_secrets import records
from aweb_secrets.containment import ContainmentRefused
from aweb_secrets.credential_audit import GovernanceUnavailable
from aweb_secrets.grant import GrantRecord
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.revisions import config_revision
from tests.harness import running_upstream
from tests.test_broker_approved_service import setup as broker_setup
from tests.test_change_sets import ALICE, TEAM
from tests.test_console import login
from tests.test_containment_credential_audit import caller, human_client
from tests.test_containment_routes import API, PATH, running
from tests.test_credential_audit import audit_for, events
from tests.test_use_approvals import REQUESTER, SECRET, SECRET_ID, _member, install
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world

ROLE = "secrets.role.deployers"
SIGNED_TRACE = "0123456789abcdef0123456789abcdef"
MEMBER_A, MEMBER_B = _member(8), _member(9)


def body(principal=None, *, request_id=None, target=ROLE):
    return {
        "request_id": request_id or uuid4().hex,
        "action": "remove-role-member",
        "target": target,
        "principal": principal or principal_key(MEMBER_A).principal_did,
    }


async def prepare(uses, *, key_only=False):
    policy = await install(uses, approval="none", approvers=[])
    selected = replace(MEMBER_A, did_aw=None) if key_only else MEMBER_A
    db, scope = uses.world.db, uses.world.admitted
    async with db.transaction() as tx:
        # Replace fixture direct grants with one real role grant. Neither A nor
        # B has another route to the tested operation.
        for row in await tx.fetch_all("SELECT grant_id FROM {{tables.grants}}"):
            await records.revoke_grant(tx, scope.installation_id, row["grant_id"])
        await records.create_grant(
            tx,
            scope.installation_id,
            TEAM,
            GrantRecord.from_after(
                {
                    "v": 1,
                    "grant_id": "grt_shared_role",
                    "secret_id": SECRET_ID,
                    "subject": {"role": ROLE},
                    "capability": "use",
                    "operations": [],
                    "open_request": True,
                    "jobs": [],
                    "policy_digest": policy.digest,
                }
            ),
        )
        for member in (selected, MEMBER_B):
            await assign(tx, principal_key(member), ROLE)
        await assign(tx, principal_key(selected), "secrets.role.unrelated")
        await assign(
            tx, PrincipalKey("other:example.com", principal_key(selected).principal_did), ROLE
        )
    audit = await audit_for(uses.world)
    svc = await caller(uses.world, audit)
    return svc, selected


async def remove(uses, svc, request, *, actor=REQUESTER):
    return await svc.by_member(
        grant=uses.grant,
        principal=actor,
        request_id=request["request_id"],
        action=request["action"],
        target=request["target"],
        member_principal=request["principal"],
        signed_trace_id=SIGNED_TRACE,
    )


@pytest.mark.parametrize("key_only", [False, True])
async def test_exact_member_only_replay_hash_and_canonical_receipt(uses, key_only):
    svc, selected = await prepare(uses, key_only=key_only)
    db, scope = uses.world.db, uses.world.admitted
    request = body(principal_key(selected).principal_did)
    before = await events(uses.world)
    revision = await config_revision(db, scope.installation_id)
    grant = await db.fetch_one("SELECT * FROM {{tables.grants}} WHERE grant_id='grt_shared_role'")
    first = await remove(uses, svc, request)
    assert first.action == request["action"] and first.target == ROLE
    assert first.affected_secret_ids == ()
    assert not await has_role(db, principal_key(selected), ROLE)
    assert await has_role(db, principal_key(MEMBER_B), ROLE)
    assert await has_role(db, principal_key(selected), "secrets.role.unrelated")
    assert await has_role(db, PrincipalKey("other:example.com", request["principal"]), ROLE)
    assert (
        await db.fetch_one("SELECT * FROM {{tables.grants}} WHERE grant_id='grt_shared_role'")
        == grant
    )
    assert await config_revision(db, scope.installation_id) == revision + 1
    assert await remove(uses, svc, request) == first
    assert await config_revision(db, scope.installation_id) == revision + 1
    emitted = (await events(uses.world))[len(before) :]
    assert len(emitted) == 1
    [event] = emitted
    assert event["payload"] == {
        "act": "role.revoked",
        "direction": "narrowing",
        "authority": "team_cert",
        "role": ROLE,
        "subject_ref": "member:" + request["principal"],
    }
    assert event["actor"]["did_aw"] == REQUESTER.did_aw
    assert event["trace"] == {"id": SIGNED_TRACE, "origin": "signed_request"}
    assert (
        await db.fetch_value("SELECT count(*) FROM {{tables.credential_narrowing_authority}}") == 1
    )
    with pytest.raises(ContainmentRefused, match="idempotency_conflict"):
        await remove(uses, svc, {**request, "principal": principal_key(MEMBER_B).principal_did})
    # A fresh no-op keeps a receipt and invalidates old drafts, with no invented
    # role event for a membership that was already absent.
    await remove(uses, svc, {**request, "request_id": uuid4().hex})
    assert await config_revision(db, scope.installation_id) == revision + 2
    assert await events(uses.world) == before + emitted
    assert await db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 2


async def test_final_f6_refusal_rolls_back_membership_revision_receipt_and_event(uses):
    svc, _ = await prepare(uses)
    db, scope = uses.world.db, uses.world.admitted
    before = await events(uses.world)
    revision = await config_revision(db, scope.installation_id)
    await db.execute(
        "CREATE FUNCTION expire_role_fence() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN UPDATE {{tables.installation_fences}} "
        "SET fresh_until=clock_timestamp()-interval '1 second'; RETURN NEW; END $$"
    )
    await db.execute(
        "CREATE TRIGGER expire_role_fence AFTER INSERT ON {{tables.outbox_events}} "
        "FOR EACH ROW EXECUTE FUNCTION expire_role_fence()"
    )
    keys = await db.fetch_value("SELECT count(*) FROM {{tables.idempotency_keys}}")
    with pytest.raises(InstallationRefused):
        await remove(uses, svc, body())
    assert await has_role(db, principal_key(MEMBER_A), ROLE)
    assert await config_revision(db, scope.installation_id) == revision
    assert await events(uses.world) == before
    assert await db.fetch_value("SELECT count(*) FROM {{tables.idempotency_keys}}") == keys
    assert await db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 0
    assert (
        await db.fetch_value("SELECT count(*) FROM {{tables.credential_narrowing_authority}}") == 0
    )


@pytest.mark.parametrize(
    "problem",
    [
        "transaction",
        "recorder",
        "app",
        "authorizer",
        "empty-role",
        "bad-role",
        "empty-subject",
        "bad-subject",
    ],
)
async def test_shared_recorder_requires_original_context_and_nonempty_targets(uses, problem):
    await prepare(uses)
    w, audit = uses.world, uses.world.credential_audit
    other = await audit_for(w) if problem == "recorder" else audit
    before = await events(w)
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        assert await hold_role(tx, principal_key(REQUESTER), OWNER_ROLE)
        prepared = await audit.prepare_containment(tx, admitted=w.admitted, principal=REQUESTER)
        if problem == "app":
            prepared = replace(prepared, admitted=replace(prepared.admitted, app_id="other-app"))
        elif problem == "authorizer":
            prepared = replace(prepared, authorized_by="")
        role = "" if problem == "empty-role" else 7 if problem == "bad-role" else ROLE
        subject = (
            ""
            if problem == "empty-subject"
            else 7
            if problem == "bad-subject"
            else "member:" + principal_key(MEMBER_A).principal_did
        )

        async def refused(effect_tx):
            with pytest.raises(GovernanceUnavailable):
                await other.record_role_revoked(
                    effect_tx,
                    context=prepared,
                    role=role,
                    subject_ref=subject,
                    occurred_at=datetime.now(UTC),
                )

        if problem != "transaction":
            await refused(tx)
    if problem == "transaction":
        async with w.db.transaction() as another:
            await refused(another)
    assert await events(w) == before
    assert (
        await w.db.fetch_value("SELECT count(*) FROM {{tables.credential_narrowing_authority}}")
        == 0
    )


async def test_owner_console_csrf_and_retained_login_without_new_ceremony(uses):
    svc, _ = await prepare(uses)
    w = uses.world
    before = await events(w)
    path = f"/installations/{w.admitted.installation_id}/containment"
    scope = owner_scope(w.admitted.installation_id, TEAM, ALICE.principal_did)
    async with human_client(w, svc, w.credential_audit) as human:
        assert (await human.post(path, json=body())).status_code == 401
        logged = await login(w, human, scope)
        assert logged.status_code == 200
        w.devices["alice@acme.com"].credentials.clear()
        request = body()
        assert (await human.post(path, json=request)).status_code == 403
        response = await human.post(
            path, json=request, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
        assert response.status_code == 200, response.text
    assert not await has_role(w.db, principal_key(MEMBER_A), ROLE)
    [event] = (await events(w))[len(before) :]
    assert event["actor"] == {"authority_mode": "system", "attestations": []}
    assert event["payload"]["authority"] == "passkey_session"
    row = await w.db.fetch_one("SELECT * FROM {{tables.credential_narrowing_authority}}")
    assert event["payload"]["approval_evidence_sha256"] == row["commitment"]
    assert row["retained_proof"] is not None


async def test_signed_api_owner_only_and_strict_action_fields(uses, registry):
    await prepare(uses)
    owner = Member(team_id=TEAM, certificate_id="role-owner")
    outsider = Member(team_id=TEAM, team_key=owner.team_key, certificate_id="role-outsider")
    await registry.add_team(TEAM, owner.team_did_key)
    for member in (owner, outsider):
        await registry.add_certificate(member.certificate())
    async with uses.world.db.transaction() as tx:
        await assign(tx, PrincipalKey(TEAM, owner.did_key), OWNER_ROLE)

    async with running(uses, registry) as api:

        async def post(member, request):
            raw = json.dumps(request).encode()
            return await api.post(
                PATH,
                content=raw,
                headers=member.headers(aud=API, method="POST", path=PATH, body=raw)
                | {"Content-Type": "application/json"},
            )

        denied = await post(outsider, body())
        assert denied.status_code == 403 and denied.json()["detail"] == "owner_required"
        for request, code in (
            (body(target=OWNER_ROLE), "containment_target_invalid"),
            (body(target="logs.reader"), "containment_target_invalid"),
            (body("alias-a"), "request_invalid"),
            ({k: v for k, v in body().items() if k != "principal"}, "request_invalid"),
            ({**body(), "credential_id": "YQ"}, "request_invalid"),
            ({**body(), "action": "revoke-grant"}, "request_invalid"),
        ):
            response = await post(owner, request)
            assert response.status_code == 400 and response.json()["detail"] == code
        response = await post(owner, body())
        assert response.status_code == 200, response.text
    assert not await has_role(uses.world.db, principal_key(MEMBER_A), ROLE)


async def test_real_tls_a_refused_b_survives_and_admitted_unsent_a_stops(uses, tmp_path):
    async with running_upstream(tmp_path) as upstream:
        broker, _, _, original = await broker_setup(uses, tmp_path, upstream)
        svc, _ = await prepare(uses)
        db = uses.world.db

        def submission(member, request_id):
            return replace(
                original,
                authorization=replace(original.authorization, principal=member),
                inbound=replace(
                    original.inbound,
                    body=json.dumps(
                        {
                            "request_id": request_id,
                            "method": "POST",
                            "url": upstream.url("/bearer/echo"),
                            "data": "hello",
                        }
                    ).encode(),
                ),
            )

        # Confirm both real principals can actually reach the independent TLS
        # receiver with this same role grant before the withdrawal.
        for member in (MEMBER_A, MEMBER_B):
            result = await broker.submit(
                secret=SECRET["ref"], submission=submission(member, uuid4().hex)
            )
            assert result.status == 200 and result.body["state"] == "completed"
        sent = len(upstream.paths)
        pending = None
        try:
            async with db.transaction() as barrier:
                await barrier.execute(
                    "LOCK TABLE {{tables.custody_secrets}} IN ACCESS EXCLUSIVE MODE"
                )
                blocker = await barrier.fetch_value("SELECT pg_backend_pid()")
                pending = asyncio.create_task(
                    broker.submit(
                        secret=SECRET["ref"],
                        submission=submission(MEMBER_A, "admitted-before-removal"),
                    )
                )
                async with asyncio.timeout(5):
                    while not await db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        blocker,
                    ):
                        assert not pending.done()
                        await asyncio.sleep(0.01)
                await asyncio.wait_for(remove(uses, svc, body()), 5)
                assert (
                    await db.fetch_value(
                        "SELECT count(*) FROM {{tables.intents}} WHERE request_id='admitted-before-removal'"
                    )
                    == 1
                )
            result = await asyncio.wait_for(pending, 5)
            assert result.status == 403 and result.body["code"] == "grant_revoked"
            assert len(upstream.paths) == sent
            refused = await broker.submit(
                secret=SECRET["ref"], submission=submission(MEMBER_A, "fresh-a")
            )
            assert refused.status == 403 and refused.body["code"] == "grant_missing"
            assert len(upstream.paths) == sent
            survived = await broker.submit(
                secret=SECRET["ref"], submission=submission(MEMBER_B, "fresh-b")
            )
            assert survived.status == 200 and survived.body["state"] == "completed"
            assert len(upstream.paths) == sent + 1
            assert (
                await db.fetch_value(
                    "SELECT revoked_at FROM {{tables.grants}} WHERE grant_id='grt_shared_role'"
                )
                is None
            )
            assert (
                await db.fetch_value(
                    "SELECT attempts FROM {{tables.dispatches}} d JOIN {{tables.use_contexts}} c USING(dispatch_id)"
                    " JOIN {{tables.intents}} i ON i.intent_id=c.intent_id WHERE i.request_id='admitted-before-removal'"
                )
                == 0
            )
        finally:
            if pending is not None and not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)

"""Owner HTTP recovery retains fresh APPROVE and atomic widening governance."""

import uuid
from dataclasses import replace
from datetime import timedelta

import asyncpg
import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp.runtime.passkeys import PasskeyInstallationContext
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.admission import AdmissionRefused, admit_use
from aweb_secrets.containment import disable_installation, disable_secret_tree
from aweb_secrets.owners import OWNER_ROLE, approver_scope, owner_scope
from aweb_secrets.revisions import config_revision
from tests.governance import view
from tests.test_change_set_containment import forest
from tests.test_change_sets import ALICE, TEAM
from tests.test_change_sets import world as world
from tests.test_console_changes import ROOT, approve, clients, sign_in
from tests.test_use_approvals import REQUESTER, use_request
from tests.test_use_approvals import uses as uses


class Registrations:
    failure = None

    async def view(self, team_id, hook):
        assert team_id == TEAM and hook == "post-governance-hook"
        if self.failure == "missing_target":
            return None
        current = view()
        return (
            replace(current, as_of=current.as_of - timedelta(minutes=2))
            if self.failure == "stale_target"
            else current
        )


async def prepare(uses, target="installation"):
    w = uses.world
    root, descendant, old = await forest(uses)
    producer = w.credential_audit._producer()
    original = w.containment.governance

    async def governance(tx, **event):
        # Real shared admission + enqueue, as in production composition.
        # No successful predicate or recorder replaces either operation.
        if event["payload"]["direction"] == "widening":
            await producer.require_admission(
                tx,
                team_id=event["team_id"],
                hook="post-governance-hook",
                occurred_at=event["occurred_at"],
                view=event.get("view"),
                max_backlog_age=timedelta(minutes=5),
            )
        return await original(tx, **event)

    w.containment.governance = governance
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        await disable_secret_tree(
            tx,
            w.approvals,
            w.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=descendant.secret_id if target == "installation" else root.secret_id,
            revoked_by=ALICE.principal_did,
        )
        if target == "installation":
            await disable_installation(
                tx,
                w.approvals,
                w.custody,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                revoked_by=ALICE.principal_did,
            )
    return root, descendant, old


async def admission(uses, ref):
    async with uses.world.db.transaction() as tx:
        return await admit_use(
            tx,
            fence=uses.world.fence,
            grant=uses.grant,
            principal=REQUESTER,
            request=replace(use_request(str(uuid.uuid4())), secret_ref=ref),
            attestation=None,
            now=uses.clock(),
            clock=uses.clock,
        )


def item(kind, ref):
    return {
        "kind": "reenable",
        "op": "enable",
        "ref": ref,
        "after": {"v": 1, "target_kind": kind, "target_ref": ref},
    }


async def draft(human, headers, kind="installation", ref=INSTALLATION_ID):
    response = await human.post(
        ROOT,
        headers=headers,
        json={"changes": [item(kind, ref)], "sealed": [], "reason": "Recover after containment"},
    )
    assert response.status_code == 201
    return response.json()


async def snapshot(w, drafted):
    return (
        await config_revision(w.db, INSTALLATION_ID),
        await w.db.fetch_value(
            "SELECT disabled_at IS NOT NULL FROM {{tables.containment_installations}}"
            " WHERE installation_id=$1 AND team_id=$2",
            INSTALLATION_ID,
            TEAM,
        ),
        await w.db.fetch_value(
            "SELECT state FROM {{tables.change_sets}} WHERE change_id=$1",
            drafted["change_id"],
        ),
        (await w.approvals.get(drafted["approval_id"])).state,
        await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}"),
        await w.db.fetch_value("SELECT sum(last_seq) FROM {{tables.outbox_sequences}}"),
    )


@pytest.mark.parametrize("target", ["installation", "secret"])
async def test_owner_http_reenable_restores_only_the_target_with_audited_approve(uses, target):
    w = uses.world
    root, descendant, old = await prepare(uses, target)
    with pytest.raises(AdmissionRefused) as blocked:
        await admission(uses, root.ref)
    assert blocked.value.code == (
        "installation_disabled" if target == "installation" else "secret_disabled"
    )
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    async with clients(w, registrations=Registrations()) as (human, agent):
        headers = await sign_in(w, human, scope)
        drafted = await draft(
            human,
            headers,
            target,
            INSTALLATION_ID if target == "installation" else root.ref,
        )
        path = ROOT + "/" + drafted["change_id"]
        assert (await agent.get(path)).status_code == 404
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 409
        with pytest.raises(AdmissionRefused):
            await admission(uses, root.ref)
        await approve(w, human, headers, drafted)
        revision = await config_revision(w.db, INSTALLATION_ID)
        decided = await w.approvals.get(drafted["approval_id"])
        assert decided.state is ApprovalState.APPROVED
        commitment = await w.passkeys.evidence_commitment(
            decided.decided_by.evidence_ref,
            context=PasskeyInstallationContext(
                w.admitted.app_id, TEAM, INSTALLATION_ID, w.admitted.generation
            ),
            scope=decided.decided_by.scope,
            subject=decided.decided_by.subject,
            purpose="approve",
        )
        with pytest.raises(AdmissionRefused):
            await admission(uses, root.ref)
        response = await human.post(path + "/confirm", json={}, headers=headers)
        assert response.status_code == 200
        assert response.json()["revision"] == revision + 1
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.CONSUMED
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 409
    recovered = await admission(uses, root.ref)
    assert recovered.installation == w.admitted and not recovered.replayed
    await w.custody.opener.open(old)
    assert (
        await w.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1",
            descendant.secret_id,
        )
        == "disabled"
    )
    rows = await w.db.fetch_all(
        "SELECT payload,signature FROM {{tables.outbox_events}} WHERE kind='post-governance-hook'"
    )
    events = [verify(bytes(r["payload"]), r["signature"], team_id=TEAM).fields for r in rows]
    act = "installation.enabled" if target == "installation" else "resource.enabled"
    [enabled] = [e for e in events if e["payload"]["act"] == act]
    payload = enabled["payload"]
    assert enabled["actor"] == {"authority_mode": "system", "attestations": []}
    assert payload["direction"] == "widening" and payload["authority"] == "passkey_session"
    assert payload["approval_id"] == drafted["approval_id"]
    assert payload["approval_evidence_sha256"] == commitment
    assert enabled["producer"]["installation_id"] == INSTALLATION_ID
    if target == "secret":
        assert (payload["resource_type"], payload["resource_ref"]) == ("secret", root.secret_id)


@pytest.mark.parametrize(
    "failure", ["missing_target", "stale_target", "stalled", "proof", "storage"]
)
async def test_reenable_audit_or_proof_failure_rolls_back_every_effect(uses, failure):
    w = uses.world
    root, _, _ = await prepare(uses)
    targets = Registrations()
    async with clients(w, registrations=targets) as (human, _):
        headers = await sign_in(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        drafted = await draft(human, headers)
        path = await approve(w, human, headers, drafted)
        targets.failure = failure
        if failure == "proof":
            decision = await w.approvals.get(drafted["approval_id"])
            await w.db.execute(
                "DELETE FROM {{tables.passkey_proofs}} WHERE evidence_ref=$1",
                decision.decided_by.evidence_ref,
            )
        elif failure == "stalled":
            await w.db.execute(
                "UPDATE {{tables.outbox_events}} SET created_at=clock_timestamp()-interval '10 minutes'"
                " WHERE event_id=(SELECT event_id FROM {{tables.outbox_events}}"
                " WHERE kind='post-governance-hook' ORDER BY position LIMIT 1)"
            )
        elif failure == "storage":
            await w.db.execute(
                "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT refuse_reenable_event"
                " CHECK(kind<>'post-governance-hook') NOT VALID"
            )
        before = await snapshot(w, drafted)
        if failure == "storage":
            with pytest.raises(asyncpg.CheckViolationError):
                await human.post(path + "/confirm", json={}, headers=headers)
        else:
            response = await human.post(path + "/confirm", json={}, headers=headers)
            assert response.status_code == 409
            assert response.json()["detail"] == (
                "passkey_proof_unavailable"
                if failure == "proof"
                else "audit_delivery_stalled"
                if failure == "stalled"
                else "audit_target_unavailable"
            )
        assert await snapshot(w, drafted) == before
    with pytest.raises(AdmissionRefused) as blocked:
        await admission(uses, root.ref)
    assert blocked.value.code == "installation_disabled"


@pytest.mark.parametrize("failure", ["pending", "expired", "withdrawn", "nonowner"])
async def test_reenable_requires_fresh_approval_and_the_current_owner(uses, failure):
    w = uses.world
    await prepare(uses)
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await draft(human, headers)
        path = ROOT + "/" + drafted["change_id"]
        if failure != "pending":
            await approve(w, human, headers, drafted)
        if failure == "expired":
            await w.db.execute(
                "UPDATE {{tables.approvals}} SET expires_at=clock_timestamp()-interval '1 second'"
                " WHERE approval_id=$1",
                drafted["approval_id"],
            )
        elif failure == "withdrawn":
            async with w.db.transaction() as tx:
                await unassign(tx, ALICE, OWNER_ROLE)
        elif failure == "nonowner":
            headers = await sign_in(
                w,
                human,
                approver_scope(INSTALLATION_ID, TEAM, "finance"),
                "finance@acme.com",
            )
        before = await snapshot(w, drafted)
        response = await human.post(path + "/confirm", json={}, headers=headers)
        assert response.status_code == (
            401 if failure == "withdrawn" else 403 if failure == "nonowner" else 409
        )
        assert await snapshot(w, drafted) == before
        assert (await w.approvals.get(drafted["approval_id"])).state is not ApprovalState.CONSUMED


@pytest.mark.parametrize("target", ["foreign_installation", "unsupported", "foreign_scope"])
async def test_reenable_preserves_target_and_installation_scope_validation(uses, target):
    w = uses.world
    await prepare(uses)
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        if target == "foreign_installation":
            drafted = await draft(human, headers, ref="foreign-installation")
            path = await approve(w, human, headers, drafted)
            before = await snapshot(w, drafted)
            response = await human.post(path + "/confirm", json={}, headers=headers)
            assert (
                response.status_code == 409 and response.json()["detail"] == "installation_unknown"
            )
            assert await snapshot(w, drafted) == before
        else:
            response = await human.post(
                ROOT.replace(INSTALLATION_ID, "foreign-installation")
                if target == "foreign_scope"
                else ROOT,
                json={
                    "changes": [
                        item("grant", "grt_unrelated")
                        if target == "unsupported"
                        else item("installation", INSTALLATION_ID)
                    ],
                    "sealed": [],
                    "reason": "Recover",
                },
                headers=headers,
            )
            assert response.status_code == (403 if target == "foreign_scope" else 409)
            assert await w.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0

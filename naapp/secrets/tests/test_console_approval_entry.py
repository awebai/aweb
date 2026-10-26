"""Read-only common entry uses actual B2 links and immutable associations."""

from functools import partial
from uuid import uuid4

import pytest
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp.runtime.approvals import ApprovalState

from aweb_secrets.approval_kind import approval_kind
from aweb_secrets.owners import approver_scope
from aweb_secrets.reconciliation_control_audit import apply_reconciliation_migrations
from tests.test_approval_kind import linked
from tests.test_change_sets import ALICE, CAROL, TEAM, by_member, change_set, draft, grant_role
from tests.test_console_changes import clients, sign_in
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world

ENTRY = "/approvals/dispatch"


def personal_token(w, approval_id):
    [token] = [t for links in w.inbox.links.values() for a, t in links if a == approval_id]
    return token


@pytest.mark.parametrize(
    "kind,path",
    [
        ("use", "/use-approvals"),
        ("run", "/run-approvals"),
        ("reconciliation_control", "/reconciliation-approvals"),
    ],
)
async def test_dispatch_returns_only_the_exact_app_kind_without_terms_or_effects(uses, kind, path):
    actual = await linked(uses, kind)
    w = uses.world
    token = personal_token(w, actual.approval.approval_id)
    lookup = partial(
        approval_kind,
        enable_runs=kind != "use",
        enable_reconciliation=kind == "reconciliation_control",
    )
    async with clients(w, forms=True, kind_lookup=lookup) as (human, agent):
        before = await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
        page = await human.get("/approvals")
        assert page.status_code == 200 and "data-approval-entry" in page.text
        for _ in range(2):
            response = await human.post(ENTRY, json={"token": token})
            assert response.status_code == 200
            assert response.json() == {"kind": kind, "path": path}
            assert token not in response.text
            for name, value in CONSOLE_HEADERS.items():
                assert response.headers[name] == value
        assert (await agent.get("/approvals")).status_code == 404
        assert (await agent.post(ENTRY, json={"token": token})).status_code == 404
        refused = await human.post(
            ENTRY, json={"token": token}, headers={"X-AWEB-Signature": "invalid"}
        )
        assert refused.status_code == 403
        current = await w.approvals.get(actual.approval.approval_id)
        assert current.state is ApprovalState.PENDING and current.consumed_operation_id is None
        assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == before


async def test_change_set_dispatch_continues_in_the_same_document(uses):
    w = uses.world
    request = change_set(drafter=by_member(ALICE), changes=[grant_role(CAROL, "secrets.role.dev")])
    approval_id = await draft(w, request)
    token = personal_token(w, approval_id)
    async with clients(w, forms=True) as (human, _):
        response = await human.post(ENTRY, json={"token": token})
        assert response.status_code == 200
        assert response.json() == {"kind": "change_set", "path": "/approvals"}
        assert (await w.approvals.get(approval_id)).state is ApprovalState.PENDING


@pytest.mark.parametrize("corruption", ["missing", "request", "policy"])
async def test_unassociated_or_mismatched_change_set_refuses_without_fallback(uses, corruption):
    w = uses.world
    request = change_set(drafter=by_member(ALICE), changes=[grant_role(CAROL, "secrets.role.dev")])
    approval_id = await draft(w, request)
    token = personal_token(w, approval_id)
    if corruption == "missing":
        await w.db.execute(
            "DELETE FROM {{tables.change_sets}} WHERE change_id=$1", request["change_id"]
        )
    elif corruption == "request":
        await w.db.execute(
            "UPDATE {{tables.change_sets}} SET request=jsonb_set(request,'{reason}','\"different\"') WHERE change_id=$1",
            request["change_id"],
        )
    else:
        await w.db.execute(
            "UPDATE {{tables.change_sets}} SET via='console' WHERE change_id=$1",
            request["change_id"],
        )
    async with clients(w) as (human, _):
        response = await human.post(ENTRY, json={"token": token})
        assert response.status_code == 409 and response.json() == {"detail": "approval_refused"}
        assert token not in response.text
        assert (await w.approvals.get(approval_id)).state is ApprovalState.PENDING


async def test_current_non_owner_approver_can_reach_the_neutral_entry(uses):
    actual = await linked(uses, "use")
    w = uses.world
    scope = approver_scope(w.admitted.installation_id, TEAM, "finance")
    async with clients(w, forms=True) as (human, _):
        await sign_in(w, human, scope, "finance@acme.com")
        response = await human.get("/approvals")
        assert response.status_code == 200 and "data-approval-entry" in response.text
        dispatched = await human.post(
            ENTRY, json={"token": personal_token(w, actual.approval.approval_id)}
        )
        assert dispatched.json() == {"kind": "use", "path": "/use-approvals"}


@pytest.mark.parametrize(
    "body", [{}, {"token": ""}, {"token": 3}, {"token": "opaque", "scope": "other"}]
)
async def test_entry_refuses_malformed_token_bodies(uses, body):
    async with clients(uses.world) as (human, _):
        response = await human.post(ENTRY, json=body)
        assert response.status_code == 400 and response.json() == {"detail": "request_invalid"}


async def test_entry_refuses_unknown_token_and_non_json(uses):
    async with clients(uses.world) as (human, _):
        response = await human.post(ENTRY, json={"token": "unissued-personal-locator"})
        assert response.status_code == 409 and response.json() == {"detail": "approval_refused"}
        assert (await human.post(ENTRY, content='{"token":"opaque"}')).status_code == 415


@pytest.mark.parametrize("corruption", ["mismatch", "multiple"])
async def test_corrupt_app_association_is_a_fixed_service_refusal(uses, corruption):
    actual = await linked(uses, "use")
    w = uses.world
    token = personal_token(w, actual.approval.approval_id)
    await apply_reconciliation_migrations(w.db)
    # Insert a corrupt second association; real association rows cannot mutate.
    await w.db.execute(
        "INSERT INTO {{tables.reconciliation_controls}}"
        " (control_id,approval_id,app_id,installation_id,team_id,install_generation,"
        "reconcile_ref,dispatch_id,outcome,request_ref,request_sha256,policy_ref,policy_version,"
        "owner_scope,owner_subject,owner_principal,expires_at)"
        " SELECT $1,a.approval_id,c.app_id,c.installation_id,c.team_id,c.install_generation,"
        "c.intent_id,c.dispatch_id,'completed',a.request_ref,$2,$3,$4,"
        "'corrupt-routing-scope','corrupt-routing-subject',$5,$6"
        " FROM {{tables.use_approval_audits}} a JOIN {{tables.use_contexts}} c USING(dispatch_id)"
        " WHERE a.approval_id=$7",
        uuid4(),
        actual.approval.request_sha256 if corruption == "multiple" else "0" * 64,
        actual.approval.policy_ref,
        actual.approval.policy_version,
        ALICE.principal_did,
        actual.approval.expires_at,
        actual.approval.approval_id,
    )
    lookup = partial(approval_kind, enable_reconciliation=True)
    async with clients(w, kind_lookup=lookup) as (human, _):
        response = await human.post(ENTRY, json={"token": token})
        assert response.status_code == 503
        assert response.json() == {"detail": "release_context_unavailable"}
        assert token not in response.text
        current = await w.approvals.get(actual.approval.approval_id)
        assert current.state is ApprovalState.PENDING and current.consumed_operation_id is None


async def test_change_set_and_app_association_cannot_choose_a_fallback(uses):
    w = uses.world
    request = change_set(drafter=by_member(ALICE), changes=[grant_role(CAROL, "secrets.role.dev")])
    approval_id = await draft(w, request)
    actual = await w.approvals.open_link(personal_token(w, approval_id))
    source = await linked(uses, "use")
    await apply_reconciliation_migrations(w.db)
    # Corrupt the global kind association, keeping both identities exact.
    await w.db.execute(
        "INSERT INTO {{tables.reconciliation_controls}}"
        " (control_id,approval_id,app_id,installation_id,team_id,install_generation,"
        "reconcile_ref,dispatch_id,outcome,request_ref,request_sha256,policy_ref,policy_version,"
        "owner_scope,owner_subject,owner_principal,expires_at)"
        " SELECT $1,$2,c.app_id,c.installation_id,c.team_id,c.install_generation,"
        "c.intent_id,c.dispatch_id,'completed',$3,$4,$5,$6,"
        "'corrupt-routing-scope','corrupt-routing-subject',$7,$8"
        " FROM {{tables.use_approval_audits}} a JOIN {{tables.use_contexts}} c USING(dispatch_id)"
        " WHERE a.approval_id=$9",
        uuid4(),
        approval_id,
        actual.approval.request_ref,
        actual.approval.request_sha256,
        actual.approval.policy_ref,
        actual.approval.policy_version,
        ALICE.principal_did,
        actual.approval.expires_at,
        source.approval.approval_id,
    )
    async with clients(w, kind_lookup=partial(approval_kind, enable_reconciliation=True)) as (
        human,
        _,
    ):
        response = await human.post(ENTRY, json={"token": personal_token(w, approval_id)})
        assert response.status_code == 409 and response.json() == {"detail": "approval_refused"}
        assert (await w.approvals.get(approval_id)).state is ApprovalState.PENDING

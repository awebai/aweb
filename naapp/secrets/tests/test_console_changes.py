"""Human change drafts and fresh passkey confirmation on real PG/native custody."""

import os
from contextlib import asynccontextmanager

import asyncpg
import httpx
import pytest
from aweb_naapp.console import COOKIE_NAME, apply_console_migrations
from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI, Request

from aweb_secrets.approval_kind import approval_kind
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.console_values import ConsoleValues, console_values_router
from aweb_secrets.use_context import apply_use_context_migrations
from tests.test_change_set_onepassword import view
from tests.test_change_sets import ALICE, BOB, ORIGIN, TEAM, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console import API

world = _world
ROOT = f"/installations/{INSTALLATION_ID}/change-sets"
TOKEN = f"/installations/{INSTALLATION_ID}/backend-credentials/onepassword/versions"


class Registrations:
    async def view(self, team_id, hook):
        assert team_id == TEAM and hook == "post-governance-hook"
        return view()


async def application(
    w,
    *,
    registrations=None,
    cleanup=None,
    forms=False,
    human_origin=ORIGIN,
    agent_origin=API,
    kind_lookup=approval_kind,
):
    await apply_console_migrations(w.db)
    await apply_dispatch_migrations(w.db)
    await apply_use_context_migrations(w.db)

    async def installation(installation_id, *, team_id: str | None = None):
        if installation_id != INSTALLATION_ID:
            raise LookupError(installation_id)
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        credential_audit=w.credential_audit,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    w.console = console
    human_app = FastAPI()
    human_app.include_router(owner_console_router(console))
    from aweb_secrets.console_ui import console_ui_router

    human_app.include_router(console_ui_router(sessions=console.sessions))
    human_app.include_router(
        console_values_router(ConsoleValues(console=console, custody=w.custody))
    )
    changes = ConsoleChanges(
        console=console,
        changes=w.change_sets,
        approvals=w.approvals,
        registrations=registrations or Registrations(),
        approval_kind=kind_lookup,
        after_commit=cleanup or w.containment.evict,
    )
    human_app.include_router(console_changes_router(changes))
    if forms:
        from aweb_secrets.console_forms import console_forms_router

        human_app.include_router(console_forms_router(changes=changes))
    return split_origins(FastAPI(), human_app, agent_origin=agent_origin, human_origin=human_origin)


@asynccontextmanager
async def clients(w, *, registrations=None, cleanup=None, forms=False, kind_lookup=approval_kind):
    app = await application(
        w, registrations=registrations, cleanup=cleanup, forms=forms, kind_lookup=kind_lookup
    )
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield human, agent


async def sign_in(w, human, scope, contact="alice@acme.com"):
    options = await human.post("/login/options", json={"scope": scope})
    assert options.status_code == 200
    logged = await human.post(
        "/login",
        json={
            "scope": scope,
            "assertion": w.devices[contact].get(options.json()),
        },
    )
    assert logged.status_code == 200
    return {"X-CSRF-Token": logged.json()["csrf_token"]}


async def retire_owner(w, scope, subject):
    logged = await w.passkeys.verify_login(
        scope, w.devices["alice@acme.com"].get(await w.passkeys.login_options(scope))
    )
    issued = await w.console.sessions.open(
        subject=logged.subject, scope=scope, evidence_ref=logged.evidence_ref
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/session",
            "headers": [(b"cookie", (COOKIE_NAME + "=" + issued.token).encode())],
        }
    )
    session = await w.console.sessions.current(request)
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        await w.containment.authorize_console(
            tx, admitted=w.admitted, session=session, action="revoke-approver", target=scope
        )
        context = await w.credential_audit.prepare_containment(
            tx, admitted=w.admitted, session=session
        )
        with w.credential_audit.prepared(context):
            await w.passkeys.retire_in(
                tx, scope=scope, subject=subject, authorized_by=session.subject
            )
        await w.fence.check(tx, w.admitted)


async def token_draft(w, human, headers):
    entered = os.urandom(24).hex()
    staged = await human.post(TOKEN, json={"value": entered}, headers=headers)
    assert staged.status_code == 201
    response = await human.post(
        ROOT,
        headers=headers,
        json={
            "changes": [
                {
                    "kind": "backend_credential",
                    "op": "create",
                    "ref": "onepassword",
                    "after": staged.json(),
                }
            ],
            "sealed": [{"secret_id": "bkc_onepassword", "version": staged.json()["version"]}],
            "reason": "Configure team vault access",
        },
    )
    assert response.status_code == 201
    assert entered not in response.text
    return response.json()


async def approve(w, human, headers, draft, contact="alice@acme.com"):
    [(approval_id, token)] = [
        pair for pair in w.inbox.links[contact] if pair[0] == draft["approval_id"]
    ]
    assert approval_id == draft["approval_id"]
    path = ROOT + "/" + draft["change_id"]
    options = await human.post(path + "/approval-options", json={"token": token}, headers=headers)
    assert options.status_code == 200
    approved = await human.post(
        path + "/approve",
        json={
            "token": token,
            "assertion": w.devices[contact].get(options.json()),
        },
        headers=headers,
    )
    assert approved.status_code == 200
    return path


async def test_http_token_ingress_draft_fresh_passkey_and_confirmation_are_distinct(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    event_count = await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
    cleanups = []

    async def cleanup(installation_id, team_id, ids):
        assert await w.db.fetch_value("SELECT state='applied' FROM {{tables.change_sets}}")
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            == 1
        )
        cleanups.append((installation_id, team_id, ids))

    async with clients(w, cleanup=cleanup) as (human, agent):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = ROOT + "/" + drafted["change_id"]
        frozen = await human.get(path)
        assert frozen.status_code == 200
        assert frozen.headers["cache-control"] == "no-store"
        change = frozen.json()["change"]
        assert change["drafter"] == {
            "via": "console",
            "scope": scope,
            "subject": (await w.passkeys.designated_approver(scope)).subject,
        }
        assert change["team_id"] == TEAM and change["installation_id"] == INSTALLATION_ID
        assert change["base_revision"] == 0 and change["install_generation"] == 1
        assert "token" not in drafted and "deliveries" not in drafted
        assert (await agent.get(path)).status_code == 404
        refused = await human.post(path + "/confirm", json={}, headers=headers)
        assert refused.status_code == 409
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            is None
        )
        await approve(w, human, headers, drafted)
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.APPROVED
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            is None
        )
        result = await human.post(path + "/confirm", json={}, headers=headers)
        assert result.status_code == 200
        assert result.json() == {
            "change_id": drafted["change_id"],
            "revision": 1,
            "runner_registrations": [],
        }
        assert result.headers["cache-control"] == "no-store"
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.CONSUMED
        assert (
            await w.db.fetch_value(
                "SELECT count(*) FROM {{tables.outbox_events}} WHERE kind='post-governance-hook'"
            )
            == event_count + 1
        )
        repeated = await human.post(path + "/confirm", json={}, headers=headers)
        assert repeated.status_code == 409
    assert cleanups == [(INSTALLATION_ID, TEAM, ())]


async def test_console_draft_has_no_unsigned_scope_or_envelope_override(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, _):
        assert (await human.post(ROOT, json={})).status_code == 401
        await sign_in(w, human, scope)
        assert (await human.post(ROOT, json={})).status_code == 403
        headers = await sign_in(w, human, scope)
        marker = os.urandom(20).hex()
        for body in (
            {"team_id": marker},
            {"changes": [], "sealed": [], "reason": "", "drafter": marker},
        ):
            result = await human.post(ROOT, json=body, headers=headers)
            assert result.status_code == 400
            assert marker not in result.text
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0


async def test_other_owner_cannot_use_candidate_link_or_confirm_its_decision(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    bob = await enrol_owner(w, BOB, "bob@acme.com")
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = ROOT + "/" + drafted["change_id"]
        [(approval_id, token)] = w.inbox.links["alice@acme.com"]
        headers = await sign_in(w, human, bob, "bob@acme.com")
        stolen = await human.post(
            path + "/approval-options", json={"token": token}, headers=headers
        )
        assert stolen.status_code == 403
        assert (await w.approvals.get(approval_id)).state is ApprovalState.PENDING
        headers = await sign_in(w, human, scope)
        await approve(w, human, headers, drafted)
        headers = await sign_in(w, human, bob, "bob@acme.com")
        refused = await human.post(path + "/confirm", json={}, headers=headers)
        assert refused.status_code == 403
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.APPROVED
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            is None
        )


async def test_login_assertion_cannot_replace_the_fresh_approve_assertion(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = ROOT + "/" + drafted["change_id"]
        [(_, token)] = w.inbox.links["alice@acme.com"]
        login_options = await human.post("/login/options", json={"scope": scope})
        refused = await human.post(
            path + "/approve",
            json={
                "token": token,
                "assertion": w.devices["alice@acme.com"].get(login_options.json()),
            },
            headers=headers,
        )
        assert refused.status_code == 409
        assert refused.json() == {"detail": "approval_refused"}
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.PENDING
        await approve(w, human, headers, drafted)
        result = await human.post(path + "/confirm", json={}, headers=headers)
        assert result.status_code == 200


async def test_http_four_eyes_draft_uses_the_other_owners_fresh_passkey(world):
    from aweb_secrets.change_policy import require_four_eyes

    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    bob = await enrol_owner(w, BOB, "bob@acme.com")
    async with w.db.transaction() as tx:
        await require_four_eyes(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=w.directory
        )
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        assert "alice@acme.com" not in w.inbox.links
        path = ROOT + "/" + drafted["change_id"]
        headers = await sign_in(w, human, bob, "bob@acme.com")
        await approve(w, human, headers, drafted, "bob@acme.com")
        result = await human.post(path + "/confirm", json={}, headers=headers)
        assert result.status_code == 200
        assert result.json()["revision"] == 2


@pytest.mark.parametrize("failure", ["audit", "fence", "storage"])
async def test_refused_confirmation_preserves_decision_and_inert_token_without_cleanup(
    world, failure
):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    cleanups = []

    class NoRegistrations:
        async def view(self, team_id, hook):
            return None

    async def cleanup(*args):
        cleanups.append(args)

    async with clients(
        w, registrations=NoRegistrations() if failure == "audit" else None, cleanup=cleanup
    ) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = await approve(w, human, headers, drafted)
        if failure == "fence":
            await w.db.execute(
                "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()-interval '1 second'"
            )
        if failure == "storage":
            await w.db.execute(
                "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT deny_effect CHECK(kind<>'post-governance-hook') NOT VALID"
            )
        # A real SQL/storage failure is propagated by the service, not a mocked hook.
        if failure == "storage":
            with pytest.raises(asyncpg.CheckViolationError):
                await human.post(path + "/confirm", json={}, headers=headers)
        else:
            result = await human.post(path + "/confirm", json={}, headers=headers)
            assert result.status_code == (503 if failure == "fence" else 409)
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            is None
        )
        assert await w.db.fetch_value("SELECT state FROM {{tables.change_sets}}") == "pending"
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.APPROVED
        assert await w.db.fetch_value("SELECT revision FROM {{tables.config_revisions}}") is None
    assert cleanups == []


async def test_cleanup_failure_never_replays_or_rolls_back_a_committed_confirmation(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    calls = []

    async def cleanup(*args):
        calls.append(args)
        raise RuntimeError("cleanup unavailable")

    async with clients(w, cleanup=cleanup) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = await approve(w, human, headers, drafted)
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 200
        assert (await human.post(path + "/confirm", json={}, headers=headers)).status_code == 409
    assert calls == [(INSTALLATION_ID, TEAM, ())]
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}") == 1
    )
    assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.CONSUMED


async def test_retired_exact_login_or_owner_role_cannot_confirm_an_approved_change(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = await approve(w, human, headers, drafted)
        approver = await w.passkeys.designated_approver(scope)
        await retire_owner(w, scope, approver.subject)
        result = await human.post(path + "/confirm", json={}, headers=headers)
        assert result.status_code == 401 and "Max-Age=0" in result.headers["set-cookie"]
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
    assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.REVOKED


@pytest.mark.parametrize("deadline", ["fence", "session"])
async def test_confirmation_deadline_crossed_while_waiting_rolls_back_approval_and_activation(
    world, deadline
):
    import asyncio

    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    cleanups = []

    async def cleanup(*args):
        cleanups.append(args)

    async with clients(w, cleanup=cleanup) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = await approve(w, human, headers, drafted)
        table = "installation_fences" if deadline == "fence" else "console_sessions"
        column = "fresh_until" if deadline == "fence" else "expires_at"
        await w.db.execute(
            f"UPDATE {{{{tables.{table}}}}} SET {column}=clock_timestamp()+interval '2 seconds'"
        )
        posting = None
        try:
            async with w.db.transaction() as gate:
                pid = await gate.fetch_value("SELECT pg_backend_pid()")
                await gate.fetch_value("SELECT change_id FROM {{tables.change_sets}} FOR UPDATE")
                posting = asyncio.create_task(
                    human.post(path + "/confirm", json={}, headers=headers)
                )
                async with asyncio.timeout(5):
                    while not await w.db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        pid,
                    ):
                        if posting.done():
                            await posting
                            pytest.fail("confirmation did not wait for its change-set row")
                        await asyncio.sleep(0.01)
                    while await w.db.fetch_value(
                        f"SELECT {column}>clock_timestamp() FROM {{{{tables.{table}}}}}"
                    ):
                        await asyncio.sleep(0.02)
            response = await asyncio.wait_for(posting, 5)
            assert response.status_code == (503 if deadline == "fence" else 401)
            if deadline == "session":
                assert "Max-Age=0" in response.headers["set-cookie"]
        finally:
            if posting is not None and not posting.done():
                posting.cancel()
            if posting is not None:
                await asyncio.gather(posting, return_exceptions=True)
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
    assert await w.db.fetch_value("SELECT state FROM {{tables.change_sets}}") == "pending"
    assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.APPROVED
    assert cleanups == []


async def test_token_rotation_cleanup_uses_only_committed_scoped_affected_ids(world):
    from tests.test_change_set_onepassword import apply, initial

    w = world
    scope, record, _, old_binding, _, first, _ = await initial(w)
    await apply(w, first)
    cleanups = []

    async def cleanup(installation_id, team_id, ids):
        assert (
            await w.db.fetch_value(
                "SELECT active_version FROM {{tables.secrets}} WHERE secret_id=$1",
                record.secret_id,
            )
            is None
        )
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            == 2
        )
        cleanups.append((installation_id, team_id, ids))

    async with clients(w, cleanup=cleanup) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = await approve(w, human, headers, drafted)
        response = await human.post(path + "/confirm", json={}, headers=headers)
        assert response.status_code == 200
    assert cleanups == [(INSTALLATION_ID, TEAM, (record.secret_id,))]
    assert await w.db.fetch_value(
        "SELECT destroyed_at IS NOT NULL FROM {{tables.onepassword_versions}} WHERE secret_id=$1 AND version=$2",
        old_binding.context.secret_id,
        old_binding.context.version,
    )


async def test_prepared_b3_draft_stays_inert_until_its_owner_confirms(world):
    from tests.test_change_sets import designate_approver

    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, _):
        headers = await sign_in(w, human, scope)
        response = await human.post(
            ROOT,
            json={
                "changes": [designate_approver("finance", "finance@acme.com", ["sec_1"])],
                "sealed": [],
                "reason": "",
            },
            headers=headers,
        )
        assert response.status_code == 201
        assert await w.db.fetch_value("SELECT state FROM {{tables.change_sets}}") == "pending"
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.approvers}}") == 0


async def test_personal_locator_resolves_only_the_current_candidates_frozen_change(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    bob = await enrol_owner(w, BOB, "bob@acme.com")
    async with clients(w) as (human, agent):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        [(_, token)] = w.inbox.links["alice@acme.com"]
        located = await human.post("/approvals/locate", json={"token": token}, headers=headers)
        assert located.status_code == 200
        assert located.json()["change"]["change_id"] == drafted["change_id"]
        assert located.json()["approval_state"] == "pending"
        assert located.json()["can_confirm"] is False
        assert token not in located.text
        assert (await agent.post("/approvals/locate", json={"token": token})).status_code == 404
        headers = await sign_in(w, human, bob, "bob@acme.com")
        refused = await human.post("/approvals/locate", json={"token": token}, headers=headers)
        assert refused.status_code == 403 and token not in refused.text
        headers = await sign_in(w, human, scope)
        path = await approve(w, human, headers, drafted)
        approved = await human.get(path)
        assert approved.json()["approval_state"] == "approved"
        assert approved.json()["can_confirm"] is True


async def test_lost_session_after_commit_returns_only_an_applied_receipt_and_reauth(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    holder = await w.passkeys.designated_approver(scope)

    async def cleanup(*args):
        await retire_owner(w, scope, holder.subject)

    async with clients(w, cleanup=cleanup) as (human, _):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        path = await approve(w, human, headers, drafted)
        result = await human.post(path + "/confirm", json={}, headers=headers)
        assert result.status_code == 200
        assert result.json() == {
            "change_id": drafted["change_id"],
            "revision": 1,
            "state": "applied",
            "reauth_required": True,
        }
        assert "Max-Age=0" in result.headers["set-cookie"]
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            == 1
        )
        assert await w.db.fetch_value("SELECT state FROM {{tables.change_sets}}") == "applied"


async def test_personal_locator_can_offer_only_its_signin_scope_before_authentication(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, agent):
        headers = await sign_in(w, human, scope)
        drafted = await token_draft(w, human, headers)
        [(_, token)] = w.inbox.links["alice@acme.com"]
        await human.post("/logout", headers=headers)
        offered = await human.post("/approvals/sign-in", json={"token": token})
        assert offered.status_code == 200 and offered.json() == {"scope": scope}
        assert token not in offered.text and drafted["change_id"] not in offered.text
        assert (await agent.post("/approvals/sign-in", json={"token": token})).status_code == 404
        refused = await human.post("/approvals/sign-in", json={"token": "unusable-locator"})
        assert refused.status_code == 409 and "unusable-locator" not in refused.text
        assert (await w.approvals.get(drafted["approval_id"])).state is ApprovalState.PENDING
        assert (
            await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
            is None
        )

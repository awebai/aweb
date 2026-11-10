"""Real handoff/B3/change writer; this is not the supported first-owner setup."""

import asyncio
import hashlib
import json
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import timedelta
from functools import partial
from time import monotonic_ns

import httpx
import pytest
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.runtime.approvals import Approvals, PgApprovalStore
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI

from aweb_secrets.approval_kind import approval_kind
from aweb_secrets.change_sets import ChangeSetPolicies, ChangeSets, DraftLimit
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.containment import Containment
from aweb_secrets.custody import Custody, LocalKeyFileProvider, apply_custody_migrations
from aweb_secrets.runners import apply_runner_migrations, mint_runner_id
from aweb_secrets.tokens import ProcessTokenCache
from aweb_secrets.use_approvals import apply_use_approval_migrations
from tests.test_change_set_runners import runner_item
from tests.test_change_sets import Inbox, by_member, change_set
from tests.test_console_changes import Registrations
from tests.test_handoff_sessions import API, journey, signed_request  # noqa: F401
from tests.test_owner_bootstrap import world  # noqa: F401
from tests.test_owner_directory import Audit

ROOT = f"/installations/{INSTALLATION_ID}/change-sets"


@dataclass(repr=False)
class DisclosureGate:
    enabled: bool = False
    committed: asyncio.Event = field(default_factory=asyncio.Event)
    resume: asyncio.Event = field(default_factory=asyncio.Event)
    session: object = None


@dataclass(repr=False)
class ConfirmationJourney:
    handoff: object
    inbox: Inbox
    writer: ChangeSets
    approvals: Approvals
    login_scope: str
    console: OwnerConsole
    disclosure: DisclosureGate

    async def signed_post(self, key, session, path, body, *, nonce=None):
        raw = json.dumps(body).encode()
        return await self.handoff.client.post(
            path,
            content=raw,
            headers=signed_request(
                key,
                self.handoff.device.origin,
                "POST",
                path,
                raw,
                session_id=session["session_id"],
                csrf=session["csrf_token"],
                nonce=nonce,
            ),
        )

    @asynccontextmanager
    async def browser(self):
        async with httpx.AsyncClient(
            transport=self.handoff.client._transport,
            base_url=self.handoff.device.origin,
        ) as client:
            options = await client.post("/login/options", json={"scope": self.login_scope})
            assert options.status_code == 200
            login = await client.post(
                "/login",
                json={
                    "scope": self.login_scope,
                    "assertion": self.handoff.device.get(options.json()),
                },
            )
            assert login.status_code == 200
            yield client, {"X-CSRF-Token": login.json()["csrf_token"]}

    async def approve(self, browser, headers, drafted):
        approval_id = drafted["approval_id"]
        [token] = [
            token
            for links in self.inbox.links.values()
            for linked_id, token in links
            if linked_id == approval_id
        ]
        path = ROOT + "/" + drafted["change_id"]
        options = await browser.post(
            path + "/approval-options", json={"token": token}, headers=headers
        )
        assert options.status_code == 200
        decided = await browser.post(
            path + "/approve",
            json={"token": token, "assertion": self.handoff.device.get(options.json())},
            headers=headers,
        )
        assert decided.status_code == 200
        return path


@pytest.fixture
async def confirmation_journey(journey, tmp_path):  # noqa: F811
    w = journey.world
    for migrate in (
        apply_custody_migrations,
        apply_runner_migrations,
        apply_use_approval_migrations,
    ):
        await migrate(w.db)
    key_file = tmp_path / "native-custody-key"
    key_file.write_text(secrets.token_bytes(32).hex())
    key_file.chmod(0o600)
    custody = Custody(LocalKeyFileProvider(key_file), w.db)
    inbox = Inbox()
    approvals = Approvals(
        store=PgApprovalStore(w.db),
        policies=ChangeSetPolicies(w.db, w.directory),
        approvers=w.directory,
        delivery=inbox,
        authenticators=[w.passkeys.authenticator()],
        audit=Audit(w.db),
    )
    # Reuse the fixture's actual governance producer, not another audit writer.
    producer = w.credential_audit._producer()
    containment = Containment(
        db=w.db,
        fence=w.console.fence,
        approvals=approvals,
        custody=custody,
        passkeys=w.passkeys,
        directory=w.directory,
        tokens=ProcessTokenCache(),
        governance=partial(producer.enqueue, hook="post-governance-hook"),
        credential_audit=w.credential_audit,
    )
    writer = ChangeSets(
        w.db,
        approvals=approvals,
        passkeys=w.passkeys,
        directory=w.directory,
        custody=custody,
        containment=containment,
        credential_audit=w.credential_audit,
        draft_limit=DraftLimit(count=4, window=timedelta(hours=1)),
        internal_destinations=InternalDestinations.DISABLED,
    )
    disclosure = DisclosureGate()

    async def current(request):
        # Observe the real verifier result without changing its authority/deadline.
        session = await journey.factory.current(request)
        disclosure.session = session
        return session

    async def after_commit(*args):
        await containment.evict(*args)
        if disclosure.enabled:
            disclosure.committed.set()
            await disclosure.resume.wait()

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        directory=w.directory,
        fence=w.console.fence,
        verifier=w.owner.verifier,
        installation=w.console.installation,
        credential_audit=w.credential_audit,
        key_bound=current,
    )
    services = ConsoleChanges(
        console=console,
        changes=writer,
        approvals=approvals,
        registrations=Registrations(),
        after_commit=after_commit,
        approval_kind=approval_kind,
        handoffs=journey.factory,
    )
    api, human = FastAPI(), FastAPI()
    api.include_router(journey.factory.api_router())
    human.include_router(journey.factory.human_router())
    human.include_router(owner_console_router(console))
    human.include_router(console_changes_router(services))
    root = split_origins(api, human, agent_origin=API, human_origin=journey.device.origin)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root), base_url=journey.device.origin
    ) as client:
        composed = replace(journey, client=client)
        # Public B3 scope returned by the original app projection; no new holding.
        projected = await journey.factory.authority.session_target(journey.scope)
        yield ConfirmationJourney(
            composed, inbox, writer, approvals, projected.b3_scope, console, disclosure
        )


@pytest.mark.parametrize("fresh_session", [False, True], ids=["original-key", "fresh-key"])
async def test_marked_runner_confirm_belongs_only_to_a_bound_decider(
    confirmation_journey, fresh_session
):
    c = confirmation_journey
    key, issued = await c.handoff.open()
    runner = mint_runner_id()
    drafted = await c.signed_post(
        key,
        issued,
        ROOT,
        {"changes": [runner_item(runner)], "sealed": [], "reason": "Register build runner"},
    )
    assert drafted.status_code == 201
    async with c.browser() as (browser, headers):
        path = await c.approve(browser, headers, drafted.json())
        refused = await browser.post(path + "/confirm", json={}, headers=headers)
        assert refused.status_code == 409
        assert refused.json() == {"detail": "confirm_in_aw"}
        assert not await c.handoff.world.db.fetch_value("SELECT count(*) FROM {{tables.runners}}")
    if fresh_session:
        key, issued = await c.handoff.open()
    nonce = secrets.token_hex(16)
    confirmed = await c.signed_post(key, issued, path + "/confirm", {}, nonce=nonce)
    assert confirmed.status_code == 200
    [registration] = confirmed.json()["runner_registrations"]
    assert registration["runner_id"] == runner
    code = registration["registration_code"]
    stored = await c.handoff.world.db.fetch_value(
        "SELECT code_hash FROM {{tables.runners}} WHERE runner_id=$1", runner
    )
    assert bool(stored == hashlib.sha256(code.encode()).digest())
    assert (
        await c.handoff.world.db.fetch_value(
            "SELECT count(*) FROM {{tables.console_session_nonces}}"
            " WHERE token_sha256=$1 AND nonce=$2",
            c.disclosure.session.token_sha256,
            nonce,
        )
        == 1
    )
    spent = await c.signed_post(key, issued, path + "/confirm", {}, nonce=nonce)
    assert spent.status_code == 401
    assert "runner_registrations" not in spent.json()
    repeated = await c.signed_post(key, issued, path + "/confirm", {})
    assert repeated.status_code == 409
    assert "runner_registrations" not in repeated.json()
    assert await c.handoff.world.db.fetch_value("SELECT count(*) FROM {{tables.runners}}") == 1


@pytest.mark.parametrize("via", ["console", "team_auth"])
async def test_unmarked_draft_keeps_browser_confirmation(confirmation_journey, via):
    c = confirmation_journey
    runner = mint_runner_id()
    async with c.browser() as (browser, headers):
        if via == "console":
            drafted = await browser.post(
                ROOT,
                json={"changes": [runner_item(runner)], "sealed": [], "reason": "Add runner"},
                headers=headers,
            )
            assert drafted.status_code == 201
            request = drafted.json()
        else:
            # Exercise the existing team-auth draft writer, not an invented API route.
            from aweb_naapp.roles import PrincipalKey

            change = change_set(
                drafter=by_member(
                    PrincipalKey(c.handoff.member.team_id, c.handoff.scope.principal)
                ),
                changes=[runner_item(runner)],
            )
            async with c.handoff.world.db.transaction() as tx:
                pending = await c.writer.draft(tx, change)
            await c.approvals.deliver(pending)
            request = {
                "change_id": change["change_id"],
                "approval_id": pending.approval.approval_id,
            }
        path = await c.approve(browser, headers, request)
        confirmed = await browser.post(path + "/confirm", json={}, headers=headers)
        assert confirmed.status_code == 200
        assert confirmed.json()["runner_registrations"][0]["runner_id"] == runner


@pytest.mark.parametrize("loss", ["closed-session", "proof-expires-during-projection"])
async def test_committed_runner_code_is_withheld_when_result_authority_is_lost(
    confirmation_journey, loss
):
    c = confirmation_journey
    key, issued = await c.handoff.open()
    runner = mint_runner_id()
    drafted = await c.signed_post(
        key,
        issued,
        ROOT,
        {"changes": [runner_item(runner)], "sealed": [], "reason": "Register build runner"},
    )
    assert drafted.status_code == 201
    async with c.browser() as (browser, headers):
        path = await c.approve(browser, headers, drafted.json())
    c.disclosure.enabled = True
    task = asyncio.create_task(c.signed_post(key, issued, path + "/confirm", {}))
    try:
        await asyncio.wait_for(c.disclosure.committed.wait(), 10)
        # This barrier follows the actual effect commit and native cache cleanup.
        assert (
            await c.handoff.world.db.fetch_value(
                "SELECT state FROM {{tables.change_sets}} WHERE change_id=$1",
                drafted.json()["change_id"],
            )
            == "applied"
        )
        if loss == "closed-session":
            await c.console.sessions.close(c.disclosure.session)
            c.disclosure.resume.set()
        else:
            async with c.handoff.world.db.transaction() as blocker:
                holder = await blocker.fetch_value("SELECT pg_backend_pid()")
                await blocker.execute("LOCK TABLE {{tables.change_sets}} IN ACCESS EXCLUSIVE MODE")
                c.disclosure.resume.set()
                # Block the last applied-state projection read, after preparation.
                async with asyncio.timeout(5):
                    while not await c.handoff.world.db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity"
                        " WHERE $1=ANY(pg_blocking_pids(pid)))",
                        holder,
                    ):
                        await asyncio.sleep(0.01)
                original = c.disclosure.session._binding.proof
                await asyncio.sleep(max(0, (original.fresh_until - monotonic_ns()) / 1e9) + 0.02)
        result = await asyncio.wait_for(task, 10)
        assert result.status_code == 200
        assert result.json() == {
            "change_id": drafted.json()["change_id"],
            "revision": 1,
            "state": "applied",
            "reauth_required": True,
        }
        assert await c.handoff.world.db.fetch_value("SELECT count(*) FROM {{tables.runners}}") == 1
    finally:
        c.disclosure.resume.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)

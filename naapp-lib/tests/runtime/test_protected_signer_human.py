"""Real console LOGIN, exact-act B3 UV, shared effect and receipt mounts."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from awid.signing import canonical_json_bytes

from tests.runtime.test_protected_signer import ORIGIN, SCOPE
from tests.runtime.test_protected_signer_http import headers, post

pytest_plugins = ("tests.runtime.test_protected_signer_http",)


async def prepared(http_world):
    w, client, key = http_world
    intent = {**w.operation.intent(), "redirect_uri": "http://127.0.0.1:41234/callback"}
    response = await post(w, client, key, intent)
    assert response.status_code == 200, response.text
    return response.json()


async def login(w, client):
    options = await client.post("/human/login/options", json={"scope": SCOPE})
    assert options.status_code == 200, options.text
    response = await client.post(
        "/human/login", json={"scope": SCOPE, "assertion": w.device.get(options.json())}
    )
    assert response.status_code == 200, response.text
    return {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}


async def test_real_login_then_exact_act_uv_returns_same_cli_receipt(http_world):
    w, client, key = http_world
    operation = await prepared(http_world)
    path = "/handoff/" + operation["handoff_id"] + "/governance"
    assert (await client.get(path)).status_code == 401
    browser = await login(w, client)
    state = await client.get(path)
    assert state.status_code == 200, state.text
    body = state.json()
    assert body["mode"] == "governance"
    assert body["payload"] == operation["payload"]
    assert (
        body["digest"]
        == operation["digest"]
        == hashlib.sha256(
            b"aweb.approval-request/1\n" + canonical_json_bytes(body["payload"])
        ).hexdigest()
    )
    assert "candidate_links" not in body
    options = await client.post(path + "/options", json={}, headers=browser)
    assert options.status_code == 200, options.text
    assert options.json()["userVerification"] == "required"
    assertion = w.device.get(options.json())
    result = await client.post(path + "/execute", json={"assertion": assertion}, headers=browser)
    assert result.status_code == 200, result.text
    outcome = result.json()
    assert outcome["state"] == "committed"
    assert outcome["redirect_uri"] == (
        "http://127.0.0.1:41234/callback?handoff_id=" + operation["handoff_id"]
    )
    # aw is a distinct, cookie-free requester, not the browser's session.
    client.cookies.clear()
    receipt_path = "/protected-operations/" + operation["operation_id"]
    receipt = await client.get(receipt_path, headers=headers(w, key, "GET", receipt_path))
    assert receipt.status_code == 200
    assert receipt.json() == {"state": "committed", "result": outcome["result"]}
    assert (await w.audit.kinds()).count("protected_operation_signed") == 1


@pytest.mark.parametrize("mutation", ["csrf", "origin", "token", "scope"])
async def test_wrong_browser_authority_never_issues_act_options(http_world, mutation):
    w, client, _ = http_world
    operation = await prepared(http_world)
    browser = await login(w, client)
    path = "/handoff/" + operation["handoff_id"] + "/governance/options"
    if mutation == "csrf":
        browser["X-CSRF-Token"] = "wrong"
    elif mutation == "origin":
        browser["Origin"] = "https://attacker.example"
    elif mutation == "token":
        client.cookies.clear()
        browser["Authorization"] = "Bearer account-token"
    else:
        await w.passkeys.db.execute("UPDATE {{tables.console_sessions}} SET scope='other-scope'")
    response = await client.post(path, json={}, headers=browser)
    assert response.status_code in (401, 403), response.text
    assert (await w.audit.kinds()).count("protected_operation_signed") == 0


async def test_login_assertion_cannot_be_reused_as_governance_uv(http_world):
    w, client, _ = http_world
    operation = await prepared(http_world)
    options = (await client.post("/human/login/options", json={"scope": SCOPE})).json()
    assertion = w.device.get(options)
    signed_in = await client.post("/human/login", json={"scope": SCOPE, "assertion": assertion})
    assert signed_in.status_code == 200
    response = await client.post(
        "/handoff/" + operation["handoff_id"] + "/governance/execute",
        json={"assertion": assertion},
        headers={"Origin": ORIGIN, "X-CSRF-Token": signed_in.json()["csrf_token"]},
    )
    assert response.status_code == 403, response.text
    assert (await w.audit.kinds()).count("protected_operation_signed") == 0


async def test_retired_login_credential_refuses_the_human_page(http_world):
    w, client, _ = http_world
    operation = await prepared(http_world)
    await login(w, client)
    await w.passkeys.db.execute("UPDATE {{tables.passkey_credentials}} SET revoked_at=NOW()")
    response = await client.get("/handoff/" + operation["handoff_id"] + "/governance")
    assert response.status_code == 401
    assert (await w.audit.kinds()).count("protected_operation_signed") == 0


async def test_page_context_is_routing_only_and_uses_the_trusted_csrf_key(http_world):
    _, client, _ = http_world
    operation = await prepared(http_world)
    # The real ASGI mount used by this client, not an actor-free HTTP endpoint.
    mount = client._transport.app.state.protected_operations
    routing = await mount.page_context(operation["handoff_id"])
    assert routing == {"b3_scope": SCOPE, "csrf_key": "protected-human-csrf"}
    state = await client.get("/handoff/" + operation["handoff_id"] + "/governance")
    assert state.status_code == 401


async def test_closed_session_after_options_cannot_sign(http_world):
    w, client, _ = http_world
    operation = await prepared(http_world)
    browser = await login(w, client)
    path = "/handoff/" + operation["handoff_id"] + "/governance"
    options = await client.post(path + "/options", json={}, headers=browser)
    assert options.status_code == 200, options.text
    proof = w.device.get(options.json())
    await w.passkeys.db.execute("UPDATE {{tables.console_sessions}} SET closed_at=NOW()")
    response = await client.post(path + "/execute", json={"assertion": proof}, headers=browser)
    assert response.status_code == 401
    assert (await w.audit.kinds()).count("protected_operation_signed") == 0


@pytest.mark.parametrize("route", ["state", "options", "execute"])
async def test_valid_other_scope_login_with_same_subject_cannot_approve(http_world, route):
    w, client, _ = http_world
    operation = await prepared(http_world)
    # The original candidate is frozen in B2. The same subject now genuinely
    # logs in to another admitted console scope with its real credential.
    await w.passkeys.db.execute(
        "UPDATE {{tables.passkey_approvers}} SET scope='other-console-scope'"
    )
    options = await client.post("/human/login/options", json={"scope": "other-console-scope"})
    assert options.status_code == 200, options.text
    signed_in = await client.post(
        "/human/login",
        json={"scope": "other-console-scope", "assertion": w.device.get(options.json())},
    )
    assert signed_in.status_code == 200, signed_in.text
    session = await w.passkeys.db.fetch_one("SELECT * FROM {{tables.console_sessions}}")
    assert session["subject"] == w.human.subject
    assert await w.passkeys.login_evidence_is_current(
        "other-console-scope", session["subject"], session["evidence_ref"]
    )
    path = "/handoff/" + operation["handoff_id"] + "/governance"
    if route == "state":
        response = await client.get(path)
    else:
        response = await client.post(
            path + "/" + route,
            json={} if route == "options" else {"assertion": {}},
            headers={"Origin": ORIGIN, "X-CSRF-Token": signed_in.json()["csrf_token"]},
        )
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "console_session_required"}
    assert (await w.audit.kinds()).count("protected_operation_signed") == 0


class WaitingSQLAuthority:
    """Real authority checks plus a SQL gate at the selected effect phase.

    This adds latency, not responses: every existing authority check delegates,
    every wait is a real PostgreSQL row-lock wait, and every result is real SQL.
    """

    def __init__(self, delegate, operation_id, phase):
        self.delegate, self.operation_id, self.phase = delegate, operation_id, phase

    async def observe(self, context, *, purpose):
        held = await self.delegate.observe(context, purpose=purpose)
        owner = self

        class Fence:
            team_key_did = held.team_key_did

            async def wait(self, tx, phase):
                row = await tx.fetch_one(
                    "SELECT a.state, o.result IS NOT NULL AS signed "
                    "FROM {{tables.protected_signer_operations}} o "
                    "JOIN {{tables.approvals}} a ON a.approval_id=o.approval_id "
                    "WHERE o.operation_id=$1",
                    owner.operation_id,
                )
                if (
                    purpose == "execute"
                    and owner.phase == phase
                    and (row["state"] == "approved" if phase == "prepare" else row["signed"])
                ):
                    await tx.fetch_value(
                        "SELECT id FROM {{tables.human_effect_gate}} WHERE id=1 FOR SHARE"
                    )

            async def prepare(self, tx, actor):
                await held.prepare(tx, actor)
                await self.wait(tx, "prepare")

            async def check(self, tx, actor):
                await held.check(tx, actor)
                await self.wait(tx, "final")

            def require_fresh(self):
                held.require_fresh()

        return Fence()


async def observed_gate_wait(db, blocker_pid, request_task):
    async with asyncio.timeout(15):
        while True:
            if request_task.done():
                result = request_task.result()
                pytest.fail(f"request completed before the database wait: {result.status_code}")
            if await db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE "
                "$1=ANY(pg_blocking_pids(pid)) AND query LIKE '%human_effect_gate%')",
                blocker_pid,
            ):
                return
            await asyncio.sleep(0.01)


@pytest.mark.parametrize("interruption", ["closed_before_effect", "expired_at_final", "current"])
async def test_admitted_browser_session_is_rechecked_across_real_effect_wait(
    http_world, interruption
):
    w, client, _ = http_world
    # One injected clock governs the original operation, UV and final session
    # deadline. SQL sessions still have a real, unexpired original timestamp.
    w.clock.now = datetime.now(UTC)
    operation = await prepared(http_world)
    browser = await login(w, client)
    expiry = w.clock() + timedelta(seconds=120)
    await w.passkeys.db.execute("UPDATE {{tables.console_sessions}} SET expires_at=$1", expiry)
    path = "/handoff/" + operation["handoff_id"] + "/governance"
    options = await client.post(path + "/options", json={}, headers=browser)
    assert options.status_code == 200, options.text
    assertion = w.device.get(options.json())
    await w.passkeys.db.execute("CREATE TABLE {{tables.human_effect_gate}} (id INT PRIMARY KEY)")
    await w.passkeys.db.execute("INSERT INTO {{tables.human_effect_gate}} VALUES(1)")
    phase = "prepare" if interruption == "closed_before_effect" else "final"
    w.signer.authority = WaitingSQLAuthority(w.signer.authority, operation["operation_id"], phase)
    task = None
    try:
        async with w.passkeys.db.transaction() as blocker:
            await blocker.fetch_one(
                "SELECT id FROM {{tables.human_effect_gate}} WHERE id=1 FOR UPDATE"
            )
            pid = await blocker.fetch_value("SELECT pg_backend_pid()")
            task = asyncio.create_task(
                client.post(path + "/execute", json={"assertion": assertion}, headers=browser)
            )
            await observed_gate_wait(w.passkeys.db, pid, task)
            if interruption == "closed_before_effect":
                await w.passkeys.db.execute(
                    "UPDATE {{tables.console_sessions}} SET closed_at=NOW()"
                )
            elif interruption == "expired_at_final":
                w.clock.now = expiry + timedelta(milliseconds=1)
        response = await asyncio.wait_for(task, 15)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    row = await w.passkeys.db.fetch_one(
        "SELECT o.result,a.state FROM {{tables.protected_signer_operations}} o "
        "JOIN {{tables.approvals}} a ON a.approval_id=o.approval_id WHERE o.operation_id=$1",
        operation["operation_id"],
    )
    if interruption == "current":
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "committed"
        assert row["result"] is not None and row["state"] == "consumed"
        assert (await w.audit.kinds()).count("protected_operation_signed") == 1
    else:
        assert response.status_code == 401, response.text
        assert response.json() == {"detail": "console_session_required"}
        assert row["result"] is None and row["state"] == "approved"
        assert (await w.audit.kinds()).count("protected_operation_signed") == 0

"""Real console LOGIN, exact-act B3 UV, shared effect and receipt mounts."""

from __future__ import annotations

import hashlib

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

"""Real current-owner console/CSRF/PG/registry preparation; coordinator VM only.

These prepare a pending intent, never approve, sign, or release it. Genuine
UV/protected-consumer application is a separate joined native selection.
"""

from contextlib import asynccontextmanager
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.console import COOKIE_NAME, CSRF_HEADER, apply_console_migrations
from fastapi import FastAPI

from tests.test_independent_protected_signer import TEAM
from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_boundary_retention_native import activate
from tests.test_protected_owner_removal_native import legacy_member

pytest_plugins = ("tests.test_independent_protected_signer",)


@asynccontextmanager
async def owner_http(a, tmp_path):
    c = a.w.app
    custody = await activate(a, tmp_path)
    await apply_console_migrations(c.db)
    sessions = c.protected_sessions()
    scope = a.w.human.b3_scope
    login = await c.passkeys.verify_login(scope, a.w.device.get(await c.passkeys.login_options(scope)))
    issued = await sessions.open(subject=login.subject, scope=scope, evidence_ref=login.evidence_ref)

    class Limiter:
        async def admit(self, *args, **kwargs):
            pass  # Authority controls; production limiter is unchanged.

    app = FastAPI()
    mount = c.operations_http(limiter=Limiter(), human_sessions=sessions, human_csrf_key="owner-init-csrf")
    app.include_router(mount.human_router())
    from aweb.protected_signing.owner import owner_router

    app.include_router(owner_router(c, sessions=sessions, csrf_key="owner-init-csrf"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=a.w.human_origin,
        cookies={COOKIE_NAME: issued.token}) as client:
        yield client, {"Origin": a.w.human_origin, CSRF_HEADER: issued.csrf_token}, custody



@asynccontextmanager
async def independent_reader(a):
    """Host reads survive revoking the root's own membership certificate."""
    from aweb.protected_signing.registry import CustomerRegistry

    key, _ = await legacy_member(a, "local", alias="protected-receipt-reader")
    original = a.w.registry
    registry = CustomerRegistry(registry_origin=original.registry_url, namespace_keys=original.namespace_keys,
        transport=a.w.host.transport, member_signing_keys={TEAM: bytes(key)})
    a.w.registry = a.w.app.registry = a.w.app.authority.registry = registry
    try:
        yield key
    finally:
        await registry.aclose()
        a.w.registry = a.w.app.registry = a.w.app.authority.registry = original

def selection(certificate):
    return {"operation_id": str(uuid4()), "operation": "team.agent.remove", "variant": "owner_approved",
        "team_id": TEAM, "certificate_id": certificate["certificate_id"]}


@pytest.mark.asyncio
async def test_current_owner_can_prepare_without_a_root_grant_but_login_cannot_sign(admissions, tmp_path, monkeypatch):
    a = admissions
    _, certificate = await legacy_member(a, "unknown")
    body = selection(certificate)
    async with owner_http(a, tmp_path) as (client, headers, custody):
        await a.w.db.execute("UPDATE {{tables.protected_requester_bindings}} SET active=false")
        response = await client.post("/governance/operations", json=body, headers=headers)
        assert response.status_code == 200, response.text
        frozen = response.json()
        request = frozen["payload"]["request"]
        assert request["requester"] == request["requester_key"] == custody.service_did_key
        assert request["target_kind"] == "kind not verified" and request["approval_format"] == "intent_v1"
        assert request["subject"]["certificate_id"] == certificate["certificate_id"]
        row = await a.w.db.fetch_one("SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", body["operation_id"])
        assert row["initiator_subject"] == a.w.human.subject and row["initiator_scope"] == a.w.human.b3_scope
        assert all(row[name] is None for name in ("issued_artifact", "signed_result", "result", "delivery_claim"))
        assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0

        async def no_refresh(*args, **kwargs):
            pytest.fail("an owned selection retry must use its saved subject before refreshing the target")

        monkeypatch.setattr(a.w.registry, "list_team_certificates_fresh", no_refresh)
        retry = await client.post("/governance/operations", json=body, headers=headers)
        assert retry.status_code == 200 and retry.json() == frozen
        changed = await client.post("/governance/operations", json={**body, "certificate_id": str(uuid4())}, headers=headers)
        assert changed.status_code == 409 and changed.json() == {"detail": "operation_conflict"}
        after = await a.w.db.fetch_one("SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", body["operation_id"])
        assert after == row


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["csrf", "origin", "host", "credential", "session", "foreign_team", "extra", "unserved"])
async def test_owner_prepare_refuses_wrong_session_scope_origin_or_selector_without_pending_state(admissions, tmp_path, change):
    a = admissions
    _, certificate = await legacy_member(a, "local")
    body = selection(certificate)
    async with owner_http(a, tmp_path) as (client, headers, _):
        if change == "csrf":
            headers.pop(CSRF_HEADER)
        if change == "origin":
            headers["Origin"] = "https://wrong.example"
        if change == "host":
            headers["Host"] = "wrong.example"
        if change == "credential":
            await a.w.db.execute("UPDATE {{tables.passkey_credentials}} SET revoked_at=NOW() WHERE subject=$1", a.w.human.subject)
        if change == "session":
            await a.w.db.execute("UPDATE {{tables.console_sessions}} SET expires_at=NOW()-$1::interval", timedelta(seconds=1))
        if change == "foreign_team":
            body["team_id"] = "another:customer.example"
        if change == "extra":
            body["requester_key"] = "did:key:caller"
        if change == "unserved":
            body["variant"] = "default"
        response = await client.post("/governance/operations", json=body, headers=headers)
        expected = {"csrf": (403, "csrf_token_required"), "origin": (403, "scope_refused"),
            "host": (403, "scope_refused"), "credential": (401, "console_session_required"),
            "session": (401, "console_session_required"), "foreign_team": (403, "scope_refused"),
            "extra": (400, "request_invalid"), "unserved": (400, "operation_not_served")}[change]
        assert response.status_code == expected[0] and response.json() == {"detail": expected[1]}, response.text
        assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", body["operation_id"]) == 0
        assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("lost_answer", [False, True])
@pytest.mark.parametrize("target", ["legacy", "root"])
async def test_owner_console_uv_reaches_protected_revocation_and_exact_recovery_without_a_root_grant(
    admissions, tmp_path, monkeypatch, lost_answer, target
):
    import base64
    import json

    from aweb_naapp.runtime.protected_signer import SignerRefused
    from awid.signing import canonical_json_bytes

    from tests.test_protected_owner_removal_native import revoked

    a = admissions
    if target == "legacy":
        _, certificate = await legacy_member(a, "unknown")
    else:
        from tests.test_independent_protected_signer import DOMAIN, did

        rows = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=True)
        root = next(row for row in rows if row.member_did_key == did(a.w.root))
        certificate = {"certificate_id": root.certificate_id}
    body = selection(certificate)
    async with independent_reader(a), owner_http(a, tmp_path) as (client, headers, custody):
        await a.w.db.execute("UPDATE {{tables.protected_requester_bindings}} SET active=false")
        prepared_response = await client.post("/governance/operations", json=body, headers=headers)
        assert prepared_response.status_code == 200, prepared_response.text
        prepared = prepared_response.json()
        path = "/handoff/" + prepared["handoff_id"] + "/governance"
        view = await client.get(path)
        assert view.status_code == 200 and view.json()["state"] == "pending", view.text
        frozen = view.json()["payload"]["request"]
        assert frozen == prepared["payload"]["request"] and frozen["target_kind"] == "kind not verified"
        query = "SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1"
        before = await a.w.db.fetch_one(query, body["operation_id"])
        assert before["issued_artifact"] is None and before["signed_result"] is None
        posts = []
        deliver = custody.deliver_retained

        async def release(operation, retained):
            posts.append(retained.fields())
            await deliver(operation, retained)
            if lost_answer:
                raise SignerRefused("receipt_unavailable")  # Lose only the applied answer.

        monkeypatch.setattr(custody, "deliver_retained", release)
        options = await client.post(path + "/options", json={}, headers=headers)
        assert options.status_code == 200, options.text
        proof = a.w.device.get(options.json())
        answer = await client.post(path + "/execute", json={"assertion": proof}, headers=headers)
        if lost_answer:
            assert answer.status_code == 503 and answer.json() == {"detail": "receipt_unavailable"}
        else:
            assert answer.status_code == 200 and answer.json()["state"] == "committed", answer.text
        assert await revoked(a, certificate)
        signed = await a.w.db.fetch_one(query, body["operation_id"])
        # A lost applied answer removes the member from the active listing.
        # The owner can still reopen the same handoff from unresolved History.
        if lost_answer:
            page = await client.get("/")
            assert page.status_code == 200, page.text
            locator = "/handoff/" + prepared["handoff_id"]
            assert f'href="{locator}"' in page.text and "Check this request" in page.text
            assert f'data-remove-certificate="{body["certificate_id"]}"' not in page.text
            assert f'data-final-operation="{body["operation_id"]}"' not in page.text
            path = locator + "/governance"
        # Authenticated receipt recovery confirms the exact retained effect,
        # independently of the member listing and without another delivery.
        recovered = await client.get(path)
        assert recovered.status_code == 200 and recovered.json()["state"] == "committed", recovered.text
        result = recovered.json()["result"]
        assert result["v"] == 2 and result["delivery"]["state"] == "applied"
        assert result["delivery"]["reference"]["operation_id"] == body["operation_id"]
        issued = json.loads(signed["issued_artifact"])
        signing = base64.b64decode(result["artifact"]["signing"], validate=True)
        signature = base64.b64decode(result["artifact"]["signature"], validate=True)
        assert signing == canonical_json_bytes(issued["request"])
        assert issued["request"]["certificate_id"] == body["certificate_id"]
        a.w.controller.verify_key.verify(signing, signature)
        replay = await client.post(path + "/execute", json={"assertion": proof}, headers=headers)
        assert replay.status_code == 200 and replay.json() == {"state": "committed", "result": result}
        after = await a.w.db.fetch_one(query, body["operation_id"])
        for name in ("intent", "request", "digest", "expires_at", "initiator_subject", "initiator_scope", "initiation_selection"):
            assert after[name] == before[name]
        for name in ("issued_artifact", "signed_result", "retained_effect", "delivery_claim"):
            assert after[name] == signed[name] and after[name] is not None
        assert len(posts) == 1
        for kind in ("protected_operation_signed", "protected_operation_applied"):
            assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_local_audit}} WHERE subject=$1 AND kind=$2",
                body["operation_id"], kind) == 1
        assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["unsigned", "signed", "unavailable"])
async def test_owner_retry_retires_only_definite_unsigned_expiry_and_can_start_a_new_uuid(
    admissions, tmp_path, monkeypatch, state
):
    from aweb.protected_signing.owner import owner_view
    from aweb_naapp.runtime.protected_signer import OperationReceipt, SignerRefused

    a = admissions
    _, certificate = await legacy_member(a, "unknown")
    body = selection(certificate)
    async with owner_http(a, tmp_path) as (client, headers, _):
        signer = a.w.app.signer
        signer.mailed_approval_wait = timedelta(seconds=30)
        response = await client.post("/governance/operations", json=body, headers=headers)
        assert response.status_code == 200, response.text
        prepared = response.json()
        path = "/handoff/" + prepared["handoff_id"] + "/governance"
        if state == "signed":
            async def no_release(operation_id, *args, **kwargs):
                return OperationReceipt(operation_id, "unknown", code="external_effect_unresolved")

            monkeypatch.setattr(signer, "_reconcile_retained", no_release)
            options = await client.post(path + "/options", json={}, headers=headers)
            assert options.status_code == 200, options.text
            answer = await client.post(path + "/execute", json={"assertion": a.w.device.get(options.json())}, headers=headers)
            assert answer.status_code == 200 and answer.json()["state"] == "unknown", answer.text
        query = "SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1"
        before = await a.w.db.fetch_one(query, body["operation_id"])
        assert (before["signed_result"] is not None) == (state == "signed")
        assert (before["retained_effect"] is not None) == (state == "signed")
        expired = before["expires_at"] + timedelta(seconds=1)
        monkeypatch.setattr(signer, "clock", lambda: expired)
        if state == "unavailable":
            observe = signer.authority.observe

            async def unavailable(*args, **kwargs):
                fence = await observe(*args, **kwargs)

                class Unavailable:
                    def __getattr__(self, name):
                        return getattr(fence, name)

                    async def check(self, *args, **kwargs):
                        raise SignerRefused("evidence_unavailable")

                return Unavailable()

            monkeypatch.setattr(signer.authority, "observe", unavailable)
        response = await client.post("/governance/operations", json=body, headers=headers)
        after = await a.w.db.fetch_one(query, body["operation_id"])
        if state == "unsigned":
            assert response.status_code == 410 and response.json() == {"detail": "operation_expired"}, response.text
            assert after["refusal_code"] == "operation_expired"
            assert all(after[name] is None for name in ("result", "signed_result", "retained_effect", "issued_artifact", "delivery_claim"))
            assert all(after[name] == before[name] for name in ("request", "intent", "digest", "expires_at", "initiation_selection"))
            view = await owner_view(a.w.app, scope=a.w.human.b3_scope, subject=a.w.human.subject, now=expired)
            history = next(item for item in view["history"] if item["operation_id"] == body["operation_id"])
            assert history["state"] == "refused" and history["code"] == "operation_expired"
            retry = await client.post("/governance/operations", json=body, headers=headers)
            assert retry.status_code == 410
            assert await a.w.db.fetch_value(
                "SELECT count(*) FROM {{tables.protected_local_audit}} WHERE subject=$1 AND kind='protected_operation_refused'",
                body["operation_id"],
            ) == 1
            fresh = await client.post("/governance/operations", json={**body, "operation_id": str(uuid4())}, headers=headers)
            assert fresh.status_code == 200 and fresh.json()["operation_id"] != body["operation_id"], fresh.text
        elif state == "signed":
            assert response.status_code == 200 and response.json() == prepared, response.text
            assert after == before
        else:
            assert response.status_code == 503 and response.json() == {"detail": "receipt_unavailable"}, response.text
            assert after == before
        assert await a.w.db.fetch_value("SELECT count(*) FROM {{tables.protected_root_admissions}}") == 0

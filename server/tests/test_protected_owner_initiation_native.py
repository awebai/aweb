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
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=a.w.human_origin,
        cookies={COOKIE_NAME: issued.token}) as client:
        yield client, {"Origin": a.w.human_origin, CSRF_HEADER: issued.csrf_token}, custody


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
            await a.w.db.execute("UPDATE {{tables.console_sessions}} SET expires_at=NOW()-$1", timedelta(seconds=1))
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

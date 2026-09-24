from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path
from dataclasses import asdict
from unittest.mock import AsyncMock
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.api import create_app
from aweb.auth_context import GRANT_SCOPE_ANY, GRANT_SCOPES, GrantContext
from aweb.grant_streams import agent_event_allowed, allowed_status_categories, grant_terminal_reason
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.coordination.routes.repos import router as repos_router
from aweb.coordination.routes.tasks import router as tasks_router
from aweb.coordination.routes.team_instructions import router as instructions_router
from aweb.coordination.routes.team_roles import router as roles_router
from aweb.coordination.routes.workspaces import router as workspaces_router
from aweb.routes import agents as agents_routes
from aweb.routes.chat import router as chat_router, stream as chat_stream_route
from aweb.routes.claims import router as claims_router
from aweb.routes.contacts import router as contacts_router
from aweb.routes.events import event_stream as events_stream_route, router as events_router
from aweb.routes.agents import router as agents_router
from aweb.routes.identity_grants import router as identity_grants_router
from aweb.routes.messages import router as messages_router
from aweb.routes.reservations import router as reservations_router
from aweb.routes.status import router as status_router, status_stream as status_stream_route
from aweb.team_auth_deps import TeamIdentity, get_team_identity, team_identity_with_grant_scope

REPO_ROOT = Path(__file__).resolve().parents[2]

TEAM_ID = "backend:acme.com"
SUBJECT_DID_KEY = "did:key:z6MkSubjectAlice"


class _DbShim:
    def __init__(self, manager):
        self.manager = manager

    def get_manager(self, name="aweb"):
        return self.manager


def _cached_body_receive(body: bytes):
    replayed = False

    async def _receive():
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    return _receive


async def _identity(request: Request):
    return TeamIdentity(
        team_id=TEAM_ID, alias=request.app.state.alias, did_key=SUBJECT_DID_KEY,
        did_aw="did:aw:alice", address="acme.com/alice",
        agent_id=request.app.state.agent_id,
        identity_scope="global", certificate_id="cert-1",
    )


def _auth_view(auth: MessagingAuth) -> dict:
    return asdict(auth)


def _build_app(aweb_db) -> FastAPI:
    app = FastAPI()
    app.include_router(identity_grants_router)

    @app.get("/v1/messages")
    async def _inbox(auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.post("/v1/messages")
    async def _send(auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.get("/v1/agents")
    async def _roster(auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.get("/v1/team-agents")
    async def _team_roster(identity: TeamIdentity = Depends(team_identity_with_grant_scope(GRANT_SCOPE_ANY))):
        return asdict(identity)

    @app.post("/v1/heartbeat")
    async def _heartbeat(identity: TeamIdentity = Depends(team_identity_with_grant_scope("presence.write"))):
        return asdict(identity)

    @app.get("/v1/chat/{session_id}/messages")
    async def _chat_read(session_id: str, auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.post("/v1/chat/{session_id}/messages")
    async def _chat_send(session_id: str, auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.post("/v1/chat/{session_id}/read")
    async def _chat_mark_read(session_id: str, auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.get("/v1/contacts")
    async def _contacts_read(auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.post("/v1/contacts")
    async def _contacts_write(auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.delete("/v1/contacts/{contact_id}")
    async def _contacts_delete(contact_id: str, auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    # Hypothetical wiring: even if a privileged route resolved messaging auth,
    # the grant verifier's path gate must refuse it.
    @app.post("/v1/session-leases")
    async def _lease(auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    app.dependency_overrides[get_team_identity] = _identity
    app.state.db = _DbShim(aweb_db)
    app.state.public_origin = "http://test"
    # Grant auth checks the issuing certificate against the registry's
    # revocations (aweb-abfn); default to none revoked.
    registry = AsyncMock()
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry

    @app.middleware("http")
    async def cache_body_middleware(request, call_next):
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = hashlib.sha256(body).hexdigest()
        request._receive = _cached_body_receive(body)
        return await call_next(request)

    return app


async def _fixture(aweb_db):
    agent_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:zTeam')
        """,
        TEAM_ID,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, alias, did_key, did_aw, address, status, identity_scope)
        VALUES ($1, $2, 'alice', $3, 'did:aw:alice', 'acme.com/alice', 'active', 'global')
        """,
        agent_id, TEAM_ID, SUBJECT_DID_KEY,
    )
    app = _build_app(aweb_db)
    app.state.agent_id = str(agent_id)
    app.state.alias = "alice"
    return app, agent_id


def _session_keypair():
    signing_key = SigningKey.generate()
    return bytes(signing_key), did_from_public_key(bytes(signing_key.verify_key))


def _grant_headers(
    *,
    signing_key: bytes,
    did_key: str,
    grant_id: str,
    method: str,
    path: str,
    body: bytes = b"",
    aud: str = "http://test",
    payload_overrides: dict | None = None,
):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "v": 1,
        "auth": "identity-grant",
        "method": method,
        "path": path,
        "grant_id": grant_id,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp": timestamp,
        "aud": aud,
    }
    payload.update(payload_overrides or {})
    canonical = canonical_json_bytes(payload)
    return {
        "Authorization": f"AWEB-Grant DIDKey {did_key} {sign_message(signing_key, canonical)}",
        "X-AWEB-Grant-ID": grant_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).decode().rstrip("="),
        "Content-Type": "application/json",
    }


async def _mint(client, *, grant_did_key: str, scopes: list[str], ttl_seconds: int = 600, label: str | None = None):
    body = {"grant_did_key": grant_did_key, "scopes": scopes, "ttl_seconds": ttl_seconds}
    if label is not None:
        body["label"] = label
    return await client.post("/v1/identity-grants", json=body)


@pytest.mark.asyncio
async def test_mint_and_grant_send_resolves_subject_attribution(aweb_cloud_db):
    app, agent_id = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        minted = await _mint(client, grant_did_key=did_key, scopes=["mail.send", "mail.send", "mail.read"], label="ci worker")
        assert minted.status_code == 200, minted.text
        grant = minted.json()
        assert grant["team_id"] == TEAM_ID
        assert grant["subject_alias"] == "alice"
        assert grant["subject_did_aw"] == "did:aw:alice"
        assert grant["grant_did_key"] == did_key
        assert grant["scopes"] == ["mail.send", "mail.read"]

        body = b'{"to":"bob","body":"hello"}'
        sent = await client.post(
            "/v1/messages",
            content=body,
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant["grant_id"],
                method="POST", path="/v1/messages", body=body,
            ),
        )
    assert sent.status_code == 200, sent.text
    auth = sent.json()
    assert auth["did_key"] == SUBJECT_DID_KEY
    assert auth["did_aw"] == "did:aw:alice"
    assert auth["address"] == "acme.com/alice"
    assert auth["alias"] == "alice"
    assert auth["agent_id"] == str(agent_id)
    assert auth["team_id"] == TEAM_ID
    assert auth["verified_team_id"] == TEAM_ID
    assert auth["identity_scope"] == "global"
    assert auth["certificate_id"] is None
    assert auth["grant"]["grant_id"] == grant["grant_id"]
    assert auth["grant"]["session_did_key"] == did_key


@pytest.mark.asyncio
async def test_wrong_session_key_is_rejected(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    other_signing_key, other_did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        wrong_key = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=other_signing_key, did_key=other_did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
        forged_did = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=other_signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
    assert wrong_key.status_code == 403
    assert wrong_key.json()["detail"] == "identity grant rejected"
    assert forged_did.status_code == 403
    assert forged_did.json()["detail"] == "identity grant rejected"


@pytest.mark.asyncio
async def test_expired_grant_is_rejected(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.identity_session_grants}}
            SET issued_at = NOW() - INTERVAL '120 seconds', expires_at = NOW() - INTERVAL '1 second'
            WHERE grant_id = $1::UUID
            """,
            grant_id,
        )
        expired = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
    assert expired.status_code == 403
    assert expired.json()["detail"] == "grant expired"


@pytest.mark.asyncio
async def test_revoked_grant_is_rejected(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        revoked = await client.post(f"/v1/identity-grants/{grant_id}/revoke")
        assert revoked.status_code == 200
        rejected = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
    assert rejected.status_code == 403
    assert rejected.json()["detail"] == "grant revoked"


@pytest.mark.asyncio
async def test_scope_enforcement_for_mail_chat_and_roster(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    send_key, send_did = _session_keypair()
    chat_key, chat_did = _session_keypair()
    contacts_key, contacts_did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        send_grant = (await _mint(client, grant_did_key=send_did, scopes=["mail.send"])).json()["grant_id"]
        chat_grant = (await _mint(client, grant_did_key=chat_did, scopes=["chat.read"])).json()["grant_id"]
        contacts_grant = (await _mint(client, grant_did_key=contacts_did, scopes=["contacts.read", "contacts.write"])).json()["grant_id"]

        def send_headers(method, path):
            return _grant_headers(signing_key=send_key, did_key=send_did, grant_id=send_grant, method=method, path=path)

        def chat_headers(method, path):
            return _grant_headers(signing_key=chat_key, did_key=chat_did, grant_id=chat_grant, method=method, path=path)

        def contacts_headers(method, path):
            return _grant_headers(signing_key=contacts_key, did_key=contacts_did, grant_id=contacts_grant, method=method, path=path)

        inbox_denied = await client.get("/v1/messages", headers=send_headers("GET", "/v1/messages"))
        send_allowed = await client.post("/v1/messages", headers=send_headers("POST", "/v1/messages"))
        roster_allowed = await client.get("/v1/agents", headers=send_headers("GET", "/v1/agents"))
        team_roster_allowed = await client.get("/v1/team-agents", headers=send_headers("GET", "/v1/team-agents"))
        presence_denied = await client.post("/v1/heartbeat", headers=send_headers("POST", "/v1/heartbeat"))
        lease_denied = await client.post("/v1/session-leases", headers=send_headers("POST", "/v1/session-leases"))

        chat_read_allowed = await client.get("/v1/chat/s1/messages", headers=chat_headers("GET", "/v1/chat/s1/messages"))
        mark_read_allowed = await client.post("/v1/chat/s1/read", headers=chat_headers("POST", "/v1/chat/s1/read"))
        chat_send_denied = await client.post("/v1/chat/s1/messages", headers=chat_headers("POST", "/v1/chat/s1/messages"))
        chat_roster_allowed = await client.get("/v1/agents", headers=chat_headers("GET", "/v1/agents"))
        contacts_read_allowed = await client.get("/v1/contacts", headers=contacts_headers("GET", "/v1/contacts"))
        contacts_write_allowed = await client.post("/v1/contacts", headers=contacts_headers("POST", "/v1/contacts"))
        contacts_delete_allowed = await client.delete("/v1/contacts/contact-1", headers=contacts_headers("DELETE", "/v1/contacts/contact-1"))
        contacts_wrong_scope = await client.get("/v1/contacts", headers=send_headers("GET", "/v1/contacts"))
        presence_key, presence_did = _session_keypair()
        presence_grant = (await _mint(client, grant_did_key=presence_did, scopes=["presence.write"])).json()["grant_id"]
        presence_allowed = await client.post(
            "/v1/heartbeat",
            headers=_grant_headers(signing_key=presence_key, did_key=presence_did, grant_id=presence_grant, method="POST", path="/v1/heartbeat"),
        )

    assert inbox_denied.status_code == 403
    assert inbox_denied.json()["detail"] == "outside grant scope"
    assert send_allowed.status_code == 200
    assert roster_allowed.status_code == 200
    assert team_roster_allowed.status_code == 200
    assert team_roster_allowed.json()["grant"]["grant_id"] == send_grant
    assert presence_denied.status_code == 403
    assert presence_denied.json()["detail"] == "outside grant scope"
    assert lease_denied.status_code == 403
    assert lease_denied.json()["detail"] == "outside grant scope"
    assert chat_read_allowed.status_code == 200
    assert mark_read_allowed.status_code == 200
    assert chat_send_denied.status_code == 403
    assert chat_send_denied.json()["detail"] == "outside grant scope"
    assert chat_roster_allowed.status_code == 200
    assert contacts_read_allowed.status_code == 200
    assert contacts_write_allowed.status_code == 200
    assert contacts_delete_allowed.status_code == 200
    assert contacts_wrong_scope.status_code == 403
    assert contacts_wrong_scope.json()["detail"] == "outside grant scope"
    assert presence_allowed.status_code == 200
    assert presence_allowed.json()["grant"]["grant_id"] == presence_grant


@pytest.mark.asyncio
async def test_grant_cannot_mint_or_revoke_grants(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    worker_key, worker_did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        body = json.dumps(
            {"grant_did_key": worker_did, "scopes": ["mail.send"], "ttl_seconds": 600},
            separators=(",", ":"),
        ).encode()
        mint_denied = await client.post(
            "/v1/identity-grants",
            content=body,
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/identity-grants", body=body,
            ),
        )
        revoke_denied = await client.post(
            f"/v1/identity-grants/{grant_id}/revoke",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path=f"/v1/identity-grants/{grant_id}/revoke",
            ),
        )
    assert mint_denied.status_code == 403
    assert mint_denied.json()["detail"] == "grants cannot mint or revoke grants"
    assert revoke_denied.status_code == 403
    assert revoke_denied.json()["detail"] == "grants cannot mint or revoke grants"


@pytest.mark.asyncio
async def test_mint_duplicate_active_grant_did_key_conflicts(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    _, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await _mint(client, grant_did_key=did_key, scopes=["mail.send"])
        duplicate = await _mint(client, grant_did_key=did_key, scopes=["mail.read"])
        assert first.status_code == 200
        assert duplicate.status_code == 409
        revoked = await client.post(f"/v1/identity-grants/{first.json()['grant_id']}/revoke")
        assert revoked.status_code == 200
        reminted = await _mint(client, grant_did_key=did_key, scopes=["mail.read"])
    assert reminted.status_code == 200


@pytest.mark.asyncio
async def test_revoke_is_idempotent_and_audited(aweb_cloud_db):
    app, agent_id = await _fixture(aweb_cloud_db.aweb_db)
    _, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        first = await client.post(f"/v1/identity-grants/{grant_id}/revoke")
        second = await client.post(f"/v1/identity-grants/{grant_id}/revoke")
        listed = await client.get("/v1/identity-grants")
    assert first.status_code == 200
    assert first.json()["status"] == "revoked"
    assert second.status_code == 200
    assert second.json()["status"] == "revoked"
    assert second.json()["revoked_at"] == first.json()["revoked_at"]
    assert [g["status"] for g in listed.json()["grants"]] == ["revoked"]
    audits = await aweb_cloud_db.aweb_db.fetch_all(
        "SELECT alias, resource, details FROM {{tables.audit_log}} WHERE event_type = 'identity_grant.revoke'"
    )
    assert len(audits) == 1
    assert audits[0]["alias"] == "alice"
    assert audits[0]["resource"] == grant_id
    details = json.loads(audits[0]["details"]) if isinstance(audits[0]["details"], str) else audits[0]["details"]
    assert details["subject_agent_id"] == str(agent_id)


@pytest.mark.asyncio
async def test_revoke_by_non_subject_is_not_found(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    bob_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, alias, did_key, status)
        VALUES ($1, $2, 'bob', 'did:key:z6MkSubjectBob', 'active')
        """,
        bob_id, TEAM_ID,
    )
    _, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        app.state.agent_id = str(bob_id)
        app.state.alias = "bob"
        denied = await client.post(f"/v1/identity-grants/{grant_id}/revoke")
        not_listed = await client.get("/v1/identity-grants")
    assert denied.status_code == 404
    assert not_listed.json()["grants"] == []


@pytest.mark.asyncio
async def test_tampered_signed_payload_path_is_rejected(aweb_cloud_db):
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        tampered = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
                payload_overrides={"path": "/v1/messages?forwarded=1"},
            ),
        )
    assert tampered.status_code == 403
    assert tampered.json()["detail"] == "identity grant rejected"


def test_identity_grant_routes_are_registered_on_production_app():
    paths = {route.path for route in create_app().routes}
    assert {"/v1/identity-grants", "/v1/identity-grants/{grant_id}/revoke"} <= paths


@pytest.mark.asyncio
async def test_grant_with_revoked_issuing_certificate_is_rejected(aweb_cloud_db):
    """aweb-abfn: revoking the membership certificate that minted a grant ends
    the delegation, even though the grant row itself is unrevoked and unexpired."""
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        before = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
        assert before.status_code == 200, before.text
        app.state.awid_registry_client.get_team_revocations = AsyncMock(return_value={"cert-1"})
        after = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
    assert after.status_code == 403
    assert after.json()["detail"] == "grant issuing certificate revoked"


@pytest.mark.asyncio
async def test_grant_registry_unavailable_fails_closed(aweb_cloud_db):
    """Registry unavailability must not silently skip the issuing-certificate
    check: same fail-closed posture as the certificate-presenting path."""
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        import httpx as _httpx

        app.state.awid_registry_client.get_team_revocations = AsyncMock(
            side_effect=_httpx.ConnectError("registry down")
        )
        resp = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_grant_with_unregistered_issuing_certificate_rejected_when_required(aweb_cloud_db, monkeypatch):
    """Staged existence requirement (AWEB_REQUIRE_REGISTERED_CERTIFICATES):
    an unregistered issuing certificate is unrevocable, so with the flag on
    the delegation ends with a verdict distinct from revocation."""
    from types import SimpleNamespace

    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    app.state.awid_registry_client.list_team_certificates = AsyncMock(return_value=[])
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        resp = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "grant issuing certificate not registered"

        # A registered issuing certificate keeps the delegation working.
        app.state.awid_registry_client.list_team_certificates = AsyncMock(
            return_value=[SimpleNamespace(certificate_id="cert-1")]
        )
        ok = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
    assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
async def test_grant_flag_off_makes_no_existence_read(aweb_cloud_db, monkeypatch):
    """Default OFF: byte-identical to today, zero registry existence reads."""
    monkeypatch.delenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", raising=False)
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    app.state.awid_registry_client.list_team_certificates = AsyncMock(return_value=[])
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        resp = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
    assert resp.status_code == 200, resp.text
    app.state.awid_registry_client.list_team_certificates.assert_not_awaited()


@pytest.mark.asyncio
async def test_legacy_grant_without_issuing_certificate_still_works(aweb_cloud_db):
    """Grants minted before issued_by_certificate_id was recorded cannot be
    checked; they keep working, bounded by their own expiry."""
    app, _ = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["mail.send"])).json()["grant_id"]
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.identity_session_grants}} SET issued_by_certificate_id = NULL WHERE grant_id = $1::UUID",
            grant_id,
        )
        app.state.awid_registry_client.get_team_revocations = AsyncMock(return_value={"cert-1"})
        resp = await client.post(
            "/v1/messages",
            headers=_grant_headers(
                signing_key=signing_key, did_key=did_key, grant_id=grant_id,
                method="POST", path="/v1/messages",
            ),
        )
    assert resp.status_code == 200, resp.text


def _build_real_messaging_app(aweb_db) -> FastAPI:
    app = FastAPI()
    app.include_router(identity_grants_router)
    app.include_router(messages_router)
    app.include_router(chat_router)
    app.include_router(contacts_router)
    app.include_router(events_router)
    app.include_router(agents_router)
    app.include_router(status_router)
    app.include_router(claims_router)
    app.include_router(reservations_router)
    app.include_router(tasks_router)
    app.include_router(workspaces_router)
    app.include_router(roles_router)
    app.include_router(instructions_router)
    app.include_router(repos_router)
    app.dependency_overrides[get_team_identity] = _identity
    app.state.db = _DbShim(aweb_db)
    app.state.public_origin = "http://test"
    app.state.redis = None
    app.state.rate_limiter = None
    registry = AsyncMock()
    registry.get_team_revocations = AsyncMock(return_value=set())
    app.state.awid_registry_client = registry

    @app.middleware("http")
    async def cache_body_middleware(request, call_next):
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = hashlib.sha256(body).hexdigest()
        request._receive = _cached_body_receive(body)
        return await call_next(request)

    return app


async def _real_messaging_fixture(aweb_db):
    app, alice_id = await _fixture(aweb_db)
    app = _build_real_messaging_app(aweb_db)
    app.state.agent_id = str(alice_id)
    app.state.alias = "alice"
    workspace_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role,
            workspace_type, last_seen_at
        )
        VALUES ($1, $2, $3, 'alice', 'Alice', 'developer', 'manual', $4)
        """,
        workspace_id,
        TEAM_ID,
        alice_id,
        datetime.now(timezone.utc) - timedelta(hours=1),
    )
    app.state.alice_workspace_id = str(workspace_id)
    bob_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, alias, did_key, did_aw, address, status, identity_scope, inbound_mode)
        VALUES ($1, $2, 'bob', 'did:key:z6MkSubjectBob', 'did:aw:bob', 'acme.com/bob', 'active', 'global', 'open')
        """,
        bob_id, TEAM_ID,
    )
    return app, alice_id, bob_id


@pytest.mark.asyncio
async def test_grant_agents_real_handlers_scope_and_liveness(aweb_cloud_db, monkeypatch):
    app, alice_id, _ = await _real_messaging_fixture(aweb_cloud_db.aweb_db)

    root_presence_calls = []

    async def _presence(_redis, **kwargs):
        root_presence_calls.append(kwargs)
        return "2026-09-24T00:00:00+00:00"

    monkeypatch.setattr(agents_routes, "update_agent_presence", _presence)
    old_last_seen = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id = $1::UUID",
        app.state.alice_workspace_id,
    )
    signing_key, grant_did = _session_keypair()
    status_key, status_did = _session_keypair()
    presence_key, presence_did = _session_keypair()
    other_presence_key, other_presence_did = _session_keypair()
    revoked_key, revoked_did = _session_keypair()
    expired_key, expired_did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        old_scope_grant = (await _mint(
            client,
            grant_did_key=grant_did,
            scopes=["mail.read", "mail.send", "chat.read", "chat.send"],
        )).json()["grant_id"]
        status_grant = (await _mint(client, grant_did_key=status_did, scopes=["coord.read"])).json()["grant_id"]
        roster = await client.get(
            "/v1/agents",
            headers=_grant_headers(signing_key=signing_key, did_key=grant_did, grant_id=old_scope_grant, method="GET", path="/v1/agents"),
        )
        heartbeat_denied = await client.post(
            "/v1/agents/heartbeat",
            headers=_grant_headers(signing_key=signing_key, did_key=grant_did, grant_id=old_scope_grant, method="POST", path="/v1/agents/heartbeat"),
        )

        presence_grant = (await _mint(client, grant_did_key=presence_did, scopes=["presence.write"])).json()["grant_id"]
        heartbeat = await client.post(
            "/v1/agents/heartbeat",
            headers=_grant_headers(signing_key=presence_key, did_key=presence_did, grant_id=presence_grant, method="POST", path="/v1/agents/heartbeat"),
        )
        other_presence_grant = (await _mint(client, grant_did_key=other_presence_did, scopes=["presence.write"])).json()["grant_id"]
        other_heartbeat = await client.post(
            "/v1/agents/heartbeat",
            headers=_grant_headers(signing_key=other_presence_key, did_key=other_presence_did, grant_id=other_presence_grant, method="POST", path="/v1/agents/heartbeat"),
        )
        grant_online_roster = await client.get(
            "/v1/agents",
            headers=_grant_headers(signing_key=signing_key, did_key=grant_did, grant_id=old_scope_grant, method="GET", path="/v1/agents"),
        )
        status_wrong_scope = await client.get(
            "/v1/status",
            headers=_grant_headers(signing_key=signing_key, did_key=grant_did, grant_id=old_scope_grant, method="GET", path="/v1/status"),
        )
        grant_online_status = await client.get(
            "/v1/status",
            headers=_grant_headers(signing_key=status_key, did_key=status_did, grant_id=status_grant, method="GET", path="/v1/status"),
        )
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.identity_session_grants}} SET revoked_at = NOW() WHERE grant_id = $1::UUID",
            presence_grant,
        )
        one_grant_roster = await client.get(
            "/v1/agents",
            headers=_grant_headers(signing_key=signing_key, did_key=grant_did, grant_id=old_scope_grant, method="GET", path="/v1/agents"),
        )
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.identity_session_grants}} SET revoked_at = NOW() WHERE grant_id = $1::UUID",
            other_presence_grant,
        )
        grant_offline_roster = await client.get(
            "/v1/agents",
            headers=_grant_headers(signing_key=signing_key, did_key=grant_did, grant_id=old_scope_grant, method="GET", path="/v1/agents"),
        )
        stale_key, stale_did = _session_keypair()
        stale_grant = (await _mint(client, grant_did_key=stale_did, scopes=["presence.write"])).json()["grant_id"]
        stale_heartbeat = await client.post(
            "/v1/agents/heartbeat",
            headers=_grant_headers(signing_key=stale_key, did_key=stale_did, grant_id=stale_grant, method="POST", path="/v1/agents/heartbeat"),
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.identity_grant_liveness}}
            SET last_seen_at = NOW() - INTERVAL '31 minutes'
            WHERE grant_id = $1::UUID
            """,
            stale_grant,
        )
        stale_roster = await client.get(
            "/v1/agents",
            headers=_grant_headers(signing_key=signing_key, did_key=grant_did, grant_id=old_scope_grant, method="GET", path="/v1/agents"),
        )
        stale_exists_after_read = await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT EXISTS (SELECT 1 FROM {{tables.identity_grant_liveness}} WHERE grant_id = $1::UUID)",
            stale_grant,
        )
        cleanup_key, cleanup_did = _session_keypair()
        cleanup_grant = (await _mint(client, grant_did_key=cleanup_did, scopes=["presence.write"])).json()["grant_id"]
        cleanup_heartbeat = await client.post(
            "/v1/agents/heartbeat",
            headers=_grant_headers(signing_key=cleanup_key, did_key=cleanup_did, grant_id=cleanup_grant, method="POST", path="/v1/agents/heartbeat"),
        )
        revoked_grant = (await _mint(client, grant_did_key=revoked_did, scopes=["presence.write"])).json()["grant_id"]
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.identity_session_grants}} SET revoked_at = NOW() WHERE grant_id = $1::UUID",
            revoked_grant,
        )
        revoked = await client.post(
            "/v1/agents/heartbeat",
            headers=_grant_headers(signing_key=revoked_key, did_key=revoked_did, grant_id=revoked_grant, method="POST", path="/v1/agents/heartbeat"),
        )

        expired_grant = (await _mint(client, grant_did_key=expired_did, scopes=["presence.write"])).json()["grant_id"]
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.identity_session_grants}}
            SET issued_at = NOW() - INTERVAL '2 seconds', expires_at = NOW() - INTERVAL '1 second'
            WHERE grant_id = $1::UUID
            """,
            expired_grant,
        )
        expired = await client.post(
            "/v1/agents/heartbeat",
            headers=_grant_headers(signing_key=expired_key, did_key=expired_did, grant_id=expired_grant, method="POST", path="/v1/agents/heartbeat"),
        )

    assert roster.status_code == 200, roster.text
    roster_body = roster.json()
    assert roster_body["team_id"] == TEAM_ID
    assert any(agent["agent_id"] == str(alice_id) for agent in roster_body["agents"])
    assert heartbeat_denied.status_code == 403
    assert heartbeat_denied.json()["detail"] == "outside grant scope"
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["agent_id"] == str(alice_id)
    assert other_heartbeat.status_code == 200, other_heartbeat.text
    new_last_seen = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id = $1::UUID",
        app.state.alice_workspace_id,
    )
    assert new_last_seen == old_last_seen
    liveness_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT grant_id::text AS grant_id, subject_agent_id::text AS subject_agent_id,
               workspace_id::text AS workspace_id, session_did_key, last_seen_at, expires_at
        FROM {{tables.identity_grant_liveness}}
        ORDER BY grant_id
        """
    )
    assert root_presence_calls == []
    initial_liveness_rows = [row for row in liveness_rows if row["grant_id"] in {presence_grant, other_presence_grant}]
    assert {row["grant_id"] for row in initial_liveness_rows} == {presence_grant, other_presence_grant}
    assert {row["subject_agent_id"] for row in initial_liveness_rows} == {str(alice_id)}
    assert {row["workspace_id"] for row in initial_liveness_rows} == {app.state.alice_workspace_id}
    assert {row["session_did_key"] for row in initial_liveness_rows} == {presence_did, other_presence_did}
    assert all(row["expires_at"] >= row["last_seen_at"] for row in initial_liveness_rows)
    online_agents = {agent["agent_id"]: agent for agent in grant_online_roster.json()["agents"]}
    assert online_agents[str(alice_id)]["online"] is True
    assert status_wrong_scope.status_code == 403
    assert status_wrong_scope.json()["detail"] == "outside grant scope"
    assert grant_online_status.status_code == 200, grant_online_status.text
    status_agents = {agent["workspace_id"]: agent for agent in grant_online_status.json()["agents"]}
    assert status_agents[app.state.alice_workspace_id]["status"] == "active"
    one_grant_agents = {agent["agent_id"]: agent for agent in one_grant_roster.json()["agents"]}
    assert one_grant_agents[str(alice_id)]["online"] is True
    offline_agents = {agent["agent_id"]: agent for agent in grant_offline_roster.json()["agents"]}
    assert offline_agents[str(alice_id)]["online"] is False
    assert stale_heartbeat.status_code == 200, stale_heartbeat.text
    stale_agents = {agent["agent_id"]: agent for agent in stale_roster.json()["agents"]}
    assert stale_agents[str(alice_id)]["online"] is False
    assert stale_exists_after_read is True
    assert cleanup_heartbeat.status_code == 200, cleanup_heartbeat.text
    assert not await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT EXISTS (SELECT 1 FROM {{tables.identity_grant_liveness}} WHERE grant_id = $1::UUID)",
        stale_grant,
    )
    assert revoked.status_code == 403
    assert revoked.json()["detail"] == "grant revoked"
    assert expired.status_code == 403
    assert expired.json()["detail"] == "grant expired"


@pytest.mark.asyncio
async def test_grant_mail_send_real_handler_attributes_subject_without_session_signature(aweb_cloud_db):
    app, alice_id, bob_id = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    signing_key, grant_did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=grant_did, scopes=["mail.send", "mail.read"])).json()["grant_id"]
        body = json.dumps({"to_alias": "bob", "body": "hello"}, separators=(",", ":")).encode()
        sent = await client.post(
            "/v1/messages",
            content=body,
            headers=_grant_headers(
                signing_key=signing_key, did_key=grant_did, grant_id=grant_id,
                method="POST", path="/v1/messages", body=body,
            ),
        )
    assert sent.status_code == 200, sent.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_agent_id, from_did, to_agent_id, signature, signed_payload FROM {{tables.messages}} WHERE body = 'hello'"
    )
    assert str(row["from_agent_id"]) == str(alice_id)
    assert row["from_did"] == "did:aw:alice"
    assert str(row["to_agent_id"]) == str(bob_id)
    assert row["signature"] is None
    assert row["signed_payload"] is None

    async def _bob_auth():
        return MessagingAuth(
            did_key="did:key:z6MkSubjectBob", did_aw="did:aw:bob", address="acme.com/bob",
            team_id=TEAM_ID, alias="bob", agent_id=str(bob_id), identity_scope="global",
            certificate_id="cert-bob", verified_team_id=TEAM_ID,
        )

    app.dependency_overrides[get_messaging_auth] = _bob_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        inbox = await client.get("/v1/messages/inbox")
    assert inbox.status_code == 200, inbox.text
    message = inbox.json()["messages"][0]
    assert message["from_did"] == "did:aw:alice"
    assert message["verification_status"] == "unverified"


@pytest.mark.asyncio
async def test_grant_chat_send_real_handler_attributes_subject_without_session_signature(aweb_cloud_db):
    app, alice_id, bob_id = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    signing_key, grant_did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=grant_did, scopes=["chat.send", "chat.read"])).json()["grant_id"]
        body = json.dumps({"to_aliases": ["bob"], "message": "hello chat"}, separators=(",", ":")).encode()
        sent = await client.post(
            "/v1/chat/sessions",
            content=body,
            headers=_grant_headers(
                signing_key=signing_key, did_key=grant_did, grant_id=grant_id,
                method="POST", path="/v1/chat/sessions", body=body,
            ),
        )
    assert sent.status_code == 200, sent.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_agent_id, from_did, signature, signed_payload FROM {{tables.chat_messages}} WHERE body = 'hello chat'"
    )
    assert str(row["from_agent_id"]) == str(alice_id)
    assert row["from_did"] == "did:aw:alice"
    assert row["signature"] is None
    assert row["signed_payload"] is None
    participant = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT agent_id FROM {{tables.chat_participants}} WHERE alias = 'bob'"
    )
    assert str(participant["agent_id"]) == str(bob_id)


@pytest.mark.asyncio
async def test_grant_real_send_handlers_reject_session_did_as_root_signed_sender(aweb_cloud_db):
    app, _, _ = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    signing_key, grant_did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=grant_did, scopes=["mail.send", "chat.send"])).json()["grant_id"]
        mail_body = json.dumps(
            {"to_alias": "bob", "body": "bad", "from_did": grant_did, "signature": "not-a-root-signature"},
            separators=(",", ":"),
        ).encode()
        mail = await client.post(
            "/v1/messages",
            content=mail_body,
            headers=_grant_headers(
                signing_key=signing_key, did_key=grant_did, grant_id=grant_id,
                method="POST", path="/v1/messages", body=mail_body,
            ),
        )
        chat_body = json.dumps(
            {"to_aliases": ["bob"], "message": "bad", "from_did": grant_did, "signature": "not-a-root-signature"},
            separators=(",", ":"),
        ).encode()
        chat = await client.post(
            "/v1/chat/sessions",
            content=chat_body,
            headers=_grant_headers(
                signing_key=signing_key, did_key=grant_did, grant_id=grant_id,
                method="POST", path="/v1/chat/sessions", body=chat_body,
            ),
        )
    assert mail.status_code == 422
    assert mail.json()["detail"] == "from_did must match the authenticated sender"
    assert chat.status_code == 422
    assert chat.json()["detail"] == "from_did must match the authenticated sender"


def _grant_identity(scopes: list[str]) -> TeamIdentity:
    return TeamIdentity(
        team_id=TEAM_ID,
        alias="alice",
        did_key=SUBJECT_DID_KEY,
        did_aw="did:aw:alice",
        address="acme.com/alice",
        agent_id="agent-1",
        identity_scope="global",
        certificate_id=None,
        grant=GrantContext(
            grant_id="11111111-1111-4111-8111-111111111111",
            session_did_key="did:key:zGrant",
            issuing_certificate_id=None,
            scopes=tuple(scopes),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ),
    )


def test_grant_stream_event_filters_require_underlying_data_scope():
    events_only = _grant_identity(["events.read"])
    assert agent_event_allowed(events_only, {"type": "control_pause"}) is True
    assert agent_event_allowed(events_only, {"type": "grant_revoked"}) is True
    assert agent_event_allowed(events_only, {"type": "actionable_mail"}) is False
    assert agent_event_allowed(events_only, {"type": "actionable_chat"}) is False
    assert agent_event_allowed(events_only, {"type": "app_event"}) is False

    assert agent_event_allowed(_grant_identity(["events.read", "mail.read"]), {"type": "actionable_mail"}) is True
    assert agent_event_allowed(_grant_identity(["events.read", "chat.read"]), {"type": "actionable_chat"}) is True
    assert agent_event_allowed(_grant_identity(["events.read", "coord.read"]), {"type": "app_event"}) is True


def test_status_stream_grant_categories_are_scope_limited():
    assert allowed_status_categories(_grant_identity(["events.read"])) == set()
    assert allowed_status_categories(_grant_identity(["events.read", "mail.read"])) == {"message"}
    assert allowed_status_categories(_grant_identity(["events.read", "chat.read"])) == {"chat"}
    assert allowed_status_categories(_grant_identity(["events.read", "coord.read"])) == {"reservation", "task"}


@pytest.mark.asyncio
async def test_grant_terminal_reason_distinguishes_normal_deadline_from_actual_expiry(aweb_cloud_db):
    app, agent_id = await _fixture(aweb_cloud_db.aweb_db)
    signing_key, did_key = _session_keypair()
    del signing_key
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did_key, scopes=["events.read"], ttl_seconds=600)).json()["grant_id"]
    expires_at = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT expires_at FROM {{tables.identity_session_grants}} WHERE grant_id = $1::UUID",
        grant_id,
    )
    identity = TeamIdentity(
        team_id=TEAM_ID,
        alias="alice",
        did_key=SUBJECT_DID_KEY,
        did_aw="did:aw:alice",
        address="acme.com/alice",
        agent_id=str(agent_id),
        identity_scope="global",
        certificate_id=None,
        grant=GrantContext(
            grant_id=grant_id,
            session_did_key=did_key,
            issuing_certificate_id="cert-1",
            scopes=("events.read",),
            expires_at=expires_at,
        ),
    )
    # A caller-supplied stream deadline may be sooner than grant expiry; that
    # must close normally, not as grant_expired.
    assert await grant_terminal_reason(type("Req", (), {"app": app})(), _DbShim(aweb_cloud_db.aweb_db), identity) is None

    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.identity_session_grants}}
        SET issued_at = NOW() - INTERVAL '2 seconds', expires_at = NOW() - INTERVAL '1 second'
        WHERE grant_id = $1::UUID
        """,
        grant_id,
    )
    expired = await grant_terminal_reason(type("Req", (), {"app": app})(), _DbShim(aweb_cloud_db.aweb_db), identity)
    assert expired == "grant_expired"


def _route_grant_scope_table(app: FastAPI) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []

    def walk(dependant):
        for dep in dependant.dependencies:
            scope = getattr(dep.call, "_aweb_grant_scope", None)
            if scope is not None:
                yield scope
            yield from walk(dep)

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for scope in walk(route.dependant):
            for method in sorted(route.methods or []):
                rows.append((method, route.path, scope))
    return sorted(set(rows))


def _direct_team_identity_calls() -> list[tuple[str, str, int]]:
    paths = [
        REPO_ROOT / "server/src/aweb/coordination/routes/tasks.py",
        REPO_ROOT / "server/src/aweb/coordination/routes/workspaces.py",
        REPO_ROOT / "server/src/aweb/coordination/routes/team_roles.py",
        REPO_ROOT / "server/src/aweb/coordination/routes/team_instructions.py",
        REPO_ROOT / "server/src/aweb/coordination/routes/repos.py",
        REPO_ROOT / "server/src/aweb/routes/apps.py",
        REPO_ROOT / "server/src/aweb/routes/connect.py",
        REPO_ROOT / "server/src/aweb/routes/events.py",
    ]
    rows: list[tuple[str, str, int]] = []
    for path in paths:
        tree = ast.parse(path.read_text())
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id != "get_team_identity":
                continue
            parent = parents.get(node)
            while parent is not None and not isinstance(parent, (ast.AsyncFunctionDef, ast.FunctionDef)):
                parent = parents.get(parent)
            rows.append((str(path.relative_to(REPO_ROOT)), getattr(parent, "name", "<module>"), node.lineno))
    return sorted(rows)


def test_route_grant_scope_declarations_are_known_and_reviewable():
    app = create_app()
    table = _route_grant_scope_table(app)
    known = set(GRANT_SCOPES) | {GRANT_SCOPE_ANY}
    expected = [
        ("DELETE", "/v1/tasks/{ref}/deps/{dep_ref}", "coord.write"),
        ("GET", "/v1/agents", GRANT_SCOPE_ANY),
        ("GET", "/v1/claims", "coord.read"),
        ("GET", "/v1/events/stream", "events.read"),
        ("GET", "/v1/instructions/active", "coord.read"),
        ("GET", "/v1/instructions/history", "coord.read"),
        ("GET", "/v1/instructions/{team_instructions_id}", "coord.read"),
        ("GET", "/v1/repos", "coord.read"),
        ("GET", "/v1/reservations", "coord.read"),
        ("GET", "/v1/roles/active", "coord.read"),
        ("GET", "/v1/roles/history", "coord.read"),
        ("GET", "/v1/roles/{team_roles_id}", "coord.read"),
        ("GET", "/v1/status", "coord.read"),
        ("GET", "/v1/status/stream", "events.read"),
        ("GET", "/v1/tasks", "coord.read"),
        ("GET", "/v1/tasks/active", "coord.read"),
        ("GET", "/v1/tasks/blocked", "coord.read"),
        ("GET", "/v1/tasks/ready", "coord.read"),
        ("GET", "/v1/tasks/{ref}", "coord.read"),
        ("GET", "/v1/tasks/{ref}/comments", "coord.read"),
        ("GET", "/v1/workspaces", "coord.read"),
        ("GET", "/v1/workspaces/online", "coord.read"),
        ("GET", "/v1/workspaces/team", "coord.read"),
        ("PATCH", "/v1/tasks/{ref}", "coord.write"),
        ("PATCH", "/v1/workspaces/{workspace_id}", "presence.write"),
        ("POST", "/v1/agents/heartbeat", "presence.write"),
        ("POST", "/v1/repos/lookup", "coord.read"),
        ("POST", "/v1/reservations", "coord.write"),
        ("POST", "/v1/reservations/release", "coord.write"),
        ("POST", "/v1/reservations/renew", "coord.write"),
        ("POST", "/v1/tasks", "coord.write"),
        ("POST", "/v1/tasks/{ref}/comments", "coord.write"),
        ("POST", "/v1/tasks/{ref}/deps", "coord.write"),
        ("POST", "/v1/workspaces/heartbeat", "presence.write"),
    ]
    assert all(scope in known for _, _, scope in table)
    assert table == expected


def test_direct_team_identity_calls_are_reviewed_root_only_sites():
    assert _direct_team_identity_calls() == [
        ("server/src/aweb/routes/apps.py", "_authorized_team_id", 79),
        ("server/src/aweb/routes/apps.py", "install_app_route", 111),
        ("server/src/aweb/routes/connect.py", "get_team_info", 483),
        ("server/src/aweb/routes/events.py", "_subscription_read_identity", 140),
        ("server/src/aweb/routes/events.py", "delete_app_event_subscription_route", 593),
        ("server/src/aweb/routes/events.py", "upsert_app_event_subscription_route", 558),
    ]

@pytest.mark.asyncio
async def test_events_stream_filters_mail_by_underlying_grant_scope(aweb_cloud_db):
    app, _, _ = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    events_key, events_did = _session_keypair()
    mail_events_key, mail_events_did = _session_keypair()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, from_did, to_did, from_alias, to_alias,
            subject, body, priority, created_at
        )
        VALUES ($1, 'did:aw:bob', 'did:aw:alice', 'bob', 'alice',
                'grant stream subject', 'wake', 'normal', NOW())
        """,
        uuid4(),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", timeout=5.0) as client:
        events_grant = (await _mint(client, grant_did_key=events_did, scopes=["events.read"])).json()["grant_id"]
        mail_events_grant = (await _mint(client, grant_did_key=mail_events_did, scopes=["events.read", "mail.read"])).json()["grant_id"]

    stream_app = FastAPI()
    stream_app.include_router(events_router)
    stream_app.state.db = _DbShim(aweb_cloud_db.aweb_db)
    stream_app.state.public_origin = "http://test"
    stream_app.state.redis = None
    stream_registry = AsyncMock()
    stream_registry.get_team_revocations = AsyncMock(return_value=set())
    stream_app.state.awid_registry_client = stream_registry

    async with AsyncClient(transport=ASGITransport(app=stream_app), base_url="http://test", timeout=5.0) as stream_client:
        deadline = (datetime.now(timezone.utc) + timedelta(milliseconds=100)).isoformat().replace("+00:00", "Z")
        path = f"/v1/events/stream?deadline={deadline}"
        events_only = await stream_client.get(
            path,
            headers=_grant_headers(signing_key=events_key, did_key=events_did, grant_id=events_grant, method="GET", path=path),
        )
        mail_allowed = await stream_client.get(
            path,
            headers=_grant_headers(signing_key=mail_events_key, did_key=mail_events_did, grant_id=mail_events_grant, method="GET", path=path),
        )

    assert events_only.status_code == 200, events_only.text
    assert "actionable_mail" not in events_only.text
    assert "grant stream subject" not in events_only.text
    assert mail_allowed.status_code == 200, mail_allowed.text
    assert "actionable_mail" in mail_allowed.text
    assert "grant stream subject" in mail_allowed.text


def _stream_request(app: FastAPI, path: str = "/v1/events/stream") -> Request:
    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [],
            "query_string": b"",
            "server": ("test", 80),
            "scheme": "http",
            "client": ("test", 1234),
            "app": app,
        },
        _receive,
    )


async def _grant_identity_from_db(aweb_db, *, grant_id: str, did_key: str, scopes: tuple[str, ...]) -> TeamIdentity:
    expires_at = await aweb_db.fetch_value(
        "SELECT expires_at FROM {{tables.identity_session_grants}} WHERE grant_id = $1::UUID",
        grant_id,
    )
    agent_id = await aweb_db.fetch_value(
        "SELECT agent_id FROM {{tables.agents}} WHERE alias = 'alice' AND team_id = $1",
        TEAM_ID,
    )
    return TeamIdentity(
        team_id=TEAM_ID,
        alias="alice",
        did_key=SUBJECT_DID_KEY,
        did_aw="did:aw:alice",
        address="acme.com/alice",
        agent_id=str(agent_id),
        identity_scope="global",
        certificate_id=None,
        grant=GrantContext(
            grant_id=grant_id,
            session_did_key=did_key,
            issuing_certificate_id="cert-1",
            scopes=scopes,
            expires_at=expires_at,
        ),
    )


def _messaging_auth_from_identity(identity: TeamIdentity) -> MessagingAuth:
    assert identity.grant is not None
    return MessagingAuth(
        did_key=identity.did_key,
        did_aw=identity.did_aw,
        address=identity.address,
        team_id=identity.team_id,
        alias=identity.alias,
        agent_id=identity.agent_id,
        identity_scope=identity.identity_scope,
        certificate_id=None,
        verified_team_id=identity.team_id,
        grant=identity.grant,
    )


async def _next_text(aiter) -> str:
    item = await anext(aiter)
    if isinstance(item, bytes):
        return item.decode()
    return str(item)


@pytest.mark.asyncio
async def test_events_stream_real_handler_emits_grant_revoked_terminal(aweb_cloud_db):
    app, _, _ = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    key, did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did, scopes=["events.read"])).json()["grant_id"]
    identity = await _grant_identity_from_db(aweb_cloud_db.aweb_db, grant_id=grant_id, did_key=did, scopes=("events.read",))
    del key
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    response = await events_stream_route(
        _stream_request(app),
        deadline=deadline,
        db=_DbShim(aweb_cloud_db.aweb_db),
        redis=None,
        identity=identity,
    )
    stream = response.body_iterator
    assert "keepalive" in await _next_text(stream)
    assert "connected" in await _next_text(stream)
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.identity_session_grants}} SET revoked_at = NOW() WHERE grant_id = $1::UUID",
        grant_id,
    )
    terminal = await _next_text(stream)
    assert "event: grant_revoked" in terminal


@pytest.mark.asyncio
async def test_events_stream_real_handler_short_client_deadline_has_no_grant_terminal(aweb_cloud_db):
    app, _, _ = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    _, did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did, scopes=["events.read"], ttl_seconds=600)).json()["grant_id"]
    identity = await _grant_identity_from_db(aweb_cloud_db.aweb_db, grant_id=grant_id, did_key=did, scopes=("events.read",))
    deadline = (datetime.now(timezone.utc) + timedelta(milliseconds=100)).isoformat().replace("+00:00", "Z")
    response = await events_stream_route(
        _stream_request(app),
        deadline=deadline,
        db=_DbShim(aweb_cloud_db.aweb_db),
        redis=None,
        identity=identity,
    )
    body = ""
    async for chunk in response.body_iterator:
        body += chunk.decode() if isinstance(chunk, bytes) else str(chunk)
    assert "grant_expired" not in body
    assert "grant_revoked" not in body


@pytest.mark.asyncio
async def test_chat_stream_real_handler_revoked_and_expired_grants_emit_terminal(aweb_cloud_db):
    app, _, _ = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    key, did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did, scopes=["chat.send", "chat.read"])).json()["grant_id"]
        body = json.dumps({"to_aliases": ["bob"], "message": "hello stream"}, separators=(",", ":")).encode()
        sent = await client.post(
            "/v1/chat/sessions",
            content=body,
            headers=_grant_headers(signing_key=key, did_key=did, grant_id=grant_id, method="POST", path="/v1/chat/sessions", body=body),
        )
        assert sent.status_code == 200, sent.text
        session_id = sent.json()["session_id"]

    identity = await _grant_identity_from_db(aweb_cloud_db.aweb_db, grant_id=grant_id, did_key=did, scopes=("chat.send", "chat.read"))
    auth = _messaging_auth_from_identity(identity)
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    response = await chat_stream_route(
        _stream_request(app, f"/v1/chat/sessions/{session_id}/stream"),
        session_id=session_id,
        deadline=deadline,
        after=None,
        db=_DbShim(aweb_cloud_db.aweb_db),
        redis=None,
        auth=auth,
    )
    stream = response.body_iterator
    assert "keepalive" in await _next_text(stream)
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.identity_session_grants}} SET revoked_at = NOW() WHERE grant_id = $1::UUID",
        grant_id,
    )
    assert "event: grant_revoked" in await _next_text(stream)

    expire_key, expire_did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        expire_grant = (await _mint(client, grant_did_key=expire_did, scopes=["chat.read"])).json()["grant_id"]
    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.identity_session_grants}}
        SET expires_at = NOW() + INTERVAL '100 milliseconds'
        WHERE grant_id = $1::UUID
        """,
        expire_grant,
    )
    expire_identity = await _grant_identity_from_db(aweb_cloud_db.aweb_db, grant_id=expire_grant, did_key=expire_did, scopes=("chat.read",))
    expire_response = await chat_stream_route(
        _stream_request(app, f"/v1/chat/sessions/{session_id}/stream"),
        session_id=session_id,
        deadline=(datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat().replace("+00:00", "Z"),
        after=None,
        db=_DbShim(aweb_cloud_db.aweb_db),
        redis=None,
        auth=_messaging_auth_from_identity(expire_identity),
    )
    expire_body = ""
    async for chunk in expire_response.body_iterator:
        expire_body += chunk.decode() if isinstance(chunk, bytes) else str(chunk)
    assert "event: grant_expired" in expire_body
    del expire_key


class _OneMessagePubSub:
    def __init__(self, payload: dict):
        self.payload = payload
        self.sent = False

    async def subscribe(self, *_channels):
        return None

    async def unsubscribe(self, *_channels):
        return None

    async def aclose(self):
        return None

    async def ping(self):
        return None

    async def get_message(self, *, ignore_subscribe_messages=True, timeout=1.0):
        if not self.sent:
            self.sent = True
            return {"type": "message", "data": json.dumps(self.payload)}
        return None


class _OneMessageRedis:
    def __init__(self, payload: dict):
        self.payload = payload

    def pubsub(self):
        return _OneMessagePubSub(self.payload)


@pytest.mark.asyncio
async def test_status_stream_real_handler_drops_coord_categories_without_coord_scope(aweb_cloud_db):
    app, _, _ = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    _, did = _session_keypair()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        grant_id = (await _mint(client, grant_did_key=did, scopes=["events.read"])).json()["grant_id"]
    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.identity_session_grants}}
        SET expires_at = NOW() + INTERVAL '100 milliseconds'
        WHERE grant_id = $1::UUID
        """,
        grant_id,
    )
    identity = await _grant_identity_from_db(aweb_cloud_db.aweb_db, grant_id=grant_id, did_key=did, scopes=("events.read",))
    response = await status_stream_route(
        _stream_request(app, "/v1/status/stream"),
        workspace_id=app.state.alice_workspace_id,
        repo=None,
        human_name=None,
        limit=200,
        event_types="task,reservation",
        redis=_OneMessageRedis({"type": "task.status_changed", "workspace_id": app.state.alice_workspace_id, "task_ref": "aweb-x"}),
        db_infra=_DbShim(aweb_cloud_db.aweb_db),
        identity=identity,
    )
    body = ""
    async for chunk in response.body_iterator:
        body += chunk.decode() if isinstance(chunk, bytes) else str(chunk)
    assert "task.status_changed" not in body
    assert "aweb-x" not in body

@pytest.mark.asyncio
async def test_grant_real_coord_and_contacts_routes(aweb_cloud_db):
    app, alice_id, bob_id = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    read_key, read_did = _session_keypair()
    write_key, write_did = _session_keypair()
    contacts_key, contacts_did = _session_keypair()
    mail_key, mail_did = _session_keypair()
    other_workspace = uuid4()
    other_agent = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ('other:acme.com', 'acme.com', 'other', 'did:key:zOtherTeam')"
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, alias, did_key, status, identity_scope)
        VALUES ($1, 'other:acme.com', 'other', 'did:key:zOtherAgent', 'active', 'global')
        """,
        other_agent,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (workspace_id, team_id, agent_id, alias, human_name, workspace_type)
        VALUES ($1, 'other:acme.com', $2, 'other', 'Other', 'manual')
        """,
        other_workspace,
        other_agent,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}} (team_id, workspace_id, alias, human_name, task_ref, claimed_at)
        VALUES ($1, $2, 'alice', 'Alice', 'aweb-abjf', NOW()),
               ('other:acme.com', $3, 'other', 'Other', 'other-task', NOW())
        """,
        TEAM_ID,
        app.state.alice_workspace_id,
        other_workspace,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.reservations}} (team_id, resource_key, holder_alias, holder_agent_id, acquired_at, expires_at, metadata_json)
        VALUES ('other:acme.com', 'other-resource', 'other', $1, NOW(), NOW() + INTERVAL '1 hour', '{}'::jsonb),
               ($2, 'bob-resource', 'bob', $3, NOW(), NOW() + INTERVAL '1 hour', '{}'::jsonb)
        """,
        other_agent,
        TEAM_ID,
        bob_id,
    )
    contact_id = await aweb_cloud_db.aweb_db.fetch_value(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label, status)
        VALUES ('did:aw:alice', 'acme.com/bob', 'Bob', 'active')
        RETURNING contact_id::text
        """
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        coord_read = (await _mint(client, grant_did_key=read_did, scopes=["coord.read"])).json()["grant_id"]
        coord_write = (await _mint(client, grant_did_key=write_did, scopes=["coord.write", "coord.read"])).json()["grant_id"]
        contacts_grant = (await _mint(client, grant_did_key=contacts_did, scopes=["contacts.read", "contacts.write"])).json()["grant_id"]
        mail_grant = (await _mint(client, grant_did_key=mail_did, scopes=["mail.read"])).json()["grant_id"]

        def h(key, did, grant_id, method, path, body=b""):
            return _grant_headers(signing_key=key, did_key=did, grant_id=grant_id, method=method, path=path, body=body)

        claims = await client.get("/v1/claims", headers=h(read_key, read_did, coord_read, "GET", "/v1/claims"))
        claims_denied = await client.get("/v1/claims", headers=h(mail_key, mail_did, mail_grant, "GET", "/v1/claims"))
        reservations = await client.get("/v1/reservations", headers=h(read_key, read_did, coord_read, "GET", "/v1/reservations"))
        reservations_denied = await client.get("/v1/reservations", headers=h(mail_key, mail_did, mail_grant, "GET", "/v1/reservations"))
        acquire_body = json.dumps({"resource_key": "alice-resource", "ttl_seconds": 120}, separators=(",", ":")).encode()
        acquired = await client.post(
            "/v1/reservations",
            content=acquire_body,
            headers=h(write_key, write_did, coord_write, "POST", "/v1/reservations", acquire_body),
        )
        renew_body = json.dumps({"resource_key": "alice-resource", "ttl_seconds": 180}, separators=(",", ":")).encode()
        renewed = await client.post(
            "/v1/reservations/renew",
            content=renew_body,
            headers=h(write_key, write_did, coord_write, "POST", "/v1/reservations/renew", renew_body),
        )
        release_bob_body = json.dumps({"resource_key": "bob-resource"}, separators=(",", ":")).encode()
        release_bob = await client.post(
            "/v1/reservations/release",
            content=release_bob_body,
            headers=h(write_key, write_did, coord_write, "POST", "/v1/reservations/release", release_bob_body),
        )
        release_body = json.dumps({"resource_key": "alice-resource"}, separators=(",", ":")).encode()
        released = await client.post(
            "/v1/reservations/release",
            content=release_body,
            headers=h(write_key, write_did, coord_write, "POST", "/v1/reservations/release", release_body),
        )
        contacts = await client.get("/v1/contacts", headers=h(contacts_key, contacts_did, contacts_grant, "GET", "/v1/contacts"))
        contacts_denied = await client.get("/v1/contacts", headers=h(mail_key, mail_did, mail_grant, "GET", "/v1/contacts"))
        deleted = await client.delete(f"/v1/contacts/{contact_id}", headers=h(contacts_key, contacts_did, contacts_grant, "DELETE", f"/v1/contacts/{contact_id}"))

    deny_app = FastAPI()
    deny_app.include_router(reservations_router)
    deny_app.state.db = _DbShim(aweb_cloud_db.aweb_db)
    deny_app.state.public_origin = "http://test"
    deny_registry = AsyncMock()
    deny_registry.get_team_revocations = AsyncMock(return_value=set())
    deny_app.state.awid_registry_client = deny_registry

    @deny_app.middleware("http")
    async def cache_body_middleware(request, call_next):
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = hashlib.sha256(body).hexdigest()
        request._receive = _cached_body_receive(body)
        return await call_next(request)

    async with AsyncClient(transport=ASGITransport(app=deny_app), base_url="http://test") as deny_client:
        revoke_denied = await deny_client.post(
            "/v1/reservations/revoke",
            content=b'{"prefix":""}',
            headers=h(write_key, write_did, coord_write, "POST", "/v1/reservations/revoke", b'{"prefix":""}'),
        )

    assert claims.status_code == 200, claims.text
    claim_refs = {claim["task_ref"] for claim in claims.json()["claims"]}
    assert "aweb-abjf" in claim_refs
    assert "other-task" not in claim_refs
    assert claims_denied.status_code == 403
    assert claims_denied.json()["detail"] == "outside grant scope"
    assert reservations.status_code == 200, reservations.text
    reservation_keys = {reservation["resource_key"] for reservation in reservations.json()["reservations"]}
    assert "bob-resource" in reservation_keys
    assert "other-resource" not in reservation_keys
    assert reservations_denied.status_code == 403
    assert acquired.status_code == 200, acquired.text
    assert acquired.json()["holder_agent_id"] == str(alice_id)
    assert renewed.status_code == 200, renewed.text
    assert release_bob.status_code == 409
    assert released.status_code == 200, released.text
    assert revoke_denied.status_code == 403
    assert revoke_denied.json()["detail"] == "outside grant scope"
    assert contacts.status_code == 200, contacts.text
    assert contacts.json()["contacts"][0]["contact_address"] == "acme.com/bob"
    assert contacts_denied.status_code == 403
    assert contacts_denied.json()["detail"] == "outside grant scope"
    assert deleted.status_code == 200, deleted.text

@pytest.mark.asyncio
async def test_grant_real_task_workspace_repo_role_instruction_routes(aweb_cloud_db):
    app, alice_id, bob_id = await _real_messaging_fixture(aweb_cloud_db.aweb_db)
    read_key, read_did = _session_keypair()
    write_key, write_did = _session_keypair()
    presence_key, presence_did = _session_keypair()
    other_presence_key, other_presence_did = _session_keypair()
    expired_presence_key, expired_presence_did = _session_keypair()
    revoked_presence_key, revoked_presence_did = _session_keypair()
    mail_key, mail_did = _session_keypair()
    await aweb_cloud_db.aweb_db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ('other:acme.com', 'acme.com', 'other', 'did:key:zOtherTeam')"
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (team_id, task_number, root_task_seq, task_ref_suffix, title, description, notes, priority, task_type, labels, created_by_alias)
        VALUES ('other:acme.com', 1, 1, 'a', 'other task', '', '', 2, 'task', '{}'::text[], 'other')
        """
    )
    bob_workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role,
            workspace_type, last_seen_at
        )
        VALUES ($1, $2, $3, 'bob', 'Bob', 'developer', 'manual', NOW() - INTERVAL '1 hour')
        """,
        bob_workspace_id,
        TEAM_ID,
        bob_id,
    )
    old_last_seen = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id = $1::UUID",
        app.state.alice_workspace_id,
    )
    repo_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.repos}} (id, team_id, origin_url, canonical_origin, name)
        VALUES ($1, $2, 'git@github.com:awebai/aweb.git', 'github.com/awebai/aweb', 'aweb')
        """,
        repo_id,
        TEAM_ID,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        read_grant = (await _mint(client, grant_did_key=read_did, scopes=["coord.read"])).json()["grant_id"]
        write_grant = (await _mint(client, grant_did_key=write_did, scopes=["coord.write", "coord.read"])).json()["grant_id"]
        presence_grant = (await _mint(client, grant_did_key=presence_did, scopes=["presence.write"])).json()["grant_id"]
        other_presence_grant = (await _mint(client, grant_did_key=other_presence_did, scopes=["presence.write"])).json()["grant_id"]
        expired_presence_grant = (await _mint(client, grant_did_key=expired_presence_did, scopes=["presence.write"])).json()["grant_id"]
        revoked_presence_grant = (await _mint(client, grant_did_key=revoked_presence_did, scopes=["presence.write"])).json()["grant_id"]
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.identity_session_grants}}
            SET issued_at = NOW() - INTERVAL '120 seconds', expires_at = NOW() - INTERVAL '1 second'
            WHERE grant_id = $1::UUID
            """,
            expired_presence_grant,
        )
        await aweb_cloud_db.aweb_db.execute(
            "UPDATE {{tables.identity_session_grants}} SET revoked_at = NOW() WHERE grant_id = $1::UUID",
            revoked_presence_grant,
        )
        mail_grant = (await _mint(client, grant_did_key=mail_did, scopes=["mail.read"])).json()["grant_id"]

        def h(key, did, grant_id, method, path, body=b""):
            return _grant_headers(signing_key=key, did_key=did, grant_id=grant_id, method=method, path=path, body=body)

        create_body = json.dumps({"title": "grant task", "description": "from grant"}, separators=(",", ":")).encode()
        created = await client.post(
            "/v1/tasks",
            content=create_body,
            headers=h(write_key, write_did, write_grant, "POST", "/v1/tasks", create_body),
        )
        task_ref = created.json().get("task_ref")
        tasks = await client.get("/v1/tasks", headers=h(read_key, read_did, read_grant, "GET", "/v1/tasks"))
        ready = await client.get("/v1/tasks/ready", headers=h(read_key, read_did, read_grant, "GET", "/v1/tasks/ready"))
        task = await client.get(f"/v1/tasks/{task_ref}", headers=h(read_key, read_did, read_grant, "GET", f"/v1/tasks/{task_ref}"))
        wrong_scope_task = await client.get("/v1/tasks", headers=h(mail_key, mail_did, mail_grant, "GET", "/v1/tasks"))
        patch_body = json.dumps({"status": "in_progress", "notes": "claimed"}, separators=(",", ":")).encode()
        patched = await client.patch(
            f"/v1/tasks/{task_ref}",
            content=patch_body,
            headers=h(write_key, write_did, write_grant, "PATCH", f"/v1/tasks/{task_ref}", patch_body),
        )
        comments_body = json.dumps({"body": "grant comment"}, separators=(",", ":")).encode()
        comment = await client.post(
            f"/v1/tasks/{task_ref}/comments",
            content=comments_body,
            headers=h(write_key, write_did, write_grant, "POST", f"/v1/tasks/{task_ref}/comments", comments_body),
        )
        comments = await client.get(f"/v1/tasks/{task_ref}/comments", headers=h(read_key, read_did, read_grant, "GET", f"/v1/tasks/{task_ref}/comments"))
        workspaces_path = "/v1/workspaces?include_presence=false"
        workspaces = await client.get(workspaces_path, headers=h(read_key, read_did, read_grant, "GET", workspaces_path))
        team_workspaces_path = "/v1/workspaces/team?include_presence=false"
        team_workspaces = await client.get(team_workspaces_path, headers=h(read_key, read_did, read_grant, "GET", team_workspaces_path))
        heartbeat_body = json.dumps({"workspace_id": app.state.alice_workspace_id, "alias": "alice"}, separators=(",", ":")).encode()
        workspace_heartbeat = await client.post(
            "/v1/workspaces/heartbeat",
            content=heartbeat_body,
            headers=h(presence_key, presence_did, presence_grant, "POST", "/v1/workspaces/heartbeat", heartbeat_body),
        )
        other_workspace_heartbeat = await client.post(
            "/v1/workspaces/heartbeat",
            content=heartbeat_body,
            headers=h(other_presence_key, other_presence_did, other_presence_grant, "POST", "/v1/workspaces/heartbeat", heartbeat_body),
        )
        bob_heartbeat_body = json.dumps({"workspace_id": str(bob_workspace_id), "alias": "bob"}, separators=(",", ":")).encode()
        wrong_workspace_heartbeat = await client.post(
            "/v1/workspaces/heartbeat",
            content=bob_heartbeat_body,
            headers=h(presence_key, presence_did, presence_grant, "POST", "/v1/workspaces/heartbeat", bob_heartbeat_body),
        )
        metadata_heartbeat_body = json.dumps({"workspace_id": app.state.alice_workspace_id, "alias": "alice", "hostname": "grant-host"}, separators=(",", ":")).encode()
        metadata_heartbeat = await client.post(
            "/v1/workspaces/heartbeat",
            content=metadata_heartbeat_body,
            headers=h(presence_key, presence_did, presence_grant, "POST", "/v1/workspaces/heartbeat", metadata_heartbeat_body),
        )
        expired_heartbeat = await client.post(
            "/v1/workspaces/heartbeat",
            content=heartbeat_body,
            headers=h(expired_presence_key, expired_presence_did, expired_presence_grant, "POST", "/v1/workspaces/heartbeat", heartbeat_body),
        )
        revoked_heartbeat = await client.post(
            "/v1/workspaces/heartbeat",
            content=heartbeat_body,
            headers=h(revoked_presence_key, revoked_presence_did, revoked_presence_grant, "POST", "/v1/workspaces/heartbeat", heartbeat_body),
        )
        workspace_patch_body = json.dumps({"focus_task_ref": task_ref}, separators=(",", ":")).encode()
        workspace_patch = await client.patch(
            f"/v1/workspaces/{app.state.alice_workspace_id}",
            content=workspace_patch_body,
            headers=h(presence_key, presence_did, presence_grant, "PATCH", f"/v1/workspaces/{app.state.alice_workspace_id}", workspace_patch_body),
        )
        workspace_wrong_scope = await client.patch(
            f"/v1/workspaces/{app.state.alice_workspace_id}",
            content=workspace_patch_body,
            headers=h(read_key, read_did, read_grant, "PATCH", f"/v1/workspaces/{app.state.alice_workspace_id}", workspace_patch_body),
        )
        workspace_wrong_subject = await client.patch(
            f"/v1/workspaces/{bob_workspace_id}",
            content=workspace_patch_body,
            headers=h(presence_key, presence_did, presence_grant, "PATCH", f"/v1/workspaces/{bob_workspace_id}", workspace_patch_body),
        )
        workspace_metadata_body = json.dumps({"hostname": "grant-host"}, separators=(",", ":")).encode()
        workspace_metadata = await client.patch(
            f"/v1/workspaces/{app.state.alice_workspace_id}",
            content=workspace_metadata_body,
            headers=h(presence_key, presence_did, presence_grant, "PATCH", f"/v1/workspaces/{app.state.alice_workspace_id}", workspace_metadata_body),
        )
        repo_lookup_body = json.dumps({"origin_url": "git@github.com:awebai/aweb.git"}, separators=(",", ":")).encode()
        repo_lookup = await client.post(
            "/v1/repos/lookup",
            content=repo_lookup_body,
            headers=h(read_key, read_did, read_grant, "POST", "/v1/repos/lookup", repo_lookup_body),
        )
        repos = await client.get("/v1/repos", headers=h(read_key, read_did, read_grant, "GET", "/v1/repos"))
        roles = await client.get("/v1/roles/active", headers=h(read_key, read_did, read_grant, "GET", "/v1/roles/active"))
        instructions = await client.get("/v1/instructions/active", headers=h(read_key, read_did, read_grant, "GET", "/v1/instructions/active"))

    deny_app = FastAPI()
    for router in (tasks_router, repos_router, roles_router, instructions_router, workspaces_router):
        deny_app.include_router(router)
    deny_app.state.db = _DbShim(aweb_cloud_db.aweb_db)
    deny_app.state.public_origin = "http://test"
    deny_app.state.redis = None
    deny_registry = AsyncMock()
    deny_registry.get_team_revocations = AsyncMock(return_value=set())
    deny_app.state.awid_registry_client = deny_registry

    @deny_app.middleware("http")
    async def cache_body_middleware(request, call_next):
        body = await request.body()
        request.state.cached_body = body
        request.state.body_sha256 = hashlib.sha256(body).hexdigest()
        request._receive = _cached_body_receive(body)
        return await call_next(request)

    async with AsyncClient(transport=ASGITransport(app=deny_app), base_url="http://test") as deny_client:
        delete_task = await deny_client.delete(f"/v1/tasks/{task_ref}", headers=h(write_key, write_did, write_grant, "DELETE", f"/v1/tasks/{task_ref}"))
        ensure_body = json.dumps({"origin_url": "git@github.com:awebai/aweb.git"}, separators=(",", ":")).encode()
        ensure_repo = await deny_client.post("/v1/repos/ensure", content=ensure_body, headers=h(write_key, write_did, write_grant, "POST", "/v1/repos/ensure", ensure_body))
        reset_roles = await deny_client.post("/v1/roles/reset", headers=h(write_key, write_did, write_grant, "POST", "/v1/roles/reset"))
        reset_instructions = await deny_client.post("/v1/instructions/reset", headers=h(write_key, write_did, write_grant, "POST", "/v1/instructions/reset"))
        delete_workspace = await deny_client.delete(f"/v1/workspaces/{app.state.alice_workspace_id}", headers=h(presence_key, presence_did, presence_grant, "DELETE", f"/v1/workspaces/{app.state.alice_workspace_id}"))

    assert created.status_code == 200, created.text
    assert task_ref
    assert tasks.status_code == 200, tasks.text
    task_refs = {item["task_ref"] for item in tasks.json()["tasks"]}
    assert task_ref in task_refs
    assert "other-a" not in task_refs
    assert ready.status_code == 200, ready.text
    assert task.status_code == 200, task.text
    assert wrong_scope_task.status_code == 403
    assert wrong_scope_task.json()["detail"] == "outside grant scope"
    assert patched.status_code == 200, patched.text
    assert patched.json()["assignee_alias"] == "alice"
    owner = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT workspace_id, alias FROM {{tables.task_claims}} WHERE team_id = $1 AND task_ref = $2",
        TEAM_ID,
        task_ref,
    )
    assert str(owner["workspace_id"]) == app.state.alice_workspace_id
    assert owner["alias"] == "alice"
    assert comment.status_code == 200, comment.text
    assert comments.status_code == 200, comments.text
    assert comments.json()["comments"][0]["body"] == "grant comment"
    assert workspaces.status_code == 200, workspaces.text
    assert all(item["team_id"] == TEAM_ID for item in workspaces.json()["workspaces"])
    assert team_workspaces.status_code == 200, team_workspaces.text
    assert workspace_heartbeat.status_code == 200, workspace_heartbeat.text
    assert other_workspace_heartbeat.status_code == 200, other_workspace_heartbeat.text
    liveness_rows = await aweb_cloud_db.aweb_db.fetch_all(
        "SELECT grant_id::text, workspace_id::text, subject_agent_id::text FROM {{tables.identity_grant_liveness}} WHERE grant_id = ANY($1::uuid[]) ORDER BY grant_id::text",
        [presence_grant, other_presence_grant],
    )
    assert {row["grant_id"] for row in liveness_rows} == {presence_grant, other_presence_grant}
    assert {row["workspace_id"] for row in liveness_rows} == {app.state.alice_workspace_id}
    assert {row["subject_agent_id"] for row in liveness_rows} == {str(alice_id)}
    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id = $1::UUID",
        app.state.alice_workspace_id,
    ) == old_last_seen
    assert wrong_workspace_heartbeat.status_code == 403
    assert wrong_workspace_heartbeat.json()["detail"] == "grant workspace mismatch"
    assert metadata_heartbeat.status_code == 403
    assert metadata_heartbeat.json()["detail"] == "grant workspace metadata is not shared presence"
    assert expired_heartbeat.status_code == 403
    assert expired_heartbeat.json()["detail"] == "grant expired"
    assert revoked_heartbeat.status_code == 403
    assert revoked_heartbeat.json()["detail"] == "grant revoked"
    assert workspace_patch.status_code == 200, workspace_patch.text
    assert workspace_wrong_scope.status_code == 403
    assert workspace_wrong_scope.json()["detail"] == "outside grant scope"
    assert workspace_wrong_subject.status_code == 403
    assert workspace_wrong_subject.json()["detail"] == "grant workspace mismatch"
    assert workspace_metadata.status_code == 403
    assert workspace_metadata.json()["detail"] == "grant workspace metadata is not shared presence"
    assert repo_lookup.status_code == 200, repo_lookup.text
    assert repo_lookup.json()["repo_id"] == str(repo_id)
    assert repos.status_code == 200, repos.text
    assert repos.json()["repos"][0]["canonical_origin"] == "github.com/awebai/aweb"
    assert roles.status_code == 200, roles.text
    assert instructions.status_code == 200, instructions.text
    for response in (delete_task, ensure_repo, reset_roles, reset_instructions, delete_workspace):
        assert response.status_code == 403
        assert response.json()["detail"] == "outside grant scope"

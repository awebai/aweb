from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI, Request
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.api import create_app
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.routes.identity_grants import router as identity_grants_router
from aweb.team_auth_deps import TeamIdentity, get_team_identity

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

    @app.get("/v1/chat/{session_id}/messages")
    async def _chat_read(session_id: str, auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.post("/v1/chat/{session_id}/messages")
    async def _chat_send(session_id: str, auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    @app.post("/v1/chat/{session_id}/read")
    async def _chat_mark_read(session_id: str, auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    # Hypothetical wiring: even if a privileged route resolved messaging auth,
    # the grant verifier's path gate must refuse it.
    @app.post("/v1/session-leases")
    async def _lease(auth: MessagingAuth = Depends(get_messaging_auth)):
        return _auth_view(auth)

    app.dependency_overrides[get_team_identity] = _identity
    app.state.db = _DbShim(aweb_db)
    app.state.public_origin = "http://test"

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
    assert auth["certificate_id"] == f"grant:{grant['grant_id']}"


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
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        send_grant = (await _mint(client, grant_did_key=send_did, scopes=["mail.send"])).json()["grant_id"]
        chat_grant = (await _mint(client, grant_did_key=chat_did, scopes=["chat.read"])).json()["grant_id"]

        def send_headers(method, path):
            return _grant_headers(signing_key=send_key, did_key=send_did, grant_id=send_grant, method=method, path=path)

        def chat_headers(method, path):
            return _grant_headers(signing_key=chat_key, did_key=chat_did, grant_id=chat_grant, method=method, path=path)

        inbox_denied = await client.get("/v1/messages", headers=send_headers("GET", "/v1/messages"))
        send_allowed = await client.post("/v1/messages", headers=send_headers("POST", "/v1/messages"))
        roster_allowed = await client.get("/v1/agents", headers=send_headers("GET", "/v1/agents"))
        lease_denied = await client.post("/v1/session-leases", headers=send_headers("POST", "/v1/session-leases"))

        chat_read_allowed = await client.get("/v1/chat/s1/messages", headers=chat_headers("GET", "/v1/chat/s1/messages"))
        mark_read_allowed = await client.post("/v1/chat/s1/read", headers=chat_headers("POST", "/v1/chat/s1/read"))
        chat_send_denied = await client.post("/v1/chat/s1/messages", headers=chat_headers("POST", "/v1/chat/s1/messages"))
        chat_roster_allowed = await client.get("/v1/agents", headers=chat_headers("GET", "/v1/agents"))

    assert inbox_denied.status_code == 403
    assert inbox_denied.json()["detail"] == "outside grant scope"
    assert send_allowed.status_code == 200
    assert roster_allowed.status_code == 200
    assert lease_denied.status_code == 403
    assert lease_denied.json()["detail"] == "outside grant scope"
    assert chat_read_allowed.status_code == 200
    assert mark_read_allowed.status_code == 200
    assert chat_send_denied.status_code == 403
    assert chat_send_denied.json()["detail"] == "outside grant scope"
    assert chat_roster_allowed.status_code == 200


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

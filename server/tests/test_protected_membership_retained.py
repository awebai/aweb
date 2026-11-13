"""Real registry/DB consumers must bind every retained or presented member field.

Synthetic protection activation tests baseline acceptance, not signer execution.
"""

import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from aweb_naapp_testing import Member, did_key
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from fastapi import FastAPI, Request
from nacl.signing import SigningKey

from aweb.auth_context import GrantContext
from aweb.coordination.app_tasks import verify_authorization_certificate
from aweb.grant_streams import grant_terminal_reason
from aweb.identity_auth_deps import get_messaging_auth
from aweb.identity_grant_status import effective_grant_status
from aweb.messaging.room_notices import _refresh_room_authority
from aweb.team_auth_deps import TeamIdentity
from tests.test_identity_grants import _grant_headers

TEAM = "backend:beta.example"
ORIGIN = "http://test"


@pytest_asyncio.fixture
async def membership_env(real_stack):
    member = Member(team_id=TEAM, extra_cert_fields={"identity_scope": "local"})
    cert = member.certificate()
    encoded = base64.b64encode(json.dumps(cert).encode()).decode()
    await real_stack.awid_db.execute(
        "INSERT INTO {{tables.teams}} (domain,name,team_did_key,visibility) "
        "VALUES ('beta.example','backend',$1,'public')", member.team_did_key,
    )
    await real_stack.awid_db.execute(
        "INSERT INTO {{tables.team_certificates}} "
        "(team_uuid,certificate_id,member_did_key,alias,identity_scope,certificate) "
        "SELECT team_uuid,$1,$2,$3,'local',$4 FROM {{tables.teams}} "
        "WHERE domain='beta.example' AND name='backend'",
        member.certificate_id, member.did_key, member.alias, encoded,
    )
    db = real_stack.aweb_db
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) "
        "VALUES ($1,'beta.example','backend',$2)", TEAM, member.team_did_key,
    )
    registry = RegistryClient(
        registry_url="https://registry.example", transport=real_stack.awid,
        service_token=real_stack.service_token,
    )
    try:
        yield SimpleNamespace(stack=real_stack, member=member, registry=registry, encoded=encoded)
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["identity", "grant", "stream", "status", "room", "task"])
@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
@pytest.mark.parametrize("change", ["genuine", "key", "alias"])
async def test_exact_retained_and_presented_membership(membership_env, surface, protected, change):
    env = membership_env
    registered = env.member
    claimed = registered
    if change == "key":
        claimed = replace(registered, member_key=SigningKey.generate())
    elif change == "alias":
        claimed = replace(registered, alias="impostor")
    db = env.stack.aweb_db
    agent_id, grant_id = uuid4(), uuid4()
    await db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id,team_id,alias,did_key,certificate_id,identity_scope,status) "
        "VALUES ($1,$2,$3,$4,$5,'local','active')",
        agent_id, TEAM, claimed.alias, claimed.did_key, registered.certificate_id,
    )
    session_key = SigningKey.generate()
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(hours=1)
    await db.execute(
        "INSERT INTO {{tables.identity_session_grants}} "
        "(grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_by_certificate_id,issued_at,expires_at) "
        "VALUES ($1,$2,$3,$4,ARRAY['mail.read','chat.read'],$5,$6,$7)",
        grant_id, TEAM, agent_id, did_key(session_key), registered.certificate_id, issued, expires,
    )
    if protected:
        await env.stack.awid_db.execute(
            "INSERT INTO {{tables.team_protection}} "
            "(domain,name,service_id,service_did_key,generation) VALUES ('beta.example','backend','test-signer',$1,1)",
            did_key(SigningKey.generate()),
        )
    app = FastAPI()
    app.state.db = SimpleNamespace(get_manager=lambda name="aweb": db)
    app.state.awid_registry_client = env.registry
    app.state.public_origin = ORIGIN
    identity = TeamIdentity(
        team_id=TEAM, alias=claimed.alias, did_key=claimed.did_key,
        did_aw="", address="", agent_id=str(agent_id), identity_scope="local",
        certificate_id=registered.certificate_id,
    )
    grant = GrantContext(
        grant_id=str(grant_id), session_did_key=did_key(session_key),
        issuing_certificate_id=registered.certificate_id,
        scopes=("mail.read", "chat.read"), expires_at=expires,
    )

    @app.get("/v1/messages")
    async def check(request: Request):
        if surface in {"identity", "grant"}:
            auth = await get_messaging_auth(request, app.state.db)
            return {"team_id": auth.team_id}
        if surface == "stream":
            reason = await grant_terminal_reason(request, app.state.db, replace(identity, grant=grant))
            return {"reason": reason}
        if surface == "status":
            row = await db.fetch_one(
                "SELECT g.*, a.did_key AS subject_did_key, a.alias, a.did_aw, a.address, "
                "a.identity_scope, a.status AS subject_status, a.deleted_at AS subject_deleted_at "
                "FROM {{tables.identity_session_grants}} g JOIN {{tables.agents}} a "
                "ON a.agent_id=g.subject_agent_id WHERE g.grant_id=$1", grant_id,
            )
            status, _ = await effective_grant_status(request, row, issued)
            return {"status": status}
        if surface == "room":
            await _refresh_room_authority(request, app.state.db, identity)
        else:
            await verify_authorization_certificate(request, {
                "certificate": base64.b64encode(json.dumps(claimed.certificate()).encode()).decode(),
                "payload": {"team_id": TEAM, "actor_did_key": claimed.did_key,
                            "certificate_id": registered.certificate_id},
            })
        return {"accepted": True}

    if surface == "grant":
        headers = _grant_headers(
            signing_key=bytes(session_key), did_key=did_key(session_key), grant_id=str(grant_id),
            method="GET", path="/v1/messages",
        )
    elif surface == "identity":
        timestamp = issued.isoformat()
        payload = canonical_json_bytes({"did_aw": "", "timestamp": timestamp,
                                        "body_sha256": hashlib.sha256(b"").hexdigest()})
        headers = {"Authorization": f"DIDKey {claimed.did_key} {sign_message(bytes(claimed.member_key), payload)}",
                   "X-AWEB-Timestamp": timestamp}
    else:
        headers = claimed.headers(aud=ORIGIN, method="GET", path="/v1/messages")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        response = await client.get("/v1/messages", headers=headers)
    assert response.status_code == (401 if protected and change != "genuine" else 200), response.text
    if protected and change != "genuine":
        assert "certificate_binding_mismatch" in response.text

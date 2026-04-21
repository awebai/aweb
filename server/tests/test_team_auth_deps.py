"""Tests for the team certificate FastAPI auth dependency."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from nacl.signing import SigningKey

import aweb.identity_auth_deps as _identity_auth_mod
import aweb.team_auth_deps as _team_auth_mod
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import IdentityAuth, get_messaging_auth
from aweb.team_auth_deps import TeamIdentity


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


def _make_certificate(team_sk, team_did_key, member_did_key, **kwargs):
    cert = {
        "version": 1,
        "certificate_id": kwargs.get("certificate_id", "cert-001"),
        "team_id": kwargs.get("team_id", "backend:acme.com"),
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": "",
        "member_address": "",
        "alias": kwargs.get("alias", "alice"),
        "lifetime": kwargs.get("lifetime", "persistent"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = canonical_json_bytes(cert)
    sig = sign_message(team_sk, payload)
    cert["signature"] = sig
    return cert


def _encode_certificate(cert):
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _request_with_headers(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/mcp",
            "query_string": b"",
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
            "http_version": "1.1",
        }
    )


class TestTeamIdentity:
    def test_dataclass_fields(self):
        from aweb.team_auth_deps import TeamIdentity

        identity = TeamIdentity(
            team_id="backend:acme.com",
            alias="alice",
            did_key="did:key:z6Mktest",
            did_aw="did:aw:alice",
            address="acme.com/alice",
            agent_id="agent-uuid",
            lifetime="persistent",
            certificate_id="cert-001",
        )

        assert identity.team_id == "backend:acme.com"
        assert identity.alias == "alice"
        assert identity.did_key == "did:key:z6Mktest"
        assert identity.did_aw == "did:aw:alice"
        assert identity.address == "acme.com/alice"
        assert identity.agent_id == "agent-uuid"
        assert identity.lifetime == "persistent"
        assert identity.certificate_id == "cert-001"

    def test_frozen(self):
        from aweb.team_auth_deps import TeamIdentity

        identity = TeamIdentity(
            team_id="backend:acme.com",
            alias="alice",
            did_key="did:key:z6Mktest",
            did_aw="did:aw:alice",
            address="acme.com/alice",
            agent_id="agent-uuid",
            lifetime="persistent",
            certificate_id="cert-001",
        )

        with pytest.raises(AttributeError):
            identity.team_id = "other"


class TestResolveTeamIdentity:
    @pytest.mark.asyncio
    async def test_resolves_from_cert_info_and_db(self, aweb_cloud_db):
        from aweb.team_auth_deps import resolve_team_identity

        db = aweb_cloud_db.aweb_db

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        # Provision team + agent via connect
        from aweb.routes.connect import connect_agent

        result = await connect_agent(
            db=db,
            cert_info={
                "team_id": "backend:acme.com",
                "alias": "alice",
                "did_key": agent_did_key,
                "member_did_aw": "did:aw:alice",
                "member_address": "acme.com/alice",
                "lifetime": "persistent",
                "certificate_id": "cert-001",
            },
            team_did_key=team_did_key,
            hostname="Mac.local",
            workspace_path="/project",
            repo_origin="",
            role="developer",
            human_name="",
            agent_type="agent",
        )

        cert_info = {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "did_key": agent_did_key,
            "member_did_aw": "did:aw:alice",
            "member_address": "acme.com/alice",
            "lifetime": "persistent",
            "certificate_id": "cert-001",
        }

        identity = await resolve_team_identity(db, cert_info)

        assert identity.team_id == "backend:acme.com"
        assert identity.alias == "alice"
        assert identity.did_key == agent_did_key
        assert identity.did_aw == "did:aw:alice"
        assert identity.address == "acme.com/alice"
        assert identity.agent_id == result["agent_id"]
        assert identity.lifetime == "persistent"
        assert identity.certificate_id == "cert-001"

    @pytest.mark.asyncio
    async def test_unknown_agent_raises(self, aweb_cloud_db):
        from aweb.team_auth_deps import resolve_team_identity

        db = aweb_cloud_db.aweb_db
        _, _, unknown_did_key = _make_keypair()

        cert_info = {
            "team_id": "backend:acme.com",
            "alias": "unknown",
            "did_key": unknown_did_key,
            "lifetime": "ephemeral",
            "certificate_id": "cert-002",
        }

        with pytest.raises(ValueError, match="not connected"):
            await resolve_team_identity(db, cert_info)


@pytest.mark.asyncio
async def test_get_team_identity_accepts_raw_manager(aweb_cloud_db, monkeypatch):
    from aweb.routes.connect import connect_agent
    from aweb.team_auth_deps import get_team_identity

    db = aweb_cloud_db.aweb_db
    team_sk, _, team_did_key = _make_keypair()
    _, _, agent_did_key = _make_keypair()

    connected = await connect_agent(
        db=db,
        cert_info={
            "team_id": "backend:acme.com",
            "alias": "alice",
            "did_key": agent_did_key,
            "member_did_aw": "did:aw:alice",
            "member_address": "acme.com/alice",
            "lifetime": "persistent",
            "certificate_id": "cert-raw-manager",
        },
        team_did_key=team_did_key,
        hostname="Mac.local",
        workspace_path="/project",
        repo_origin="",
        role="developer",
        human_name="",
        agent_type="agent",
    )

    async def _fake_verify_request_certificate(_request, _db):
        return {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "did_key": agent_did_key,
            "member_did_aw": "did:aw:alice",
            "member_address": "acme.com/alice",
            "lifetime": "persistent",
            "certificate_id": "cert-raw-manager",
        }

    monkeypatch.setattr(_team_auth_mod, "verify_request_certificate", _fake_verify_request_certificate)

    identity = await get_team_identity(_request_with_headers({}), db)

    assert identity.agent_id == connected["agent_id"]
    assert identity.did_aw == "did:aw:alice"
    assert identity.address == "acme.com/alice"


@pytest.mark.asyncio
async def test_get_messaging_auth_accepts_raw_manager(aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    agent_id = uuid.uuid4()

    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        "backend:acme.com",
        "acme.com",
        "backend",
        "did:key:z6MkTeam",
    )

    await db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, address, alias, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, 'persistent', 'active')
        """,
        agent_id,
        "backend:acme.com",
        "did:key:z6MkAlice",
        "did:aw:alice",
        "acme.com/alice",
        "alice",
    )

    async def _fake_get_team_identity(_request, _db):
        return TeamIdentity(
            team_id="backend:acme.com",
            alias="alice",
            did_key="did:key:z6MkAlice",
            did_aw="did:aw:alice",
            address="acme.com/alice",
            agent_id=str(agent_id),
            lifetime="persistent",
            certificate_id="cert-1",
        )

    monkeypatch.setattr(_identity_auth_mod, "get_team_identity", _fake_get_team_identity)

    auth = await get_messaging_auth(
        _request_with_headers(
            {
                "Authorization": "DIDKey did:key:z6MkAlice signature",
                "X-AWID-Team-Certificate": "certificate",
            }
        ),
        db,
    )

    assert auth.agent_id == str(agent_id)
    assert auth.did_aw == "did:aw:alice"
    assert auth.address == "acme.com/alice"


@pytest.mark.asyncio
async def test_get_messaging_auth_enriches_identity_auth_from_agent_row(aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    agent_id = uuid.uuid4()

    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:gsk.aweb.ai', 'gsk.aweb.ai', 'ops', 'did:key:z6MkTeam')
        """
    )
    await db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, did_aw, address, alias, lifetime, status)
        VALUES ($1, 'ops:gsk.aweb.ai', $2, NULL, NULL, 'gsk', 'ephemeral', 'active')
        """,
        agent_id,
        "did:key:z6MkGsk",
    )

    async def _fake_resolve_identity_auth(_request):
        return IdentityAuth(did_key="did:key:z6MkGsk", did_aw=None, address=None)

    monkeypatch.setattr(_identity_auth_mod, "resolve_identity_auth", _fake_resolve_identity_auth)

    auth = await get_messaging_auth(
        _request_with_headers({"Authorization": "DIDKey did:key:z6MkGsk signature"}),
        db,
    )

    assert auth.did_key == "did:key:z6MkGsk"
    assert auth.team_id == "ops:gsk.aweb.ai"
    assert auth.alias == "gsk"
    assert auth.agent_id == str(agent_id)
    assert auth.lifetime == "ephemeral"


@pytest.mark.asyncio
async def test_get_messaging_auth_rejects_ambiguous_identity_auth_agent_rows(aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db

    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES
            ('ops:gsk.aweb.ai', 'gsk.aweb.ai', 'ops', 'did:key:z6MkTeamOps'),
            ('dev:gsk.aweb.ai', 'gsk.aweb.ai', 'dev', 'did:key:z6MkTeamDev')
        """
    )
    await db.execute(
        """
        INSERT INTO {{tables.agents}}
            (team_id, did_key, did_aw, address, alias, lifetime, status)
        VALUES
            ('ops:gsk.aweb.ai', 'did:key:z6MkGsk', NULL, NULL, 'gsk', 'ephemeral', 'active'),
            ('dev:gsk.aweb.ai', 'did:key:z6MkGsk', NULL, NULL, 'gsk', 'ephemeral', 'active')
        """
    )

    async def _fake_resolve_identity_auth(_request):
        return IdentityAuth(did_key="did:key:z6MkGsk", did_aw=None, address=None)

    monkeypatch.setattr(_identity_auth_mod, "resolve_identity_auth", _fake_resolve_identity_auth)

    with pytest.raises(HTTPException) as exc_info:
        await get_messaging_auth(
            _request_with_headers({"Authorization": "DIDKey did:key:z6MkGsk signature"}),
            db,
        )

    assert exc_info.value.status_code == 409

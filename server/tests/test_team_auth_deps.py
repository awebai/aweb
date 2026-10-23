"""Tests for the team certificate FastAPI auth dependency."""

from __future__ import annotations

import base64
from collections import OrderedDict
from time import monotonic
import hashlib
import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from nacl.signing import SigningKey

import aweb.identity_auth_deps as _identity_auth_mod
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.identity_auth_deps import IdentityAuth, get_messaging_auth
from aweb.identity_binding import IdentityBinding
from aweb.team_auth_deps import TeamIdentity
from test_dashboard_privacy import privacy_app  # noqa: F401


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
        "identity_scope": kwargs.get("identity_scope", "global"),
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


def _request_with_app_state(
    headers: dict[str, str],
    *,
    public_origin: str = "https://local.example",
    body_sha256: str | None = None,
) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/tasks",
            "raw_path": b"/v1/tasks",
            "query_string": b"",
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
            "scheme": "https",
            "server": ("local.example", 443),
            "client": ("127.0.0.1", 12345),
            "http_version": "1.1",
            "app": SimpleNamespace(state=SimpleNamespace(public_origin=public_origin)),
            "state": {"body_sha256": body_sha256 or hashlib.sha256(b"").hexdigest()},
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
            identity_scope="global",
            certificate_id="cert-001",
        )

        assert identity.team_id == "backend:acme.com"
        assert identity.alias == "alice"
        assert identity.did_key == "did:key:z6Mktest"
        assert identity.did_aw == "did:aw:alice"
        assert identity.address == "acme.com/alice"
        assert identity.agent_id == "agent-uuid"
        assert identity.identity_scope == "global"
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
            identity_scope="global",
            certificate_id="cert-001",
        )

        with pytest.raises(AttributeError):
            identity.team_id = "other"


class TestResolveTeamIdentity:
    @pytest.mark.asyncio
    async def test_resolves_from_cert_info_and_db(self, privacy_app):
        from aweb.identity_binding import observe_identity_binding
        from aweb.routes.connect import connect_agent
        from aweb.team_auth_deps import resolve_team_identity
        from identity_binding_support import register_global_identity
        from test_cli_never_grants import registry_listener
        from test_dashboard_privacy import TEAM

        env = privacy_app
        bob = env.actors["bob"]
        address = "example.test/bob"
        async with registry_listener(env) as (registry, _):
            stable = await register_global_identity(env, bob, address)
            binding = await observe_identity_binding(registry, did_key=bob.did, did_aw=stable, address=address)
            cert_info = dict(team_id=TEAM, alias="bob", did_key=bob.did, member_did_aw=stable,
                             member_address=address, identity_scope="global", certificate_id="cert-001",
                             identity_binding=binding)
            result = await connect_agent(
                db=env.db, cert_info=cert_info, identity_binding=binding, team_did_key=env.team_did,
                hostname="Mac.local", workspace_path="/project", repo_origin="", role="developer",
                human_name="", agent_type="agent",
            )
            identity = await resolve_team_identity(env.db, cert_info)
        assert identity.team_id == TEAM
        assert identity.alias == "bob"
        assert identity.did_key == bob.did
        assert identity.did_aw == stable
        assert identity.address == address
        assert identity.agent_id == result["agent_id"]
        assert identity.identity_scope == "global"
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
            "identity_scope": "local",
            "certificate_id": "cert-002",
        }

        with pytest.raises(ValueError, match="not connected"):
            await resolve_team_identity(db, cert_info)


@pytest.mark.asyncio
async def test_get_team_identity_accepts_raw_manager(privacy_app):
    from aweb.identity_binding import observe_identity_binding
    from aweb.routes.connect import connect_agent
    from aweb.team_auth_deps import get_team_identity
    from identity_binding_support import register_global_identity
    from test_cli_never_grants import registry_listener
    from test_dashboard_privacy import TEAM
    from test_messages_http import _make_certificate as certificate, _encode_certificate as encode, _signed_team_headers

    env = privacy_app
    bob = env.actors["bob"]
    address = "example.test/bob"
    async with registry_listener(env) as (registry, _):
        stable = await register_global_identity(env, bob, address)
        binding = await observe_identity_binding(registry, did_key=bob.did, did_aw=stable, address=address)
        connected = await connect_agent(
            db=env.db,
            cert_info=dict(team_id=TEAM, alias="bob", did_key=bob.did, member_did_aw=stable,
                           member_address=address, identity_scope="global", certificate_id="cert-raw-manager"),
            identity_binding=binding, team_did_key=env.team_did,
            hostname="Mac.local", workspace_path="/project", repo_origin="", role="developer",
            human_name="", agent_type="agent",
        )
        cert = encode(certificate(env.team_sk, env.team_did, bob.did, team_id=TEAM, alias="bob",
                                  identity_scope="global", member_did_aw=stable, member_address=address,
                                  certificate_id="cert-raw-manager"))
        req = _request_with_app_state(_signed_team_headers(bob.sk, bob.did, TEAM, cert, b""))
        req.scope["app"] = env.app
        identity = await get_team_identity(req, env.db)
    assert identity.agent_id == connected["agent_id"]
    assert identity.did_aw == stable
    assert identity.address == address


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
            (agent_id, team_id, did_key, did_aw, address, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, $5, $6, 'global', 'active')
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
            identity_scope="global",
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
            (agent_id, team_id, did_key, did_aw, address, alias, identity_scope, status)
        VALUES ($1, 'ops:gsk.aweb.ai', $2, NULL, NULL, 'gsk', 'local', 'active')
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
    assert auth.identity_scope == "local"


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
            (team_id, did_key, did_aw, address, alias, identity_scope, status)
        VALUES
            ('ops:gsk.aweb.ai', 'did:key:z6MkGsk', NULL, NULL, 'gsk', 'local', 'active'),
            ('dev:gsk.aweb.ai', 'did:key:z6MkGsk', NULL, NULL, 'gsk', 'local', 'active')
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


@pytest.mark.asyncio
async def test_get_messaging_auth_allows_identity_scoped_persistent_multi_membership(aweb_cloud_db, monkeypatch):
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
            (team_id, did_key, did_aw, address, alias, identity_scope, status, did_aw_verified_key)
        VALUES
            ('ops:gsk.aweb.ai', 'did:key:z6MkGsk', 'did:aw:gsk', 'gsk.aweb.ai/grace', 'grace', 'global', 'active', 'did:key:z6MkGsk'),
            ('dev:gsk.aweb.ai', 'did:key:z6MkGsk', 'did:aw:gsk', 'gsk.aweb.ai/grace', 'grace', 'global', 'active', 'did:key:z6MkGsk')
        """
    )

    async def _fake_resolve_identity_auth(_request, *, db=None):
        return IdentityAuth(did_key="did:key:z6MkGsk", did_aw="did:aw:gsk", address="gsk.aweb.ai/grace")

    monkeypatch.setattr(_identity_auth_mod, "resolve_identity_auth", _fake_resolve_identity_auth)

    request = _request_with_app_state({"Authorization": "DIDKey did:key:z6MkGsk signature"})
    # This projection-selection unit test starts after successful identity
    # verification. The real registry admission cases live in
    # test_identity_binding_http.py.
    request.app.state.awid_registry_client = object()
    request.app.state.identity_binding_cache = OrderedDict({
        ("did:aw:gsk", "did:key:z6MkGsk", "gsk.aweb.ai/grace"): (
            monotonic() + 60, IdentityBinding("did:aw:gsk", "gsk.aweb.ai/grace"),
        ),
    })
    auth = await get_messaging_auth(request, db)

    assert auth.did_key == "did:key:z6MkGsk"
    assert auth.did_aw == "did:aw:gsk"
    assert auth.address == "gsk.aweb.ai/grace"
    assert auth.team_id is None
    assert auth.alias is None
    assert auth.agent_id is None


HOSTILE_CERTIFICATES = {
    "list": base64.b64encode(b"[]").decode(),
    "string": base64.b64encode(b'"x"').decode(),
    "deep": base64.b64encode(b"[" * 6000).decode(),
    "oversize": base64.b64encode(b'{"pad":"' + b"a" * 7000 + b'"}').decode(),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("certificate", HOSTILE_CERTIFICATES.values(), ids=HOSTILE_CERTIFICATES.keys())
async def test_verify_request_certificate_refuses_a_hostile_certificate_with_401(certificate):
    from aweb.team_auth_deps import verify_request_certificate

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    request = _request_with_app_state(
        {
            "Authorization": "DIDKey did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK sig",
            "X-AWEB-Timestamp": timestamp,
            "X-AWID-Team-Certificate": certificate,
        }
    )
    with pytest.raises(HTTPException) as refused:
        await verify_request_certificate(request, db=object())
    assert refused.value.status_code == 401
    assert refused.value.detail == "Malformed certificate"


@pytest.mark.parametrize("certificate", HOSTILE_CERTIFICATES.values(), ids=HOSTILE_CERTIFICATES.keys())
def test_parse_and_verify_certificate_refuses_a_hostile_certificate(certificate):
    from aweb.team_auth import parse_and_verify_certificate

    with pytest.raises(ValueError) as refused:
        parse_and_verify_certificate(
            certificate,
            request_did_key="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            team_public_key_resolver=lambda _team_id: "",
            revocation_checker=lambda _team_id, _certificate_id: False,
        )
    assert str(refused.value) == "Malformed certificate: invalid base64 or JSON"

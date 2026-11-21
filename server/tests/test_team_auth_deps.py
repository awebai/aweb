"""Tests for the team certificate FastAPI auth dependency."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from contextlib import aclosing
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from aweb.identity_auth_deps import get_messaging_auth
from aweb.member_status import MemberStatus
from aweb.team_auth_deps import TeamIdentity
from awid.did import did_from_public_key
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid.registry import RegistryClient
from awid.request_auth import compact_team_auth_payload
from awid.signing import canonical_json_bytes, sign_message
from awid_service.main import create_app as create_registry_app
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport
from nacl.signing import SigningKey
from starlette.requests import Request
from test_dashboard_privacy import privacy_app as privacy_app

__all__ = ["privacy_app"]


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
            "app": FastAPI(),
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


async def _admitted_cert_info(env, *, alias):
    """Register/connect through real routes before exercising a native reader."""
    from aweb.application_state import application_registry_client
    from aweb.team_auth import parse_and_verify_certificate
    from test_dashboard_privacy import TEAM, TEAM_NAME
    from test_messages_http import _signed_team_headers

    member = env.actors[alias]
    claims = json.loads(base64.b64decode(member.certificate))
    registry = application_registry_client(env.app.state)
    await registry.register_team_certificate(
        "example.test",
        TEAM_NAME,
        team_controller_signing_key=env.team_sk,
        certificate_id=claims["certificate_id"],
        member_did_key=member.did,
        member_did_aw=claims.get("member_did_aw") or None,
        member_address=claims.get("member_address") or None,
        alias=alias,
        identity_scope=claims["identity_scope"],
        certificate=member.certificate,
    )
    connected = await env.client.post(
        "/v1/connect",
        content=b"{}",
        headers={
            **_signed_team_headers(member.sk, member.did, TEAM, member.certificate, b"{}"),
            "Content-Type": "application/json",
        },
    )
    assert connected.status_code == 200, connected.text
    team_key = await registry.get_team_public_key("example.test", TEAM_NAME)
    revoked = await registry.get_team_revocations("example.test", TEAM_NAME)
    registered = await registry.list_team_certificates("example.test", TEAM_NAME, active_only=False)
    cert_info = parse_and_verify_certificate(
        member.certificate,
        request_did_key=member.did,
        team_did_key=team_key,
        revoked_certificate_ids=revoked,
        registered_certificate_ids={certificate.certificate_id for certificate in registered},
    )
    cert_info["verified_team_did_key"] = team_key
    return member, cert_info


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
            binding = await observe_identity_binding(
                registry, did_key=bob.did, did_aw=stable, address=address
            )
            cert_info = dict(
                team_id=TEAM,
                alias="bob",
                did_key=bob.did,
                member_did_aw=stable,
                member_address=address,
                identity_scope="global",
                certificate_id="cert-001",
                identity_binding=binding,
                verified_team_did_key=env.team_did,
            )
            result = await connect_agent(
                db=env.db,
                cert_info=cert_info,
                identity_binding=binding,
                team_did_key=env.team_did,
                hostname="Mac.local",
                workspace_path="/project",
                repo_origin="",
                role="developer",
                human_name="",
                agent_type="agent",
            )
            assert binding.fresh_observation
            queries = []
            async with env.db.transaction() as tx:
                with tx.connection.query_logger(lambda event: queries.append(event.query)):
                    identity = await resolve_team_identity(tx, cert_info)
                    assert await tx.fetch_value("SELECT 1") == 1
            assert any("FOR SHARE OF t FOR UPDATE OF a" in query for query in queries)
            assert (
                await env.db.fetch_value(
                    "SELECT accepted_team_did_key FROM {{tables.agents}} WHERE agent_id=$1", bob.id
                )
                == env.team_did
            )
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
    async def test_rechecks_the_exact_native_snapshot_under_acceptance_locks(self, privacy_app):
        from aweb.member_team_key import read_member_projection
        from aweb.team_auth_deps import resolve_team_identity

        env = privacy_app
        member, cert_info = await _admitted_cert_info(env, alias="bob")
        queries = []
        async with env.db.transaction() as tx:
            cert_info["agent_row"] = await read_member_projection(
                tx, team_id=cert_info["team_id"], did_key=member.did
            )
            with tx.connection.query_logger(lambda event: queries.append(event.query)):
                identity = await resolve_team_identity(tx, cert_info)
                # Flush scheduled query-log callbacks through real I/O. This is
                # observation on the caller's connection, not a DB replacement.
                assert await tx.fetch_value("SELECT 1") == 1
        assert identity.agent_id == str(member.id)
        member_reads = [
            query for query in queries if "agents" in query.lower() and "select" in query.lower()
        ]
        assert len(member_reads) == 1, member_reads
        assert "FOR SHARE OF t, a" in member_reads[0]

    @pytest.mark.asyncio
    async def test_another_members_snapshot_requires_the_exact_native_lookup(self, privacy_app):
        from aweb.member_team_key import read_member_projection
        from aweb.team_auth_deps import resolve_team_identity
        from test_dashboard_privacy import TEAM

        env = privacy_app
        member, cert_info = await _admitted_cert_info(env, alias="bob")
        queries = []
        async with env.db.transaction() as tx:
            cert_info["agent_row"] = await read_member_projection(
                tx, team_id=TEAM, did_key=env.actors["alice"].did
            )
            with tx.connection.query_logger(lambda event: queries.append(event.query)):
                identity = await resolve_team_identity(tx, cert_info)
                assert await tx.fetch_value("SELECT 1") == 1
        assert identity.agent_id == str(member.id)
        member_reads = [
            query for query in queries if "agents" in query.lower() and "select" in query.lower()
        ]
        assert len(member_reads) == 2, member_reads
        assert "FOR SHARE OF t, a" in member_reads[-1]


@pytest.mark.asyncio
async def test_team_and_messaging_dependencies_use_registered_identity(privacy_app):
    """R11c's six raw-manager projections use a real signed member dependency."""
    from aweb.team_auth_deps import get_team_identity
    from identity_binding_support import register_global_identity
    from test_cli_never_grants import registry_listener
    from test_dashboard_privacy import TEAM, TEAM_NAME
    from test_messages_http import _encode_certificate, _make_certificate, _signed_team_headers

    env = privacy_app
    signing_key, _, did_key = _make_keypair()
    actor = SimpleNamespace(sk=signing_key, did=did_key)
    address = "example.test/raw-manager"
    async with registry_listener(env) as (registry, _):
        stable = await register_global_identity(env, actor, address)
        document = _make_certificate(
            env.team_sk,
            env.team_did,
            did_key,
            team_id=TEAM,
            alias="raw-manager",
            identity_scope="global",
            member_did_aw=stable,
            member_address=address,
            certificate_id=str(uuid.uuid4()),
        )
        encoded = _encode_certificate(document)
        await registry.register_team_certificate(
            "example.test",
            TEAM_NAME,
            team_controller_signing_key=env.team_sk,
            certificate_id=document["certificate_id"],
            member_did_key=did_key,
            member_did_aw=stable,
            member_address=address,
            alias="raw-manager",
            identity_scope="global",
            certificate=encoded,
        )
        connected = await env.client.post(
            "/v1/connect",
            content=b"{}",
            headers={
                **_signed_team_headers(signing_key, did_key, TEAM, encoded, b"{}"),
                "Content-Type": "application/json",
            },
        )
        assert connected.status_code == 200, connected.text
        request = _request_with_app_state(
            _signed_team_headers(signing_key, did_key, TEAM, encoded, b"")
        )
        request.scope["app"] = env.app
        identity = await get_team_identity(request, env.db)
        auth = await get_messaging_auth(request, env.db)
    assert identity.agent_id == connected.json()["agent_id"]
    assert identity.did_aw == stable
    assert identity.address == address
    assert auth.agent_id == connected.json()["agent_id"]
    assert auth.did_aw == stable
    assert auth.address == address


@pytest.mark.asyncio
async def test_identity_auth_enriches_the_registered_local_member_context(privacy_app):
    from test_messages_http import _signed_identity_headers

    env = privacy_app
    member, cert_info = await _admitted_cert_info(env, alias="bob")
    headers = _signed_identity_headers(member.sk, member.did, "")
    floor = await env.client.get("/v1/messages/inbox", headers=headers)
    assert floor.status_code == 200, floor.text
    request = _request_with_app_state(headers)
    request.scope["app"] = env.app
    auth = await get_messaging_auth(request, env.db)
    assert auth.did_key == member.did
    assert auth.team_id == cert_info["team_id"]
    assert auth.alias == "bob"
    assert auth.agent_id == str(member.id)
    assert auth.identity_scope == "local"


@pytest.mark.asyncio
async def test_identity_auth_refuses_corrupt_duplicate_local_memberships(privacy_app):
    from test_dashboard_privacy import TEAM
    from test_messages_http import _signed_identity_headers

    env = privacy_app
    member, _ = await _admitted_cert_info(env, alias="bob")
    headers = _signed_identity_headers(member.sk, member.did, "")
    floor = await env.client.get("/v1/messages/inbox", headers=headers)
    assert floor.status_code == 200, floor.text
    # Explicit corrupt historical storage: local identities are single-team.
    # Start with a real admitted member, then inject the duplicate to exercise
    # refusal; this row is never offered as supported registration setup.
    duplicate_team = "corrupt-" + uuid.uuid4().hex + ":example.test"
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
        "VALUES ($1, 'example.test', $2, $3)",
        duplicate_team,
        duplicate_team.split(":", 1)[0],
        env.team_did,
    )
    await env.db.execute(
        "INSERT INTO {{tables.agents}} "
        "(team_id, did_key, alias, identity_scope, status, accepted_team_did_key, inbound_mode) "
        "VALUES ($1, $2, 'bob', 'local', 'active', $3, 'open')",
        duplicate_team,
        member.did,
        env.team_did,
    )
    request = _request_with_app_state(headers)
    request.scope["app"] = env.app
    with pytest.raises(HTTPException) as refused:
        await get_messaging_auth(request, env.db)
    assert refused.value.status_code == 409
    assert "Select the intended team with a current team certificate" in refused.value.detail
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.agents}} WHERE did_key=$1 AND team_id=ANY($2::text[])",
            member.did,
            [TEAM, duplicate_team],
        )
        == 2
    )


HOSTILE_CERTIFICATES = {
    "list": base64.b64encode(b"[]").decode(),
    "string": base64.b64encode(b'"x"').decode(),
    "deep": base64.b64encode(b"[" * 6000).decode(),
    "oversize": base64.b64encode(b'{"pad":"' + b"a" * 7000 + b'"}').decode(),
}


@pytest.mark.asyncio
async def test_verify_request_certificate_returns_coded_422_for_unusable_registry_answer():
    from aweb.team_auth_deps import verify_request_certificate

    registry = create_registry_app()
    registry.state.rate_limiter = MemoryFixedWindowRateLimiter()
    # AWID refuses this team slug before accessing the database.
    registry.state.db = None
    team_id = "invalid_slug:acme.com"
    team_key, _, team_did = _make_keypair()
    member_key, _, member_did = _make_keypair()
    certificate = _make_certificate(team_key, team_did, member_did, team_id=team_id)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = compact_team_auth_payload(
        team_id=team_id, timestamp=timestamp, body_sha256=hashlib.sha256(b"").hexdigest()
    )
    request = _request_with_app_state({
        "Authorization": f"DIDKey {member_did} {sign_message(member_key, payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWID-Team-Certificate": _encode_certificate(certificate),
    })

    transport = ASGITransport(app=registry)
    async with aclosing(RegistryClient("http://registry.test", transport=transport)) as client:
        request.app.state.awid_registry_client = client
        with pytest.raises(HTTPException) as refused:
            await verify_request_certificate(request, db=object())

    assert refused.value.status_code == 422
    assert refused.value.detail == {
        "code": "registry_response_unusable",
        "message": (
            "AWID team key resolution received an unusable registry response. "
            "Ask the server operator to check the registry."
        ),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "certificate", HOSTILE_CERTIFICATES.values(), ids=HOSTILE_CERTIFICATES.keys()
)
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
    assert refused.value.detail == "malformed"


@pytest.mark.parametrize(
    "certificate", HOSTILE_CERTIFICATES.values(), ids=HOSTILE_CERTIFICATES.keys()
)
def test_parse_and_verify_certificate_refuses_a_hostile_certificate(certificate):
    from aweb.team_auth import parse_and_verify_certificate

    with pytest.raises(ValueError) as refused:
        parse_and_verify_certificate(
            certificate,
            request_did_key="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            team_did_key="",
            revoked_certificate_ids=(),
            registered_certificate_ids=None,
        )
    assert str(refused.value) == "malformed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status", [MemberStatus.RETIRED, MemberStatus.ARCHIVED, MemberStatus.DELETED]
)
async def test_certificate_auth_refuses_a_nonactive_row_without_a_deletion_timestamp(
    privacy_app, status
):
    from test_dashboard_privacy import TEAM
    from test_messages_http import _signed_team_headers

    env = privacy_app
    member, _ = await _admitted_cert_info(env, alias="bob")

    async def team_read():
        return await env.client.get(
            "/v1/team",
            headers=_signed_team_headers(member.sk, member.did, TEAM, member.certificate, b""),
        )

    floor = await team_read()
    assert floor.status_code == 200, floor.text
    # Deliberate historical terminal-row shape allowed by the native schema;
    # current retirement writes a deletion timestamp too. This is not setup
    # for a supported active member or a replacement for the lifecycle route.
    await env.db.execute(
        "UPDATE {{tables.agents}} SET status=$2, deleted_at=NULL WHERE agent_id=$1",
        member.id,
        status,
    )
    refused = await team_read()
    assert refused.status_code == 403, refused.text
    assert "Reconnect with a certificate" in refused.json()["detail"]
    row = await env.db.fetch_one(
        "SELECT status,deleted_at FROM {{tables.agents}} WHERE agent_id=$1", member.id
    )
    assert row["status"] == status
    assert row["deleted_at"] is None

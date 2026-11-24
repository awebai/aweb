"""Tests for the team certificate FastAPI auth dependency."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid
from contextlib import aclosing
from datetime import datetime, timedelta, timezone
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


async def _register_fixture_certificate(env, certificate):
    from aweb.application_state import application_registry_client
    from test_dashboard_privacy import TEAM_NAME

    claims = json.loads(base64.b64decode(certificate))
    registry = application_registry_client(env.app.state)
    await registry.register_team_certificate(
        "example.test",
        TEAM_NAME,
        team_controller_signing_key=env.team_sk,
        certificate_id=claims["certificate_id"],
        member_did_key=claims["member_did_key"],
        member_did_aw=claims.get("member_did_aw") or None,
        member_address=claims.get("member_address") or None,
        alias=claims["alias"],
        identity_scope=claims["identity_scope"],
        certificate=certificate,
    )
    return registry


async def _admitted_cert_info(env, *, alias):
    """Register/connect through real routes before exercising a native reader."""
    from aweb.team_auth import parse_and_verify_certificate
    from test_dashboard_privacy import TEAM, TEAM_NAME
    from test_messages_http import _signed_team_headers

    member = env.actors[alias]
    registry = await _register_fixture_certificate(env, member.certificate)
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
    @pytest.mark.parametrize("locked_row", ["member", "team"])
    async def test_warm_certificate_reads_complete_while_update_lock_is_held(self, privacy_app, locked_row):
        from test_dashboard_privacy import TEAM
        from test_messages_http import _signed_team_headers

        env = privacy_app
        member, _ = await _admitted_cert_info(env, alias="bob")
        headers = _signed_team_headers(member.sk, member.did, TEAM, member.certificate, b"")
        async with env.db.transaction() as writer:
            # PostgreSQL takes this row lock for an UPDATE of non-key columns.
            if locked_row == "member":
                assert await writer.fetch_value(
                    "SELECT agent_id FROM {{tables.agents}} WHERE agent_id = $1 FOR NO KEY UPDATE",
                    member.id,
                ) == member.id
            else:
                assert await writer.fetch_value(
                    "SELECT team_id FROM {{tables.teams}} WHERE team_id = $1 FOR NO KEY UPDATE", TEAM,
                ) == TEAM
            async with asyncio.timeout(3):
                for path in ("/v1/agents", "/v1/messages/inbox"):
                    response = await env.client.get(path, headers=headers)
                    assert response.status_code == 200, response.text

    @pytest.mark.asyncio
    async def test_reads_the_exact_native_snapshot_in_an_existing_transaction(self, privacy_app):
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
        assert "FOR SHARE" not in member_reads[0] and "FOR UPDATE" not in member_reads[0]

    @pytest.mark.asyncio
    async def test_warm_admission_takes_one_statement_on_the_request_connection(self, privacy_app):
        from aweb.connection_scope import connection_scope
        from aweb.member_team_key import read_member_projection
        from aweb.team_auth_deps import resolve_team_identity

        env = privacy_app
        member, cert_info = await _admitted_cert_info(env, alias="bob")
        db = env.infra.get_manager("aweb")
        cert_info["agent_row"] = await read_member_projection(db, agent_id=member.id)
        queries = []
        async with connection_scope():
            async with db.acquire() as connection:
                assert not connection.is_in_transaction()
            with connection.query_logger(lambda event: queries.append(event.query)):
                identity = await resolve_team_identity(db, cert_info)
                assert await db.fetch_value("SELECT 1") == 1

        assert identity.agent_id == str(member.id)
        admission = [query for query in queries if query != "SELECT 1"]
        assert len(admission) == 1, admission
        assert "FOR SHARE" not in admission[0] and "FOR UPDATE" not in admission[0]

    @pytest.mark.asyncio
    async def test_mounted_snapshot_reads_member_and_overlay_together(self, privacy_app):
        from dataclasses import replace

        from aweb.connection_scope import connection_scope
        from aweb.team_auth_deps import (
            admitted_member_projection,
            read_team_member_snapshot,
            resolve_team_membership,
        )

        env = privacy_app
        member, cert_info = await _admitted_cert_info(env, alias="bob")
        request = _request_with_headers({})
        overlay = """
            SELECT t.team_id AS host_team_id, native_member.agent_id AS host_agent_id,
                   $3 AS host_certificate_id
            FROM {{tables.teams}} t LEFT JOIN native_member ON TRUE
            WHERE t.team_id=$1
        """
        queries = []
        async with connection_scope():
            async with env.db.acquire() as connection:
                assert not connection.is_in_transaction()
            with connection.query_logger(lambda event: queries.append(event.query)):
                snapshot = await read_team_member_snapshot(
                    env.db, cert_info, request=request, overlay_sql=overlay,
                )
                wrapped_request = Request(dict(request.scope))
                admitted = await resolve_team_membership(
                    env.db, cert_info, request=wrapped_request, snapshot=snapshot,
                )
                assert await env.db.fetch_value("SELECT 1") == 1
            assert admitted_member_projection(wrapped_request, admitted.identity) is snapshot.member
            for changed in (
                {"team_id": "other:example.test"},
                {"agent_id": str(uuid.uuid4())},
                {"did_key": "other-did"},
                {"certificate_id": "other-certificate"},
                {"verified_team_did_key": "other-controller"},
                {"certificate_verified": False},
            ):
                assert admitted_member_projection(wrapped_request, replace(admitted.identity, **changed)) is None
            assert admitted_member_projection(_request_with_headers({}), admitted.identity) is None
            with pytest.raises(ValueError, match="different request or certificate"):
                await resolve_team_membership(
                    env.db, cert_info, request=_request_with_headers({}), snapshot=snapshot,
                )
            with pytest.raises(ValueError, match="different request or certificate"):
                await resolve_team_membership(
                    env.db, {**cert_info, "certificate_id": "another-certificate"},
                    request=wrapped_request, snapshot=snapshot,
                )

        assert admitted.identity.agent_id == str(member.id)
        assert admitted.snapshot is snapshot
        assert snapshot.member is not None and snapshot.member["agent_id"] == member.id
        assert snapshot.host_row == {
            "host_team_id": cert_info["team_id"],
            "host_agent_id": member.id,
            "host_certificate_id": cert_info["certificate_id"],
        }
        admission = [query for query in queries if query != "SELECT 1"]
        assert len(admission) == 1, admission
        assert "FOR SHARE" not in admission[0] and "FOR UPDATE" not in admission[0]
        assert admitted_member_projection(request, admitted.identity) is None
        with pytest.raises(ValueError, match="different request or certificate"):
            await resolve_team_membership(env.db, cert_info, request=request, snapshot=snapshot)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("remove_before_retry", [False, True])
    async def test_mounted_reacceptance_checks_host_policy_on_the_update_reread(
        self, privacy_app, remove_before_retry,
    ):
        from aweb.application_state import application_registry_client
        from aweb.connection_scope import connection_scope
        from aweb.lifecycle_agent import AgentDisposition, apply_agent_disposition_on
        from aweb.member_team_key import CurrentMembershipRequired, read_member_projection
        from aweb.team_auth_deps import (
            admitted_member_projection,
            read_team_member_snapshot,
            resolve_team_membership,
            verify_request_certificate,
        )
        from test_dashboard_privacy import TEAM, TEAM_NAME
        from test_messages_http import _signed_team_headers

        env = privacy_app
        member, first = await _admitted_cert_info(env, alias="bob")
        registry = application_registry_client(env.app.state)
        await registry.revoke_team_certificate(
            "example.test", TEAM_NAME,
            team_controller_signing_key=env.team_sk, certificate_id=first["certificate_id"],
        )
        replacement_id = str(uuid.uuid4())
        replacement = _encode_certificate(_make_certificate(
            env.team_sk, env.team_did, member.did,
            certificate_id=replacement_id, team_id=TEAM, alias=first["alias"],
        ))
        await _register_fixture_certificate(env, replacement)
        request = _request_with_headers(
            _signed_team_headers(member.sk, member.did, TEAM, replacement, b"")
        )
        request.scope["app"] = env.app
        checked = await verify_request_certificate(request, env.infra, fresh=True)
        snapshot = await read_team_member_snapshot(
            env.db, checked, request=request,
            overlay_sql="SELECT certificate_id AS previous_certificate_id FROM native_member",
        )
        assert snapshot.member is not None and snapshot.member["certificate_id"] == first["certificate_id"]
        assert snapshot.host_row == {"previous_certificate_id": first["certificate_id"]}

        rereads = []

        def refuse(reread):
            rereads.append(reread)
            raise HTTPException(403, "Host policy refused")

        with pytest.raises(HTTPException, match="Host policy refused"):
            await resolve_team_membership(
                env.db, checked, request=request, snapshot=snapshot, before_write=refuse,
            )
        assert len(rereads) == 1 and rereads[0] is not snapshot
        assert rereads[0].member == snapshot.member and rereads[0].host_row == snapshot.host_row
        assert await read_member_projection(env.db, agent_id=member.id) == snapshot.member

        if remove_before_retry:
            async with env.db.transaction() as tx:
                await apply_agent_disposition_on(
                    tx, team_id=TEAM, agent_ids=[member.id],
                    disposition=AgentDisposition.PREPARED_REMOVAL, deleted_at=datetime.now(timezone.utc),
                )
            with pytest.raises(CurrentMembershipRequired):
                await resolve_team_membership(
                    env.db, checked, request=request, snapshot=snapshot, before_write=rereads.append,
                )
            assert len(rereads) == 1
            removed = await read_member_projection(env.db, agent_id=member.id)
            assert removed is not None and removed["deleted_at"] is not None
            assert removed["certificate_id"] == first["certificate_id"]
            return

        async with connection_scope():
            admitted = await resolve_team_membership(
                env.db, checked, request=request, snapshot=snapshot, before_write=rereads.append,
            )
            assert admitted_member_projection(request, admitted.identity) is admitted.snapshot.member
        assert len(rereads) == 2
        assert admitted.identity.certificate_id == replacement_id
        assert admitted.snapshot.member == await read_member_projection(env.db, agent_id=member.id)
        assert admitted.snapshot.member["certificate_id"] == replacement_id

    @pytest.mark.asyncio
    async def test_mounted_proof_can_read_host_facts_before_connect(self, privacy_app):
        from aweb.member_team_key import CurrentMembershipRequired
        from aweb.team_auth_deps import (
            read_team_member_snapshot,
            resolve_team_membership,
            verify_request_certificate,
        )
        from test_dashboard_privacy import TEAM
        from test_messages_http import _signed_team_headers

        env = privacy_app
        private_key, _, did_key = _make_keypair()
        certificate = _encode_certificate(_make_certificate(
            env.team_sk, env.team_did, did_key, certificate_id=str(uuid.uuid4()),
            team_id=TEAM, alias="awaiting-connect", identity_scope="local",
        ))
        await _register_fixture_certificate(env, certificate)
        request = _request_with_headers(_signed_team_headers(private_key, did_key, TEAM, certificate, b""))
        request.scope["app"] = env.app
        checked = await verify_request_certificate(request, env.infra)
        snapshot = await read_team_member_snapshot(
            env.db, checked, request=request,
            overlay_sql="SELECT team_id AS host_team_id FROM {{tables.teams}} WHERE team_id=$1",
        )
        assert snapshot.member is None
        assert snapshot.host_row == {"host_team_id": TEAM}
        with pytest.raises(CurrentMembershipRequired, match="Agent not connected"):
            await resolve_team_membership(env.db, checked, request=request, snapshot=snapshot)

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
        assert "FOR SHARE" not in member_reads[-1] and "FOR UPDATE" not in member_reads[-1]


@pytest.mark.asyncio
async def test_mounted_certificate_uses_stored_verified_identity_when_evidence_is_skipped(
    privacy_app, monkeypatch,
):
    from aweb import identity_auth_deps, team_auth_deps
    from aweb.application_state import application_registry_client
    from aweb.human_kind import is_verified_human
    from aweb.lifecycle_agent import AgentDisposition, apply_agent_disposition_on
    from aweb.member_team_key import CurrentMembershipRequired
    from aweb.resource_startup import start_agent_wakes, stop_agent_wakes
    from awid.identity_observation import IdentityKind
    from messaging_actor_support import admit_messaging_actor
    from test_dashboard_privacy import TEAM, TEAM_NAME
    from test_events_http import _http_frames, _next_named
    from test_messages_http import _make_certificate as make_certificate
    from test_messages_http import _signed_team_headers
    from test_team_room import admit_room_member
    from test_workspace_liveness_http import _send_member_request

    env = privacy_app
    member = env.actors["bob"]
    registry = application_registry_client(env.app.state)
    stable = (await registry.register_did(member.did, member.sk)).did_aw
    resolution = await registry.resolve_key_fresh(stable)
    assert resolution.current_did_key == member.did
    assert resolution.id_tree is not None and not resolution.id_tree.enrolled

    def certificate_for(certificate_id, address=""):
        return _encode_certificate(make_certificate(
            env.team_sk, env.team_did, member.did,
            team_id=TEAM, alias="bob", certificate_id=certificate_id,
            member_did_aw=stable, member_address=address, identity_scope="global",
        ))

    def headers(certificate, body=b""):
        return {**_signed_team_headers(member.sk, member.did, TEAM, certificate, body),
                "Content-Type": "application/json"}

    first_id, addressed_id = str(uuid.uuid4()), str(uuid.uuid4())
    first = certificate_for(first_id)
    await _register_fixture_certificate(env, first)
    connected = await env.client.post("/v1/connect", headers=headers(first, b"{}"), content=b"{}")
    assert connected.status_code == 200, connected.text
    control = await env.client.get("/v1/agents", headers=headers(first))
    assert control.status_code == 200, control.text

    domain, name = "identity-address.test", "withdrawn"
    # AWID guards active certificates in the address namespace's own teams.
    # A controller can withdraw an address used by one of its other teams.
    await env.registry.ensure_namespace(domain=domain, controller=env.namespace_sk)
    await registry.register_address(domain, name, stable, env.namespace_sk, member.did)
    await registry.revoke_team_certificate(
        "example.test", TEAM_NAME, team_controller_signing_key=env.team_sk, certificate_id=first_id,
    )
    addressed = certificate_for(addressed_id, f"{domain}/{name}")
    await _register_fixture_certificate(env, addressed)
    await registry.delete_address(domain, name, env.namespace_sk)
    assert await registry.resolve_address_fresh(domain, name) is None
    refused = await env.client.post("/v1/connect", headers=headers(addressed, b"{}"), content=b"{}")
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"] == "identity_binding_mismatch"
    strict = await env.client.get("/v1/agents", headers=headers(addressed))
    assert strict.status_code == 403, strict.text

    async def mounted_member(request: Request):
        checked = await team_auth_deps.verify_request_certificate(
            request, env.infra, identity_evidence=team_auth_deps.IdentityEvidencePolicy.SKIP,
        )
        snapshot = await team_auth_deps.read_team_member_snapshot(env.db, checked, request=request)
        try:
            resolved = await team_auth_deps.resolve_team_membership(
                env.db, checked, request=request, snapshot=snapshot,
            )
        except CurrentMembershipRequired as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return checked, resolved

    @env.app.get("/_test/mounted-certificate")
    async def mounted_certificate(request: Request):
        checked, resolved = await mounted_member(request)
        assert resolved.snapshot.member is not None
        attribution = resolved.snapshot.member.verified_identity()
        return {
            "key": resolved.identity.did_key,
            "did_aw": resolved.identity.did_aw,
            "address": resolved.identity.address,
            "verified_did_aw": checked["verified_member_did_aw"],
            "verified_address": checked["verified_member_address"],
            "verified_key": checked["did_aw_verified_key"],
            "kind": checked["identity_kind"],
            "id_chain": request.state.id_chain,
            "id_chain_result": request.state.id_chain_result,
            "verified_human": is_verified_human(resolved.snapshot.member),
            "stored_attribution": [attribution["did_aw"], attribution["address"], attribution["human_verified_key"]],
        }

    started = len(env.registry.transport.calls)
    served = await env.client.get(
        "/_test/mounted-certificate",
        headers={**headers(addressed), "X-AWID-ID-Chain": "unfinished-chain"},
    )
    assert served.status_code == 200, served.text
    assert served.json() == {
        "key": member.did, "did_aw": stable, "address": "", "verified_did_aw": "",
        "verified_address": "", "verified_key": "", "kind": None, "id_chain": None,
        "id_chain_result": None, "verified_human": False,
        "stored_attribution": [stable, None, None],
    }
    routes = [request.url.path for request in env.registry.transport.calls[started:]]
    team_path = f"/v1/namespaces/example.test/teams/{TEAM_NAME}"
    assert any(path.endswith("/revocations") for path in routes)
    assert all(path == team_path or path.startswith(f"{team_path}/") for path in routes)
    stored = await env.db.fetch_one(
        "SELECT did_aw, address, did_aw_verified_key FROM {{tables.agents}} WHERE agent_id = $1", member.id,
    )
    assert dict(stored) == {"did_aw": stable, "address": None, "did_aw_verified_key": member.did}

    # The embedding hook supplies actual verified membership to the native
    # routes. Native Connect continues to require the live address evidence.
    async def mounted_team_identity(request: Request, db=None):
        _, resolved = await mounted_member(request)
        return resolved.identity

    monkeypatch.setattr(identity_auth_deps, "get_team_identity", mounted_team_identity)
    event_route = next(route for route in env.app.routes if route.path == "/v1/events/stream")
    event_auth = next(
        dependency.call for dependency in event_route.dependant.dependencies
        if getattr(dependency.call, "_aweb_grant_scope", None) == "events.read"
    )
    env.app.dependency_overrides[event_auth] = mounted_team_identity
    await admit_room_member(env, alias="alice")

    await start_agent_wakes(env.app, env.redis)
    try:
        async with env.client.stream(
            "GET", "/v1/events/stream",
            params={"deadline": (datetime.now(timezone.utc) + timedelta(seconds=15)).isoformat()},
            headers=headers(addressed),
        ) as stream:
            assert stream.status_code == 200, await stream.aread()
            async with aclosing(_http_frames(stream.aiter_lines())) as frames:
                await _next_named(frames, "connected")
                incoming = await _send_member_request(
                    env, alias="alice", method="POST", path="/v1/messages",
                    body={"to_did": stable, "subject": "stable inbox", "body": "hello"},
                )
                assert incoming.status_code == 200, incoming.text
                message_id = incoming.json()["message_id"]
                assert (await _next_named(frames, "actionable_mail"))["message_id"] == message_id
    finally:
        await stop_agent_wakes(env.app)

    inbox = await env.client.get("/v1/messages/inbox", headers=headers(addressed))
    assert inbox.status_code == 200, inbox.text
    assert [(item["message_id"], item["to_did"]) for item in inbox.json()["messages"]] == [
        (message_id, stable)
    ]
    chat = await _send_member_request(
        env, alias="alice", method="POST", path="/v1/chat/sessions",
        body={"to_dids": [stable], "message": "stable pending"},
    )
    assert chat.status_code == 200, chat.text
    pending = await env.client.get("/v1/chat/pending", headers=headers(addressed))
    assert pending.status_code == 200, pending.text
    assert chat.json()["session_id"] in {item["session_id"] for item in pending.json()["pending"]}

    alice = env.actors["alice"]
    signed_mail = {
        "message_id": str(uuid.uuid4()),
        "conversation_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "subject": "stable sender",
        "body": "reply",
        "from_did": member.did,
    }
    signed = canonical_json_bytes({
        **signed_mail, "type": "mail", "from_stable_id": stable, "to_did": alice.did,
    })
    payload = json.dumps({
        **signed_mail, "to_did": alice.did, "signature": sign_message(member.sk, signed),
        "signed_payload": signed.decode(),
    }).encode()
    sent = await env.client.post("/v1/messages", headers=headers(addressed, payload), content=payload)
    assert sent.status_code == 200, sent.text
    received = await _send_member_request(
        env, alias="alice", method="GET", path=f"/v1/messages/{sent.json()['message_id']}",
    )
    assert received.status_code == 200, received.text
    assert received.json()["from_stable_id"] == stable
    assert received.json().get("id_chain") is None
    assert received.json().get("from_address") != f"{domain}/{name}"

    human = await admit_messaging_actor(
        env, alias="mounted-human", team_id=TEAM, address="example.test/mounted-human",
        kind=IdentityKind.HUMAN,
    )
    human_response = await env.client.get(
        "/_test/mounted-certificate",
        headers=_signed_team_headers(human.signing_key, human.did_key, TEAM, human.certificate),
    )
    assert human_response.status_code == 200, human_response.text
    assert human_response.json()["did_aw"] == human.stable_id
    assert human_response.json()["address"] == human.address
    assert human_response.json()["verified_human"] is True
    assert human_response.json()["kind"] is None
    assert human_response.json()["id_chain"] is None

    claimed_only = _encode_certificate(make_certificate(
        env.team_sk, env.team_did, alice.did, team_id=TEAM, alias="alice",
        certificate_id=str(uuid.uuid4()), member_did_aw=stable,
        member_address=f"{domain}/{name}", identity_scope="global",
    ))
    skipped_claim = await env.client.get(
        "/_test/mounted-certificate",
        headers=_signed_team_headers(alice.sk, alice.did, TEAM, claimed_only),
    )
    assert skipped_claim.status_code == 200, skipped_claim.text
    assert skipped_claim.json()["key"] == alice.did
    assert skipped_claim.json()["did_aw"] == skipped_claim.json()["address"] == ""

    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
    unregistered = await env.client.get(
        "/_test/mounted-certificate", headers=headers(certificate_for(str(uuid.uuid4()))),
    )
    assert unregistered.status_code == 401, unregistered.text
    wrong_signer = await env.client.get(
        "/_test/mounted-certificate",
        headers=_signed_team_headers(alice.sk, alice.did, TEAM, addressed),
    )
    assert wrong_signer.status_code == 401, wrong_signer.text
    wrong_team_key, _, wrong_team_did = _make_keypair()
    wrong_controller = _encode_certificate(make_certificate(
        wrong_team_key, wrong_team_did, member.did, team_id=TEAM, alias="bob",
        certificate_id=str(uuid.uuid4()), identity_scope="global",
    ))
    rejected_team_key = await env.client.get(
        "/_test/mounted-certificate", headers=headers(wrong_controller),
    )
    assert rejected_team_key.status_code == 401, rejected_team_key.text
    assert rejected_team_key.json()["detail"]["code"] == "team_key_not_current"

    await registry.revoke_team_certificate(
        "example.test", TEAM_NAME, team_controller_signing_key=env.team_sk, certificate_id=addressed_id,
    )
    revoked = await env.client.get("/_test/mounted-certificate", headers=headers(addressed))
    assert revoked.status_code == 401, revoked.text
    assert revoked.json()["detail"]["code"] == "certificate_revoked"
    replacement = certificate_for(str(uuid.uuid4()))
    await _register_fixture_certificate(env, replacement)
    async with env.db.transaction() as tx:
        assert await apply_agent_disposition_on(
            tx, agent_ids=[member.id], team_id=TEAM,
            disposition=AgentDisposition.DELETED, deleted_at=datetime.now(timezone.utc),
        ) == 1
    removed = await env.client.get("/_test/mounted-certificate", headers=headers(replacement))
    assert removed.status_code == 403, removed.text


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

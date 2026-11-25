"""Selected-resource consumers with actual registry writes and native verifiers.

The resource reference below carries configuration only. All identity, tree,
certificate and controller evidence comes from the real registry fixture.
"""

from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, Request

from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier
from aweb.api import _build_awid_registry_client
from aweb.application_state import RegistryClientUnavailable
from aweb.coordination.app_tasks import (
    _current_certificates,
    verify_authorization_certificate,
)
from aweb.id_chain_auth import authenticate_id_chain
from aweb.identity_auth_deps import resolve_identity_auth
from aweb.identity_binding import verify_identity_binding
from aweb.routes.dashboard import _get_team_visibility
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_id_chain_request_auth import (
    ALICE,
    ROOT,
    _fixture_signer,
    _signed_fixture_certificate,
)
from test_messages_http import _signed_identity_headers
from test_team_room import admit_room_member

__all__ = ["privacy_app"]


def root_app(native, registry):
    root = FastAPI()
    root.state.native_resources = SimpleNamespace(
        registry_client=registry, api_app=native
    )
    return root


def root_request(root):
    return Request(
        {"type": "http", "app": root, "method": "GET", "path": "/", "headers": []}
    )


@pytest_asyncio.fixture
async def enrolled_registry(privacy_app, monkeypatch):
    env = privacy_app
    domain = f"awtest-selected-{uuid4().hex}.test"
    async with registry_listener(env) as (writer, origin):

        async def exact_dns(selected):
            assert selected == domain
            return DomainAuthority(ROOT["did_key"], origin, "_awid." + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        stable = (
            await writer.register_did(
                ALICE["did_key"], bytes.fromhex(ALICE["seed_hex"])
            )
        ).did_aw
        await writer.register_namespace(
            domain, ROOT["did_key"], bytes.fromhex(ROOT["seed_hex"])
        )
        signed = _signed_fixture_certificate(
            "alice",
            domain=domain,
            identity=stable,
            parent={"kind": "namespace", "id": domain},
            issuer="root",
        )
        await writer.register_id_certificate(
            {"v": 1, "type": "aweb.id-chain", "certificates": [signed]},
            signer=_fixture_signer("alice"),
            expected_head=None,
            invitation_id=None,
        )
        monkeypatch.setenv("AWID_REGISTRY_URL", origin)
        monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
        cached = _build_awid_registry_client(
            env.app, redis=env.redis, domain_verifier=exact_dns
        )
        try:
            binding = await verify_identity_binding(
                root_request(env.app),
                did_key=ALICE["did_key"],
                did_aw=stable,
                fresh=True,
                registry_client=cached,
            )
            assert binding.fresh_observation
            assert binding.id_tree is not None
            assert binding.id_tree.enrolled
            yield env, cached, binding
        finally:
            await cached.aclose()


@pytest.mark.asyncio
async def test_signed_identity_auth_on_resource_only_root_uses_selected_registry(
    enrolled_registry,
):
    env, registry, binding = enrolled_registry
    root = root_app(env.app, registry)
    assert not hasattr(root.state, "awid_registry_client")

    @root.get("/identity")
    async def identity(request: Request):
        principal = await resolve_identity_auth(request, db=env.infra)
        kind = request.state.identity_kind
        return {
            "did_key": principal.did_key,
            "did_aw": principal.did_aw,
            "kind": kind.kind.value,
            "identity_valid": kind.result["identity_valid"],
        }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(root), base_url="http://host.test"
    ) as client:
        response = await client.get(
            "/identity",
            headers=_signed_identity_headers(
                bytes.fromhex(ALICE["seed_hex"]),
                ALICE["did_key"],
                binding.did_aw,
                b"",
            ),
        )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "did_key": ALICE["did_key"],
        "did_aw": binding.did_aw,
        "kind": "human",
        "identity_valid": True,
    }


@pytest.mark.asyncio
async def test_id_chain_missing_selected_client_refuses_despite_outer_shadow(
    enrolled_registry,
):
    env, registry, binding = enrolled_registry
    root = root_app(env.app, None)
    root.state.awid_registry_client = registry
    with pytest.raises(RegistryClientUnavailable) as refused:
        await authenticate_id_chain(root_request(root), binding)
    assert refused.value.status_code == 503
    assert refused.value.code == "registry_client_unavailable"


@pytest.mark.asyncio
async def test_id_chain_explicit_foreign_client_wins_over_missing_host_resource(
    enrolled_registry,
):
    env, foreign, binding = enrolled_registry
    root = root_app(env.app, None)
    result = await authenticate_id_chain(
        root_request(root), binding, registry_client=foreign
    )
    assert result["identity_valid"] is True
    assert result["kind"] == "human"


@pytest.mark.asyncio
async def test_dashboard_visibility_reads_the_selected_root_registry(privacy_app):
    env = privacy_app
    root = root_app(env.app, env.app.state.awid_registry_client)
    assert not hasattr(root.state, "awid_registry_client")
    assert await _get_team_visibility(root_request(root), TEAM) == "public"


@pytest.mark.asyncio
async def test_app_task_fresh_roster_reads_the_selected_root_registry(privacy_app):
    env = privacy_app
    certificate = await admit_room_member(env, alias="alice")
    root = root_app(env.app, env.app.state.awid_registry_client)
    certificates = await _current_certificates(root_request(root), TEAM)
    assert [item.certificate_id for item in certificates] == [
        certificate["certificate_id"]
    ]


@pytest.mark.asyncio
async def test_app_task_certificate_verifier_reads_the_selected_root_registry(
    privacy_app,
):
    env = privacy_app
    certificate = await admit_room_member(env, alias="alice")
    actor = env.actors["alice"]
    root = root_app(env.app, env.app.state.awid_registry_client)
    info, certificates = await verify_authorization_certificate(
        root_request(root),
        {
            "payload": {
                "team_id": TEAM,
                "certificate_id": certificate["certificate_id"],
                "actor_did_key": actor.did,
            },
            "certificate": actor.certificate,
        },
    )
    assert info["team_id"] == TEAM
    assert info["did_key"] == actor.did
    assert info["certificate_id"] == certificate["certificate_id"]
    assert [item.certificate_id for item in certificates] == [
        certificate["certificate_id"]
    ]
